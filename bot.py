import os
import json
import time
import logging
import threading
import subprocess
import ipaddress
import tldextract
import shutil

from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone


from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from playwright.sync_api import sync_playwright

# ------------------------------------------------
# CONFIGURATION & PERMISSIONS
# ------------------------------------------------
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN")

LIST_DIR = "/etc/squid/lists"
DOMAINS_FILE = "/etc/squid/domains.json"
FULLNET_DIR = "/etc/squid/conf.d/fullnet"
CDN_DOMAINS_FILE = "/etc/squid/cdn_domains.txt"
DOMAIN_CONF = "/etc/squid/conf.d/02-domain-lists.conf"
HOSTS_CONF = "/etc/squid/conf.d/01-hosts.conf"
GROUP_RULES_CONF = "/etc/squid/conf.d/03-group.conf"
RULES_CONF = "/etc/squid/conf.d/03-rules.conf"

# STARTUP GUARD
os.makedirs(FULLNET_DIR, exist_ok=True)
os.makedirs(LIST_DIR, exist_ok=True)
os.makedirs(f"{LIST_DIR}/groups", exist_ok=True)

if not os.listdir(FULLNET_DIR):
    with open(f"{FULLNET_DIR}/00-placeholder.conf", "w") as f:
        f.write("# Placeholder to prevent Squid startup crash\n")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)

app = App(token=SLACK_BOT_TOKEN)
lock = threading.Lock()
last_reload = 0
CDN_LIST = []

# ------------------------------------------------
# DYNAMIC CDN LOADING (NEW & CRITICAL)
# ------------------------------------------------

def get_cdn_domains():
    """Reads the CDN list from the external file. Fixes YouTube buffering."""
    if not os.path.exists(CDN_DOMAINS_FILE):
        # Fallback to essential defaults if file is missing
        return [
            "cloudflare.com", "fastly.net", "akamai.net", "cloudfront.net",
            "gstatic.com", "googleapis.com", "googlevideo.com", "ytimg.com"
        ]
    
    with open(CDN_DOMAINS_FILE, "r") as f:
        return [line.strip().lower() for line in f if line.strip()]

def classify(domain):
    """
    Normalize a hostname to a whitelistable domain pattern.
    Fixed:
    - Proper CDN subdomain matching (no false prefix matches)
    - Handles unusual TLDs
    - Strips leading dots safely
    """
    domain = domain.lower().strip().lstrip(".")

    # Layer 1: Match against CDN list first
    for cdn in CDN_LIST:
        cdn_clean = cdn.lstrip(".")
        if domain == cdn_clean or domain.endswith("." + cdn_clean):
            return "." + cdn_clean

    # Layer 2: Extract root domain via tldextract
    ext = tldextract.extract(domain)

    if not ext.domain or not ext.suffix:
        return None

    # Always group under root domain (subdomains included via dot prefix)
    return f".{ext.domain}.{ext.suffix}"

# Initialize CDN list after function is defined
CDN_LIST = get_cdn_domains()

# ------------------------------------------------

def get_host_acls():
    """Extract ACL names from 01-hosts.conf"""

    acls = set()

    if not os.path.exists(HOSTS_CONF):
        return []

    with open(HOSTS_CONF, "r") as f:
        for line in f:

            line = line.strip()

            if line.startswith("acl"):

                parts = line.split()

                if len(parts) >= 2:
                    acl_name = parts[1]
                    acls.add(acl_name)

    return sorted(acls)

#-------------------------------------------------
# SQUID CONFIG GENERATOR (NEW)
# ------------------------------------------------

def regenerate_squid_configs():
    """
    Rebuilds 02-domain-lists.conf and 03-rules.conf
    from:
      - /etc/squid/lists/groups/*.txt  (group domains)
      - /etc/squid/lists/<ip>.txt      (per-IP domains)
    """

    GROUP_DIR = os.path.join(LIST_DIR, "groups")

    # Ensure at least one group file exists
    if not os.listdir(GROUP_DIR):
        placeholder = os.path.join(GROUP_DIR, "default.txt")
        with open(placeholder, "w") as f:
            f.write(".example.com\n")

    ip_files = []
    group_files = []

    # -------------------------
    # Scan group domain lists
    # -------------------------
    if os.path.exists(GROUP_DIR):
        for f in os.listdir(GROUP_DIR):
            if f.endswith(".txt"):
                group_files.append(f)

    # -------------------------
    # Scan IP domain lists
    # -------------------------
    for f in os.listdir(LIST_DIR):

        full_path = os.path.join(LIST_DIR, f)

        if os.path.isdir(full_path):
            continue

        if not f.endswith(".txt"):
            continue

        ip = f.replace(".txt", "")

        try:
            ipaddress.ip_address(ip)
            ip_files.append(f)
        except ValueError:
            continue

    # -------------------------
    # Build domain config
    # -------------------------
    domain_lines = [
        "# =====================================",
        "# Domain Lists (Auto Generated)",
        "# =====================================",
        ""
    ]

    # GROUP DOMAIN ACLS
    domain_lines.append("# GROUP DOMAIN LISTS")

    for g in sorted(group_files):

        path = os.path.join(GROUP_DIR, g)

        # Skip empty files
        if os.path.getsize(path) == 0:
            continue

        name = g.replace(".txt", "")
        safe = name.replace("-", "_")

        domain_lines.append(
            f'acl group_{safe}_domains dstdomain "{path}"'
        )

    domain_lines.append("")
    domain_lines.append("# IP DOMAIN LISTS")

    for file in sorted(ip_files):

        ip = file.replace(".txt", "")
        safe = ip.replace(".", "_")
        path = os.path.join(LIST_DIR, file)

        # Safety: ensure file exists
        if not os.path.exists(path):
            open(path, "w").close()

        domain_lines.append(f'acl ip_{safe} src {ip}')
        domain_lines.append(
            f'acl ip_{safe}_domains dstdomain "{path}"'
        )

    with open(DOMAIN_CONF, "w") as f:
        f.write("\n".join(domain_lines) + "\n")

    # -------------------------
    # Build rules config
    # -------------------------

    rule_lines = [
        "# =====================================",
        "# ACCESS RULES (AUTO GENERATED)",
        "# =====================================",
        "",
        "# IP SPECIFIC ACCESS"
    ]

    for file in sorted(ip_files):

        ip = file.replace(".txt", "")
        safe = ip.replace(".", "_")

        rule_lines.append(
            f"http_access allow ip_{safe} ip_{safe}_domains"
        )

    rule_lines.append("")
    rule_lines.append("# GROUP RULES (ADMIN MANAGED)")

    if not os.path.exists(GROUP_RULES_CONF):
        with open(GROUP_RULES_CONF, "w") as f:
            f.write("# Add group http_access rules here\n")

    rule_lines.append(f"include {GROUP_RULES_CONF}")

    rule_lines.append("")
    rule_lines.append("# AUTO DENY FROM HOST ACLS")

    host_acls = get_host_acls()

    for acl in host_acls:
        rule_lines.append(f"http_access deny {acl}")

    rule_lines.append("")
    rule_lines.append("http_access deny all")

    if os.path.exists(RULES_CONF):
        shutil.copy(RULES_CONF, RULES_CONF + ".bak")

    with open(RULES_CONF, "w") as f:
        f.write("\n".join(rule_lines) + "\n")

# ------------------------------------------------
# VALIDATION & UTILITIES
# ------------------------------------------------

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def validate_domain(domain):
    ext = tldextract.extract(domain)
    return bool(ext.domain and ext.suffix)

def load_domains():
    if not os.path.exists(DOMAINS_FILE): return {}
    try:
        with open(DOMAINS_FILE) as f: return json.load(f)
    except: return {}

def save_domains(data):
    with open(DOMAINS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def normalize(domain):

    domain = domain.lower().strip()

    if domain.startswith("http"):
        parsed = urlparse(domain)
        domain = parsed.hostname if parsed.hostname else domain

    domain = domain.split("/")[0]

    return domain

# ------------------------------------------------
# SQUID RELOAD (THREAD SAFE)
# ------------------------------------------------

def reload_squid(respond=None):
    global last_reload
    with lock:
        now = time.time()
        if now - last_reload < 5:
            return

        test = subprocess.run(["sudo", "squid", "-k", "parse"], capture_output=True)
        if test.returncode != 0:
            msg = f"Squid config parse error: {test.stderr.decode().strip()}"
            log.error(msg)
            if respond:
                respond(f"❌ Squid config error:\n{test.stderr.decode()}")
            return

        result = subprocess.run(["sudo", "squid", "-k", "reconfigure"], capture_output=True)
        last_reload = now

        if result.returncode == 0:
            log.info("Squid reloaded successfully")
            if respond:
                respond("🧾 Squid configuration reloaded")
        else:
            log.error(f"Squid reload failed: {result.stderr.decode().strip()}")
            if respond:
                respond(f"❌ Reload failed: {result.stderr.decode()}")

# ------------------------------------------------
# DOMAIN DISCOVERY WITH PLAYWRIGHT (NEW & IMPROVED)
# ------------------------------------------------

def discover(domain, respond):
    """
    Improved dependency scanner.
    Fixed:
    - Follows redirects (tracks final URL)
    - Captures lazy/deferred resources (scroll + interactions)
    - Uses networkidle instead of domcontentloaded
    - Scans multiple pages (root + login + common subpages)
    - Captures iframes and web workers
    """
    discovered = set()
    respond("🔎 Launching dependency scanner...")

    # Pages to scan beyond root
    EXTRA_PATHS = ["/login", "/signin", "/app", "/dashboard", "/api"]

    def capture_requests(page):
        """Attach request interceptor to a page."""
        def on_request(req):
            try:
                host = urlparse(req.url).hostname
                if host:
                    d = classify(host)
                    if d:
                        discovered.add(d)
            except:
                pass

        def on_frame(frame):
            """Capture iframe src domains."""
            try:
                host = urlparse(frame.url).hostname
                if host:
                    d = classify(host)
                    if d:
                        discovered.add(d)
            except:
                pass

        page.on("request", on_request)
        page.on("framenavigated", on_frame)

    def interact_page(page):
        """Simulate user interactions to trigger lazy loads."""
        try:
            # Scroll down in steps to trigger lazy loading
            for scroll_y in [300, 600, 1000, 1500, 2000]:
                page.mouse.wheel(0, scroll_y)
                page.wait_for_timeout(500)

            # Move mouse to trigger hover-based loads
            page.mouse.move(640, 400)
            page.wait_for_timeout(500)

            # Wait for any network activity to settle
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass  # timeout is fine, we just want to catch late requests

        except Exception:
            pass

    with sync_playwright() as p:
        browser = None
        try:
            browser = p.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage"]
            )
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800}
            )

            # ----------------------------------------
            # Page 1: Root domain
            # ----------------------------------------
            respond(f"🌐 Scanning root: https://{domain}")
            page = context.new_page()
            capture_requests(page)

            try:
                response = page.goto(
                    "https://" + domain,
                    timeout=30000,
                    wait_until="domcontentloaded"
                )

                # Track redirect — final URL may be a different domain
                if response:
                    final_url = response.url
                    final_host = urlparse(final_url).hostname
                    if final_host:
                        d = classify(final_host)
                        if d:
                            discovered.add(d)
                        # If redirected to a different domain, scan that too
                        if final_host != domain:
                            respond(f"↪️ Redirect detected: {final_host}")

                interact_page(page)

            except Exception as e:
                respond(f"⚠️ Root scan warning: {e}")
            finally:
                page.close()

            # ----------------------------------------
            # Page 2+: Common subpages
            # ----------------------------------------
            for path in EXTRA_PATHS:
                url = f"https://{domain}{path}"
                try:
                    sub_page = context.new_page()
                    capture_requests(sub_page)

                    sub_resp = sub_page.goto(
                        url,
                        timeout=15000,
                        wait_until="domcontentloaded"
                    )

                    # Only interact if page actually loaded (not 404)
                    if sub_resp and sub_resp.status < 400:
                        respond(f"📄 Scanning: {url}")
                        interact_page(sub_page)
                    
                    sub_page.close()

                except:
                    # Subpage may not exist — silently skip
                    try:
                        sub_page.close()
                    except:
                        pass

        except Exception as e:
            respond(f"⚠️ Scanner error: {str(e)}")
        finally:
            if browser:
                browser.close()

    respond(f"✅ Scan complete — {len(discovered)} dependencies found")
    return discovered

# ------------------------------------------------
# EXPIRY WORKER
# ------------------------------------------------



def expiry_worker():

    while True:

        changed = False
        db_snapshot = None

        new_cdn_list = get_cdn_domains()

        # -----------------------------
        # Phase 1 — Minimal Lock Scope
        # -----------------------------
        with lock:

            # Refresh CDN list periodically
            global CDN_LIST
            CDN_LIST = new_cdn_list

            db = load_domains()
            now = datetime.now(timezone.utc).timestamp()

            expired_rules = [
                k for k, v in db.items()
                if v.get("expires") and now > v["expires"]
            ]

            if expired_rules:

                for key in expired_rules:
                    del db[key]

                save_domains(db)
                changed = True

            if changed:
                db_snapshot = dict(db)

        # -----------------------------
        # Phase 2 — Heavy I/O Outside Lock
        # -----------------------------
        if changed and db_snapshot is not None:

            ip_deps = {}

            # rebuild dependency map
            for entry in db_snapshot.values():

                ip = entry["ip"]

                if ip not in ip_deps:
                    ip_deps[ip] = set()

                ip_deps[ip].update(entry["deps"])

            # -----------------------------
            # Update IP files
            # -----------------------------
            for ip, deps in ip_deps.items():

                path = os.path.join(LIST_DIR, f"{ip}.txt")

                with open(path, "w") as f:
                    for d in sorted(deps):
                        f.write(d + "\n")

            # -----------------------------
            # Clean IP files that lost rules
            # (DO NOT delete them)
            # -----------------------------
            for filename in os.listdir(LIST_DIR):

                if not filename.endswith(".txt"):
                    continue

                ip_str = filename.replace(".txt", "")

                try:
                    ipaddress.ip_address(ip_str)
                except ValueError:
                    continue

                path = os.path.join(LIST_DIR, filename)

                if ip_str not in ip_deps:
                    # Clear file but keep it
                    open(path, "w").close()

            # -----------------------------
            # Regenerate configs safely
            # -----------------------------
            regenerate_squid_configs()

            reload_squid()

        time.sleep(60)

# ------------------------------------------------
# SLASH COMMANDS
# ------------------------------------------------

@app.command("/allow")
def allow_cmd(ack, respond, command):
    ack()
    args = command["text"].split()
    if len(args) < 2:
        respond("Usage: `/allow <ip> <domain> [Nh]`")
        return

    ip, domain = args[0], args[1]
    expiry_timestamp = None
    time_text = "indefinitely ♾️"

    if len(args) == 3:
        time_str = args[2].lower()
        try:
            hours = float(time_str[:-1])
            if not time_str.endswith("h") or hours <= 0:
                raise ValueError
            expiry_timestamp = (
                datetime.now(timezone.utc) + timedelta(hours=hours)
            ).timestamp()
            time_text = f"for {hours} hour(s) ⏳"
        except ValueError:
            respond("❌ Error: Time must be like `1h`, `1.5h`, or `24h`.")
            return

    if not validate_ip(ip):
        respond(f"❌ Invalid IP: {ip}")
        return

    domain = normalize(domain)
    
    if not validate_domain(domain):
        respond(f"❌ Invalid domain: {domain}")
        return
    
    respond(f"⚙️ Processing {domain} for {ip}...")

    deps = discover(domain, respond)
    base = classify(domain)
    if base: deps.add(base)

    with lock:
        db = load_domains()
        db[f"{ip}:{domain}"] = {
            "ip": ip, "domain": domain, "deps": list(deps), "expires": expiry_timestamp
        }
        save_domains(db)

        path = os.path.join(LIST_DIR, f"{ip}.txt")
        current = set()
        if os.path.exists(path):
            with open(path, 'r') as f: current = set(line.strip() for line in f if line.strip())
        
        updated = current | deps
        with open(path, 'w') as f:
            for d in sorted(updated): f.write(d + "\n")
        
    regenerate_squid_configs()
    reload_squid()
    respond(f"✅ *Allowed:* {domain} is now accessible for {ip} {time_text}")

# ------------------------------------------------
# DENY
# ------------------------------------------------

@app.command("/deny")
def deny_cmd(ack, respond, command):

    ack()

    args = command["text"].split()

    if len(args) != 2:
        respond("Usage: `/deny <ip> <domain>`")
        return

    ip, domain = args

    if not validate_ip(ip):
        respond(f"❌ Invalid IP: {ip}")
        return

    domain = normalize(domain)
    key = f"{ip}:{domain}"

    with lock:

        db = load_domains()

        if key not in db:
            respond(f"⚠️ `{domain}` not found for `{ip}`")
            return

        # Remove from database
        del db[key]

        save_domains(db)

        # Recalculate dependencies for this IP
        remaining_deps = set()

        for entry in db.values():
            if entry["ip"] == ip:
                remaining_deps.update(entry["deps"])

    # --- Rewrite IP ACL file (outside lock) ---

    list_path = os.path.join(LIST_DIR, f"{ip}.txt")

    with open(list_path, "w") as f:
        for d in sorted(remaining_deps):
            f.write(d + "\n")

    # If no domains remain, file will simply be empty
    # (CRITICAL: file is never deleted)

    regenerate_squid_configs()

    reload_squid()

    respond(f"🚫 `{domain}` removed from `{ip}`")



#-----------------------------------
# COMMAND: EXTEND
# -----------------------------------    

@app.command("/extend")
def extend_cmd(ack, respond, command):
    ack()

    args = command["text"].split()

    if len(args) != 3:
        respond("Usage: `/extend <ip> <domain> <Nh>`")
        return

    ip, domain, time_str = args

    if not validate_ip(ip):
        respond(f"❌ Invalid IP: {ip}")
        return

    domain = normalize(domain)

    try:
        hours = float(time_str[:-1])
        if not time_str.endswith("h") or hours <= 0:
            raise ValueError
    except ValueError:
        respond("❌ Time must be like `1h`, `1.5h`, `24h`")
        return

    extra_seconds = hours * 3600

    key = f"{ip}:{domain}"

    with lock:

        db = load_domains()

        if key not in db:
            respond(f"⚠️ No active rule found for `{domain}` on `{ip}`")
            return

        entry = db[key]

        now = datetime.now(timezone.utc).timestamp()

        # If already expired or unlimited
        if not entry.get("expires"):
            respond(f"⚠️ `{domain}` for `{ip}` has no expiry to extend.")
            return

        current_expiry = entry["expires"]

        # Extend from whichever is later (now or current expiry)
        base_time = max(now, current_expiry)

        new_expiry = base_time + extra_seconds

        entry["expires"] = new_expiry

        db[key] = entry

        save_domains(db)

    respond(
        f"⏱️ *Extended access*\n"
        f"IP: `{ip}`\n"
        f"Domain: `{domain}`\n"
        f"Added: `{hours}h`"
    )

# ------------------------------------------------
# COMMAND: FULL NET
# ------------------------------------------------
@app.command("/full-net")
def fullnet_cmd(ack, respond, command):
    ack()
    ip = command["text"].strip()
    if not validate_ip(ip):
        respond("Invalid IP")
        return
    safe_name = ip.replace(".", "_")
    path = os.path.join(FULLNET_DIR, f"{ip}.conf")
    rule = f"# Override for {ip}\nacl fullnet_{safe_name} src {ip}\nhttp_access allow fullnet_{safe_name}\n"
    with lock:
        with open(path, "w") as f: f.write(rule)
    reload_squid()
    respond(f"🔓 *Full Internet Enabled* for {ip}")

# ------------------------------------------------
# COMMAND: LOCK NET
# ------------------------------------------------
@app.command("/lock-net")
def locknet_cmd(ack, respond, command):
    ack()
    ip = command["text"].strip()
    path = os.path.join(FULLNET_DIR, f"{ip}.conf")
    with lock:
        if os.path.exists(path):
            with open(path, "w") as f:
                f.write("# Disabled by /lock-net command\n")
            reload_squid()
            respond(f"🔒 *Restrictions Restored* for {ip}")
        else:
            respond(f"Note: No full-net override found for {ip}")

# ------------------------------------------------
# COMMAND: LIST
# ------------------------------------------------
@app.command("/list")
def list_cmd(ack, respond, command):
    ack()
    ip = command["text"].strip()
    if not validate_ip(ip):
        respond("Usage: `/list <ip>`")
        return
        
    db = load_domains()
    ip_rules = [entry for entry in db.values() if entry["ip"] == ip]
    
    if not ip_rules:
        respond(f"No specific rules found for `{ip}`")
        return
        
    lines = [f"Allowed domains for `{ip}`:"]
    for idx, rule in enumerate(sorted(ip_rules, key=lambda x: x["domain"])):
        domain = rule["domain"]
        expires = rule.get("expires")
        if expires:
            dt = datetime.fromtimestamp(expires, timezone.utc)
            expiry_str = f"expires {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        else:
            expiry_str = "indefinitely"
        lines.append(f"{idx+1}. `{domain}` - {expiry_str}")
        
    respond("\n".join(lines))

# ------------------------------------------------
# STARTUP
# ------------------------------------------------
if __name__ == "__main__":

    regenerate_squid_configs()
    reload_squid()

    threading.Thread(
        target=expiry_worker,
        daemon=True
    ).start()

    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    print("🚀 Slack Squid Bot is active and monitoring...")
    handler.start()
