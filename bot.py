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

# Load .env file (for running directly with `python3 bot.py`).
# When deployed via systemd, EnvironmentFile= handles this instead.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed — rely on environment variables being pre-set


from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from playwright.sync_api import sync_playwright

# ------------------------------------------------
# CONFIGURATION & PERMISSIONS
# ------------------------------------------------
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN")
SLACK_LOG_CHANNEL  = os.environ.get("SLACK_LOG_CHANNEL")

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
# DISCOVERY FILTER CONFIG  (loaded from filter_config.json)
# Edit filter_config.json to add/remove blocked domains or change
# allowed resource types — no bot restart required.
# ------------------------------------------------

FILTER_CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "filter_config.json")

def load_filter_config():
    """
    Reads filter_config.json and returns:
      blocklist      : set of root domains to hard-block during discovery
      resource_types : set of Playwright resource types to count as real deps

    Falls back to safe built-in defaults if the file is missing or malformed.
    """
    defaults_blocklist = {
        "facebook.com", "youtube.com", "twitter.com", "instagram.com",
        "google-analytics.com", "googletagmanager.com", "doubleclick.net"
    }
    defaults_types = {"document", "script", "fetch", "xhr", "websocket", "eventsource", "other"}

    if not os.path.exists(FILTER_CONFIG_FILE):
        log.warning("filter_config.json not found — using built-in defaults.")
        return defaults_blocklist, defaults_types

    try:
        with open(FILTER_CONFIG_FILE, "r") as f:
            cfg = json.load(f)

        # Flatten all blocklist categories into one set, skip _comment keys
        combined = set()
        for category, entries in cfg.get("blocklist", {}).items():
            if category == "_comment":
                continue
            if isinstance(entries, list):
                combined.update(d.lower().strip() for d in entries)

        resource_types = set(cfg.get("functional_resource_types", list(defaults_types)))

        log.info(f"Filter config loaded: {len(combined)} blocked domains, {len(resource_types)} resource types")
        return combined, resource_types

    except Exception as e:
        log.error(f"Failed to load filter_config.json: {e} — using built-in defaults.")
        return defaults_blocklist, defaults_types


def load_full_access_domains():
    """
    Reads the full_access_domains section from filter_config.json.
    Returns a flat set of root domains whose /allow requests should
    automatically trigger full-net access instead of domain whitelisting.

    Used for relay-based tools (UltraViewer, AnyDesk, TeamViewer, etc.)
    whose server IPs change dynamically and can't be reliably whitelisted.
    """
    if not os.path.exists(FILTER_CONFIG_FILE):
        return set()
    try:
        with open(FILTER_CONFIG_FILE, "r") as f:
            cfg = json.load(f)
        result = set()
        for category, entries in cfg.get("full_access_domains", {}).items():
            if category == "_comment" or not isinstance(entries, list):
                continue
            result.update(d.lower().strip() for d in entries)
        return result
    except Exception as e:
        log.warning(f"load_full_access_domains: {e}")
        return set()




def get_cdn_domains():
    """Reads the CDN list from the external file. Fixes YouTube buffering."""
    if not os.path.exists(CDN_DOMAINS_FILE):
        # Fallback to essential infrastructure CDNs only.
        # NOTE: youtube/media CDNs deliberately excluded — they get pulled
        # in by every site with an embed, causing unintended whitelisting.
        return [
            "cloudflare.com", "fastly.net", "akamai.net", "cloudfront.net",
            "gstatic.com", "googleapis.com"
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
    # Atomic write: write to .tmp first, then rename.
    # Prevents empty/corrupt domains.json if the bot crashes mid-write.
    tmp = DOMAINS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, DOMAINS_FILE)

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
        # Run as root — call squid directly, no sudo needed
        test = subprocess.run(["/usr/sbin/squid", "-k", "parse"], capture_output=True)
        parse_out = test.stdout.decode().strip()
        parse_err = test.stderr.decode().strip()
        if test.returncode != 0:
            detail = parse_err or parse_out or "(no output)"
            msg = f"Squid config parse error (exit {test.returncode}): {detail}"
            log.error(msg)
            if respond:
                respond(f"❌ Squid config parse error:\n```{detail}```")
            return

        if parse_err:
            log.warning(f"Squid parse warnings: {parse_err}")

        result = subprocess.run(["/usr/sbin/squid", "-k", "reconfigure"], capture_output=True)
        last_reload = time.time()
        reconf_out = result.stdout.decode().strip()
        reconf_err = result.stderr.decode().strip()

        if result.returncode == 0:
            log.info("Squid reloaded successfully")
            if respond:
                respond("🧾 Squid reloaded")
        else:
            detail = reconf_err or reconf_out or "(no output)"
            log.error(f"Squid reload failed (exit {result.returncode}): {detail}")
            if respond:
                respond(f"❌ Reload failed:\n```{detail}```")

# ------------------------------------------------
# AUDIT LOGGER
# Posts structured action records to SLACK_LOG_CHANNEL.
# Fire-and-forget: a Slack API failure never breaks command execution.
# Set channel message retention to 15 days in Slack Admin settings.
# ------------------------------------------------

def audit_log(action: str, user_id: str, user_name: str, details: str, status: str = "✅ Success"):
    """Post a structured audit log entry to the dedicated log channel."""
    if not SLACK_LOG_CHANNEL:
        return
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    text = (
        f"{status} *[{action}]* by <@{user_id}> (`{user_name}`)\n"
        f"{details}\n"
        f"📅 `{timestamp}`"
    )
    try:
        app.client.chat_postMessage(channel=SLACK_LOG_CHANNEL, text=text)
    except Exception as e:
        log.error(f"audit_log: failed to post to Slack: {e}")

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
    respond("🔎 Searching...")

    # Pages to scan beyond root
    EXTRA_PATHS = ["/login", "/signin", "/app", "/dashboard", "/api"]

    # Load filter config fresh on every scan — no restart needed after edits
    social_ad_blocklist, functional_resource_types = load_filter_config()

    # --- Explicit domain override ---
    # If the requested domain is itself in the blocklist (e.g. youtube.com),
    # temporarily lift that entire blocklist category for THIS scan only.
    # This lets the domain's own CDNs (googlevideo.com, ytimg.com, etc.)
    # be discovered as dependencies instead of being silently blocked.
    # All other categories (analytics, ads, CRM) still apply normally.
    effective_blocklist = set(social_ad_blocklist)
    requested_root = f"{tldextract.extract(domain).domain}.{tldextract.extract(domain).suffix}"

    if requested_root in effective_blocklist or domain.lower() in effective_blocklist:
        try:
            with open(FILTER_CONFIG_FILE, "r") as f:
                cfg = json.load(f)
            for category, entries in cfg.get("blocklist", {}).items():
                if category == "_comment" or not isinstance(entries, list):
                    continue
                category_domains = {e.lower().strip() for e in entries}
                if requested_root in category_domains or domain.lower() in category_domains:
                    effective_blocklist -= category_domains
                    
                    log.info(f"discover: lifted '{category}' blocklist for explicit request of {domain}")
                    break
        except Exception as e:
            log.warning(f"Error: Finding {domain}: {e}")


    def capture_requests(page):
        """Attach request interceptor to a page."""

        def is_noise(host: str) -> bool:
            """
            Returns True if this host should be excluded from discovered deps.
            Uses effective_blocklist which may have the requested domain's
            own category lifted when the domain was explicitly requested.
            """
            host = host.lower().lstrip(".")
            if host in effective_blocklist:
                return True
            ext = tldextract.extract(host)
            root = f"{ext.domain}.{ext.suffix}"
            return root in effective_blocklist


        def on_request(req):
            try:
                # FILTER 1: Only count functional request types.
                # image/media/font are embeds, ads, and tracking pixels.
                if req.resource_type not in functional_resource_types:
                    return

                host = urlparse(req.url).hostname
                if not host:
                    return

                # FILTER 2: Hard-block social/ad/analytics domains.
                if is_noise(host):
                    return

                d = classify(host)
                if d:
                    discovered.add(d)
            except:
                pass

        def on_frame(frame):
            """Capture iframe src domains — apply same filters."""
            try:
                host = urlparse(frame.url).hostname
                if not host:
                    return
                if is_noise(host):
                    return
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

    # --- Full-net override for relay-based tools ---
    # Domains like UltraViewer, AnyDesk, TeamViewer route through dynamically
    # assigned relay IPs — domain whitelisting is unreliable for these.
    # If the requested domain is in full_access_domains, automatically grant
    # full-net access to the IP instead and skip the dependency scanner.
    domain_root = f"{tldextract.extract(domain).domain}.{tldextract.extract(domain).suffix}"
    full_access_set = load_full_access_domains()

    if domain_root in full_access_set or domain.lower() in full_access_set:
        safe_name = ip.replace(".", "_")
        path = os.path.join(FULLNET_DIR, f"{ip}.conf")
        rule = f"# Full-net override for {ip} (auto: {domain} is a relay-based tool)\nacl fullnet_{safe_name} src {ip}\nhttp_access allow fullnet_{safe_name}\n"
        with lock:
            with open(path, "w") as f:
                f.write(rule)
        reload_squid(respond)
        respond(
            f"🔓 *Full Internet Access Granted* for `{ip}`\n"
            f"• Reason: `{domain}` uses dynamic relay servers that cannot be whitelisted by domain.\n"
            f"• Effect: all outbound traffic from `{ip}` is now permitted.\n"
            f"• Use `/lock-net {ip}` to revoke when the session is done."
        )
        audit_log(
            action="ALLOW→FULL-NET",
            user_id=command["user_id"],
            user_name=command["user_name"],
            details=(
                f"• IP: `{ip}`\n"
                f"• Requested: `{domain}` (relay-based tool — auto-upgraded to full-net)\n"
                f"• Full internet access granted"
            ),
            status="🔓 Auto Full-Net"
        )
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
    reload_squid(respond)
    audit_log(
        action="ALLOW",
        user_id=command["user_id"],
        user_name=command["user_name"],
        details=(
            f"• IP: `{ip}`\n"
            f"• Domain: `{domain}`\n"
            f"• Expiry: {time_text}\n"
            f"• Dependencies discovered: `{len(deps)}`"
        )
    )

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

    # Collect outcome inside the lock — respond() is an HTTP call and must
    # never be made while holding the lock (would block the expiry worker).
    not_found = False
    remaining_deps = set()

    with lock:
        db = load_domains()
        if key not in db:
            not_found = True
        else:
            del db[key]
            save_domains(db)
            for entry in db.values():
                if entry["ip"] == ip:
                    remaining_deps.update(entry["deps"])

    if not_found:
        respond(f"⚠️ `{domain}` not found for `{ip}`")
        return

    # --- Rewrite IP ACL file (outside lock) ---

    list_path = os.path.join(LIST_DIR, f"{ip}.txt")

    with open(list_path, "w") as f:
        for d in sorted(remaining_deps):
            f.write(d + "\n")

    # If no domains remain, file will simply be empty
    # (CRITICAL: file is never deleted)

    regenerate_squid_configs()

    reload_squid(respond)

    respond(f"🚫 `{domain}` removed from `{ip}`")
    audit_log(
        action="DENY",
        user_id=command["user_id"],
        user_name=command["user_name"],
        details=(
            f"• IP: `{ip}`\n"
            f"• Domain: `{domain}` — access revoked"
        )
    )



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

    # Use a result code so all respond() calls happen OUTSIDE the lock.
    # respond() is an HTTP call — holding the lock during it blocks everything.
    result = None

    with lock:
        db = load_domains()
        if key not in db:
            result = "not_found"
        else:
            entry = db[key]
            now = datetime.now(timezone.utc).timestamp()
            if not entry.get("expires"):
                result = "no_expiry"
            else:
                current_expiry = entry["expires"]
                base_time = max(now, current_expiry)
                entry["expires"] = base_time + extra_seconds
                db[key] = entry
                save_domains(db)
                result = "ok"

    if result == "not_found":
        respond(f"⚠️ No active rule found for `{domain}` on `{ip}`")
        audit_log(
            action="EXTEND",
            user_id=command["user_id"],
            user_name=command["user_name"],
            details=f"• IP: `{ip}`\n• Domain: `{domain}` — rule not found",
            status="⚠️ Not Found"
        )
        return
    if result == "no_expiry":
        respond(f"⚠️ `{domain}` for `{ip}` has no expiry to extend.")
        audit_log(
            action="EXTEND",
            user_id=command["user_id"],
            user_name=command["user_name"],
            details=f"• IP: `{ip}`\n• Domain: `{domain}` — rule is permanent (no expiry)",
            status="⚠️ Skipped"
        )
        return

    respond(
        f"⏱️ *Extended access*\n"
        f"IP: `{ip}`\n"
        f"Domain: `{domain}`\n"
        f"Added: `{hours}h`"
    )
    audit_log(
        action="EXTEND",
        user_id=command["user_id"],
        user_name=command["user_name"],
        details=(
            f"• IP: `{ip}`\n"
            f"• Domain: `{domain}`\n"
            f"• Added: `{hours}h`"
        )
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
    reload_squid(respond)
    respond(f"🔓 *Full Internet Enabled* for {ip}")
    audit_log(
        action="FULL-NET",
        user_id=command["user_id"],
        user_name=command["user_name"],
        details=f"• IP: `{ip}` — unrestricted internet access granted",
        status="🔓 Enabled"
    )

# ------------------------------------------------
# COMMAND: LOCK NET
# ------------------------------------------------
@app.command("/lock-net")
def locknet_cmd(ack, respond, command):
    ack()
    ip = command["text"].strip()
    if not validate_ip(ip):
        respond("❌ Invalid IP")
        return
    path = os.path.join(FULLNET_DIR, f"{ip}.conf")
    did_disable = False
    with lock:
        if os.path.exists(path):
            with open(path, "w") as f:
                f.write("# Disabled by /lock-net command\n")
            did_disable = True
    # reload_squid() called OUTSIDE lock — it acquires the same lock
    # internally and would deadlock if called from within the with lock: block.
    if did_disable:
        reload_squid(respond)
        respond(f"🔒 *Restrictions Restored* for `{ip}`")
        audit_log(
            action="LOCK-NET",
            user_id=command["user_id"],
            user_name=command["user_name"],
            details=f"• IP: `{ip}` — full-net access revoked, normal restrictions restored",
            status="🔒 Locked"
        )
    else:
        respond(f"⚠️ No full-net override found for `{ip}`")

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

    # Read under lock to avoid racing with expiry worker mid-write
    with lock:
        db = load_domains()

    # Filter out already-expired entries (expiry worker cleans every 60s,
    # so entries in the cleanup window would otherwise show as still active)
    now = datetime.now(timezone.utc).timestamp()
    ip_rules = [
        entry for entry in db.values()
        if entry["ip"] == ip
        and (not entry.get("expires") or entry["expires"] > now)
    ]

    if not ip_rules:
        respond(f"No active rules found for `{ip}`")
        return

    lines = [f"Allowed domains for `{ip}`:"]
    for idx, rule in enumerate(sorted(ip_rules, key=lambda x: x["domain"])):
        domain = rule["domain"]
        expires = rule.get("expires")
        if expires:
            dt = datetime.fromtimestamp(expires, timezone.utc)
            expiry_str = f"expires {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        else:
            expiry_str = "indefinitely ♾️"
        lines.append(f"{idx+1}. `{domain}` — {expiry_str}")

    response_text = "\n".join(lines)
    # Guard against Slack's ~4000 char block limit
    if len(response_text) > 3800:
        response_text = response_text[:3800] + "\n… *(truncated — too many entries)*"
    respond(response_text)

# ------------------------------------------------
# SQUID MONITOR WORKER
# ------------------------------------------------

def squid_monitor_worker():
    if not SLACK_LOG_CHANNEL:
        log.warning("SLACK_LOG_CHANNEL not set. Squid crash alerts disabled.")
        return

    squid_was_down = False

    while True:
        try:
            result = subprocess.run(["systemctl", "is-active", "squid"], capture_output=True, text=True)
            is_active = result.stdout.strip() == "active"
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            if not is_active and not squid_was_down:
                squid_was_down = True
                log.error("Squid status monitor: Squid is offline!")
                try:
                    app.client.chat_postMessage(
                        channel=SLACK_LOG_CHANNEL,
                        text=(
                            f"🚨 *[SQUID-DOWN]*\n"
                            f"• The Squid proxy engine has gone *offline* or failed to reload.\n"
                            f"• Action required: check the proxy server immediately.\n"
                            f"📅 `{timestamp}`"
                        )
                    )
                except Exception as e:
                    log.error(f"Failed to send Squid crash alert: {e}")

            elif is_active and squid_was_down:
                squid_was_down = False
                log.info("Squid status monitor: Squid is back online.")
                try:
                    app.client.chat_postMessage(
                        channel=SLACK_LOG_CHANNEL,
                        text=(
                            f"✅ *[SQUID-RECOVERY]*\n"
                            f"• The Squid proxy engine is back *online* and functioning normally.\n"
                            f"📅 `{timestamp}`"
                        )
                    )
                except Exception as e:
                    log.error(f"Failed to send Squid recovery alert: {e}")

        except Exception as e:
            log.error(f"Squid monitor encountered an error: {e}")

        time.sleep(30)

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

    threading.Thread(
        target=squid_monitor_worker,
        daemon=True
    ).start()

    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    print("🚀 Slack Squid Bot is active and monitoring...")
    handler.start()
