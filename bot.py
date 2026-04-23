import os
import json
import time
import logging
import threading
import subprocess
import ipaddress
import tldextract
import shutil
import requests

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
SLACK_BOT_TOKEN     = os.environ.get("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN     = os.environ.get("SLACK_APP_TOKEN")
SLACK_ALERT_CHANNEL = os.environ.get("SLACK_ALERT_CHANNEL")      # Squid crash/recovery alerts
SLACK_ADMIN_CHANNEL = os.environ.get("SLACK_ADMIN_CHANNEL")      # Where approval cards are posted
SLACK_ADMIN_USER_IDS = {
    uid.strip()
    for uid in os.environ.get("SLACK_ADMIN_USER_IDS", "").split(",")
    if uid.strip()
}

# Jira
JIRA_BASE_URL    = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
JIRA_EMAIL       = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN   = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "NET")

LIST_DIR         = "/etc/squid/lists"
DOMAINS_FILE     = "/etc/squid/domains.json"
FULLNET_DIR      = "/etc/squid/conf.d/fullnet"
OVERRIDE_DIR     = "/etc/squid/conf.d/override"
SPECIAL_APPS_DIR = "/etc/squid/special_apps"
CDN_DOMAINS_FILE = "/etc/squid/cdn_domains.txt"
DOMAIN_CONF      = "/etc/squid/conf.d/02-domain-lists.conf"
HOSTS_CONF       = "/etc/squid/conf.d/01-hosts.conf"
GROUP_RULES_CONF = "/etc/squid/conf.d/03-group.conf"
RULES_CONF       = "/etc/squid/conf.d/03-rules.conf"

FILTER_CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "filter_config.json")
PENDING_FILE       = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pending_requests.json")

# STARTUP GUARD
os.makedirs(FULLNET_DIR, exist_ok=True)
os.makedirs(OVERRIDE_DIR, exist_ok=True)
os.makedirs(SPECIAL_APPS_DIR, exist_ok=True)
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

app          = App(token=SLACK_BOT_TOKEN)
lock         = threading.Lock()
pending_lock = threading.Lock()
CDN_LIST     = []

# ------------------------------------------------
# DISCOVERY FILTER CONFIG  (loaded from filter_config.json)
# Edit filter_config.json to add/remove blocked domains or change
# allowed resource types — no bot restart required.
# ------------------------------------------------

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


def load_special_domains() -> dict:
    """
    Reads the special_domains section from filter_config.json.
    Returns a dict mapping root domains to their app name, e.g.:
      {"ultraviewer.net": "ultraviewer", "teamviewer.com": "teamviewer"}

    The app name corresponds to a list file at:
      /etc/squid/special_apps/<app_name>.txt

    Example config entry:
      "special_domains": {
          "ultraviewer": ["ultraviewer.net", "ultraviewer.com"],
          "teamviewer":  ["teamviewer.com", "teamviewer.net"]
      }
    """
    if not os.path.exists(FILTER_CONFIG_FILE):
        return {}
    try:
        with open(FILTER_CONFIG_FILE, "r") as f:
            cfg = json.load(f)
        result = {}
        for app_name, entries in cfg.get("special_domains", {}).items():
            if app_name == "_comment" or not isinstance(entries, list):
                continue
            for d in entries:
                result[d.lower().strip()] = app_name
        return result
    except Exception as e:
        log.warning(f"load_special_domains: {e}")
        return {}


def get_cdn_domains():
    """Reads the CDN list from the external file."""
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


# ------------------------------------------------
# SQUID CONFIG GENERATOR
# ------------------------------------------------

def regenerate_squid_configs():
    """
    Rebuilds 02-domain-lists.conf and 03-rules.conf from:
      - /etc/squid/lists/groups/*.txt  (group domains)
      - /etc/squid/lists/<ip>.txt      (per-IP domains)
    Must be called OUTSIDE the lock — does file I/O.
    """
    GROUP_DIR = os.path.join(LIST_DIR, "groups")

    # Ensure at least one group file exists
    if not os.listdir(GROUP_DIR):
        placeholder = os.path.join(GROUP_DIR, "default.txt")
        with open(placeholder, "w") as f:
            f.write(".example.com\n")

    ip_files = []
    group_files = []

    if os.path.exists(GROUP_DIR):
        for f in os.listdir(GROUP_DIR):
            if f.endswith(".txt"):
                group_files.append(f)

    for f in os.listdir(LIST_DIR):
        full_path = os.path.join(LIST_DIR, f)
        if os.path.isdir(full_path):
            continue
        if f.endswith(".dst.txt"):
            continue
        if not f.endswith(".txt"):
            continue
        ip = f.replace(".txt", "")
        try:
            ipaddress.ip_address(ip)
            ip_files.append(f)
        except ValueError:
            continue

    # Build domain config
    domain_lines = [
        "# =====================================",
        "# Domain Lists (Auto Generated)",
        "# =====================================",
        ""
    ]

    domain_lines.append("# GROUP DOMAIN LISTS")
    for g in sorted(group_files):
        path = os.path.join(GROUP_DIR, g)
        if os.path.getsize(path) == 0:
            continue
        name = g.replace(".txt", "")
        safe = name.replace("-", "_")
        domain_lines.append(f'acl group_{safe}_domains dstdomain "{path}"')

    domain_lines.append("")
    domain_lines.append("# PER-CLIENT IP: dstdomain + optional dst (literal destination IPs)")

    for file in sorted(ip_files):
        ip = file.replace(".txt", "")
        safe = ip.replace(".", "_")
        path_domains = os.path.join(LIST_DIR, file)
        path_dst = os.path.join(LIST_DIR, f"{ip}.dst.txt")
        if not os.path.exists(path_domains):
            open(path_domains, "w").close()
        has_domains = os.path.getsize(path_domains) > 0
        has_dst = os.path.exists(path_dst) and os.path.getsize(path_dst) > 0
        if not has_domains and not has_dst:
            continue
        domain_lines.append(f'acl ip_{safe} src {ip}')
        if has_domains:
            domain_lines.append(f'acl ip_{safe}_domains dstdomain "{path_domains}"')
        if has_dst:
            domain_lines.append(f'acl ip_{safe}_dst dst "{path_dst}"')

    with open(DOMAIN_CONF, "w") as f:
        f.write("\n".join(domain_lines) + "\n")

    # Build rules config
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
        path_domains = os.path.join(LIST_DIR, file)
        path_dst = os.path.join(LIST_DIR, f"{ip}.dst.txt")
        has_domains = os.path.exists(path_domains) and os.path.getsize(path_domains) > 0
        has_dst = os.path.exists(path_dst) and os.path.getsize(path_dst) > 0
        if not has_domains and not has_dst:
            continue
        if has_domains:
            rule_lines.append(f"http_access allow ip_{safe} ip_{safe}_domains")
        if has_dst:
            rule_lines.append(f"http_access allow ip_{safe} ip_{safe}_dst")

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

def rebuild_override_configs():
    """
    Rebuilds /etc/squid/conf.d/override/<app_name>.conf for every special app
    that has active client IPs in the database.

    For each app:
      1. Reads /etc/squid/special_apps/<app_name>.txt (mixed domains + IPs)
      2. Splits into <app_name>.domains.txt and <app_name>.ips.txt
      3. Generates /etc/squid/conf.d/override/<app_name>.conf with proper ACLs
      4. Cleans up .conf files for apps that no longer have active clients

    Called outside lock.
    """
    os.makedirs(OVERRIDE_DIR, exist_ok=True)

    db = load_domains()
    special = load_special_domains()  # dict: root_domain → app_name

    # Build a mapping: app_name → set of client IPs that have active rules
    app_ips = {}  # { "ultraviewer": {"192.168.1.50", ...}, ... }
    for entry in db.values():
        d = entry["domain"].lower()
        if validate_ip(d):
            continue
        ext = tldextract.extract(d)
        root = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else d
        app_name = special.get(root)
        if app_name:
            app_ips.setdefault(app_name, set()).add(entry["ip"])

    # Collect all known app names from config (to clean up stale .conf files)
    all_app_names = set(special.values())

    for app_name in all_app_names:
        conf_path = os.path.join(OVERRIDE_DIR, f"{app_name}.conf")
        ips = app_ips.get(app_name)

        if not ips:
            # No active clients — remove the override conf if it exists
            if os.path.exists(conf_path):
                os.remove(conf_path)
                log.info(f"rebuild_override_configs: removed {conf_path} (no active clients)")
            continue

        # Read the app's master list file from /etc/squid/special_apps/
        list_file = os.path.join(SPECIAL_APPS_DIR, f"{app_name}.txt")
        app_domains = []
        app_dst_ips = []

        if os.path.exists(list_file):
            with open(list_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Lines starting with a digit are IPs or CIDR ranges
                    if line[0].isdigit():
                        app_dst_ips.append(line)
                    else:
                        app_domains.append(line)
        else:
            log.warning(
                f"rebuild_override_configs: list file missing for '{app_name}': {list_file}"
            )

        # Write split files for Squid (dstdomain cannot parse raw IPs)
        dom_file = os.path.join(SPECIAL_APPS_DIR, f"{app_name}.domains.txt")
        ip_file  = os.path.join(SPECIAL_APPS_DIR, f"{app_name}.ips.txt")

        with open(dom_file, "w") as f:
            f.write("\n".join(app_domains) + "\n" if app_domains else "")
        with open(ip_file, "w") as f:
            f.write("\n".join(app_dst_ips) + "\n" if app_dst_ips else "")

        # Build the Squid override config
        safe_name   = app_name.replace("-", "_")
        ip_list_str = " ".join(ips)

        rule = (
            f"# Auto Generated Override — {app_name}\n"
            f"acl {safe_name}_src src {ip_list_str}\n"
        )
        if app_domains:
            rule += f'acl {safe_name}_dst_dom dstdomain "{dom_file}"\n'
            rule += f"http_access allow {safe_name}_src {safe_name}_dst_dom\n"
        if app_dst_ips:
            rule += f'acl {safe_name}_dst_ip dst "{ip_file}"\n'
            rule += f"http_access allow {safe_name}_src {safe_name}_dst_ip\n"

        with open(conf_path, "w") as f:
            f.write(rule)
        log.info(
            f"rebuild_override_configs: wrote {conf_path} — "
            f"{len(ips)} client(s), {len(app_domains)} domains, {len(app_dst_ips)} IPs"
        )


# ------------------------------------------------
# VALIDATION & UTILITIES
# ------------------------------------------------

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_domain(domain):
    ext = tldextract.extract(domain)
    return bool(ext.domain and ext.suffix)


def is_destination_ip(raw):
    """True if the allow/deny target is a literal destination IP (not a hostname)."""
    return validate_ip(normalize(raw))


def canonical_destination_ip(raw):
    """Normalize a destination IP string for stable keys and list files."""
    return str(ipaddress.ip_address(normalize(raw)))


def load_domains():
    if not os.path.exists(DOMAINS_FILE):
        return {}
    try:
        with open(DOMAINS_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


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
# HELPER: rebuild IP file from domains.json
#
# FIX: allow_cmd previously merged new deps with the existing IP file
# using `current | deps`, causing stale domains from old /allow calls to
# accumulate permanently. Now all IP file writes go through this function,
# which rebuilds purely from domains.json — the single source of truth.
# Matches what expiry_worker already did correctly.
# ------------------------------------------------

def rebuild_ip_file(ip, db):
    """
    Rewrites Squid list files for this client IP from domains.json:
      - <ip>.txt       — dstdomain patterns (from Playwright deps for hostname rules)
      - <ip>.dst.txt   — literal destination IPs (Squid acl ... dst file)

    Cleared to empty when no rules remain for this client.
    Must be called while holding the lock.
    """
    dstdomain_lines = set()
    dst_ips = set()
    for entry in db.values():
        if entry["ip"] != ip:
            continue
        dest = entry["domain"]
        if validate_ip(dest):
            dst_ips.add(str(ipaddress.ip_address(dest)))
            for d in entry.get("deps", []):
                if validate_ip(d):
                    dst_ips.add(str(ipaddress.ip_address(d)))
        else:
            dstdomain_lines.update(entry.get("deps", []))

    path_domains = os.path.join(LIST_DIR, f"{ip}.txt")
    path_dst = os.path.join(LIST_DIR, f"{ip}.dst.txt")
    with open(path_domains, "w") as f:
        for d in sorted(dstdomain_lines):
            f.write(d + "\n")
    with open(path_dst, "w") as f:
        for d in sorted(dst_ips):
            f.write(d + "\n")


# ------------------------------------------------
# SQUID RELOAD (THREAD SAFE)
#
# FIX: The original reload_squid(respond) passed Slack's respond() callback
# directly into the reload function. respond() is a Slack webhook that expires
# in ~3 seconds, but Squid's parse + reconfigure can take longer — causing the
# confirmation message to be silently dropped every time.
#
# Solution: reload_squid() now accepts an optional Slack channel ID and posts
# results via app.client.chat_postMessage(), which has no timeout.
# All command handlers call respond() BEFORE triggering the reload so the user
# gets immediate feedback, and the reload result posts asynchronously after.
# ------------------------------------------------

def reload_squid(channel=None):
    """
    Parses and reloads Squid config.
    If channel is provided, posts the result to that Slack channel
    via chat_postMessage (no webhook timeout risk).
    Returns True on success, False on failure.
    """
    with lock:
        test = subprocess.run(["/usr/sbin/squid", "-k", "parse"], capture_output=True)
        parse_out = test.stdout.decode().strip()
        parse_err = test.stderr.decode().strip()

        if test.returncode != 0:
            detail = parse_err or parse_out or "(no output)"
            msg = f"❌ Squid config parse error (exit {test.returncode}):\n```{detail}```"
            log.error(msg)
            if channel:
                try:
                    app.client.chat_postMessage(channel=channel, text=msg)
                except Exception as e:
                    log.error(f"reload_squid: failed to post parse error: {e}")
            return False

        if parse_err:
            log.warning(f"Squid parse warnings: {parse_err}")

        result = subprocess.run(["/usr/sbin/squid", "-k", "reconfigure"], capture_output=True)
        reconf_out = result.stdout.decode().strip()
        reconf_err = result.stderr.decode().strip()

        if result.returncode == 0:
            log.info("Squid reloaded successfully")
            if channel:
                try:
                    app.client.chat_postMessage(channel=channel, text="🧾 Squid reloaded successfully")
                except Exception as e:
                    log.error(f"reload_squid: failed to post reload success: {e}")
            return True
        else:
            detail = reconf_err or reconf_out or "(no output)"
            msg = f"❌ Reload failed (exit {result.returncode}):\n```{detail}```"
            log.error(msg)
            if channel:
                try:
                    app.client.chat_postMessage(channel=channel, text=msg)
                except Exception as e:
                    log.error(f"reload_squid: failed to post reload error: {e}")
            return False


# ------------------------------------------------
# JIRA INTEGRATION
# ------------------------------------------------

def _jira_auth():
    return (JIRA_EMAIL, JIRA_API_TOKEN)

def _jira_headers():
    return {"Content-Type": "application/json", "Accept": "application/json"}


def jira_create_ticket(summary: str, description: str, command_name: str) -> tuple:
    """
    Creates a Jira Task. Returns (issue_key, issue_id).
    Raises RuntimeError on failure.
    """
    if not JIRA_BASE_URL or not JIRA_EMAIL or not JIRA_API_TOKEN:
        raise RuntimeError("Jira credentials not configured — add JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN to .env")

    url = f"{JIRA_BASE_URL}/rest/api/3/issue"
    payload = {
        "fields": {
            "project":   {"key": JIRA_PROJECT_KEY},
            "issuetype": {"name": "Task"},
            "summary":   summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description}]
                    }
                ]
            },
            "labels": ["squid-proxy", "pending-approval", command_name]
        }
    }
    resp = requests.post(url, json=payload, auth=_jira_auth(), headers=_jira_headers(), timeout=15)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Jira API {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    return data["key"], data["id"]


def jira_get_transitions(issue_key: str) -> dict:
    """
    Returns a dict mapping both:
      - transition action name  → transition id   (e.g. 'Approve' → '21')
      - destination status name → transition id   (e.g. 'Approved' → '21')
    This lets jira_transition_ticket find the right transition regardless of
    how the workflow action is labelled in Jira.
    """
    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/transitions"
    try:
        resp = requests.get(url, auth=_jira_auth(), headers=_jira_headers(), timeout=10)
        if resp.status_code == 200:
            result = {}
            for t in resp.json().get("transitions", []):
                result[t["name"]] = t["id"]                    # action name  e.g. 'Approve'
                to_status = t.get("to", {}).get("name", "")
                if to_status and to_status not in result:
                    result[to_status] = t["id"]               # dest status  e.g. 'Approved'
            log.debug(f"jira_get_transitions [{issue_key}]: {list(result.keys())}")
            return result
    except Exception as e:
        log.warning(f"jira_get_transitions: {e}")
    return {}


def jira_transition_ticket(issue_key: str, target_status: str):
    """
    Transitions a Jira issue to the named status.
    For approval  → pass 'Done'
    For rejection → pass 'Rejected' (falls back through Won't Do → Cancelled → Done)
    Tries exact match → case-insensitive match → rejection-specific fallbacks → Done.
    """
    transitions = jira_get_transitions(issue_key)
    if not transitions:
        log.warning(f"jira_transition_ticket: no transitions available for {issue_key}")
        return

    # Exact match first
    tid = transitions.get(target_status)

    # Case-insensitive match
    if not tid:
        tid = next((v for k, v in transitions.items() if k.lower() == target_status.lower()), None)

    # Rejection-specific fallback chain
    if not tid and target_status.lower() in ("rejected", "reject", "won't do", "cancelled"):
        tid = (
            transitions.get("Won't Do")
            or transitions.get("Cancelled")
            or transitions.get("Invalid")
            or transitions.get("Done")
            or next(iter(transitions.values()), None)
        )

    # Generic fallback
    if not tid:
        tid = (
            transitions.get("Done")
            or transitions.get("Close Issue")
            or next(iter(transitions.values()), None)
        )

    if not tid:
        log.warning(f"jira_transition_ticket: could not find any transition for '{target_status}' on {issue_key}")
        return

    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/transitions"
    try:
        resp = requests.post(
            url,
            json={"transition": {"id": tid}},
            auth=_jira_auth(),
            headers=_jira_headers(),
            timeout=10
        )
        if resp.status_code not in (200, 204):
            log.warning(f"jira_transition_ticket: {resp.status_code} — {resp.text[:200]}")
        else:
            log.info(f"jira_transition_ticket: {issue_key} → '{target_status}' (tid={tid})")
    except Exception as e:
        log.error(f"jira_transition_ticket: {e}")


def _jira_update_labels(issue_key: str, add_labels: list, remove_labels: list = None):
    """
    Adds/removes labels on a Jira issue.
    Used to tag tickets as 'approved' or 'rejected' regardless of workflow status.
    """
    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}"
    try:
        resp = requests.get(url, auth=_jira_auth(), headers=_jira_headers(), timeout=10)
        if resp.status_code != 200:
            log.warning(f"_jira_update_labels: could not fetch issue {issue_key}: {resp.status_code}")
            return
        current = set(resp.json().get("fields", {}).get("labels", []))
        for lbl in (remove_labels or []):
            current.discard(lbl)
        current.update(add_labels)
        patch_resp = requests.put(
            url,
            json={"fields": {"labels": list(current)}},
            auth=_jira_auth(),
            headers=_jira_headers(),
            timeout=10
        )
        if patch_resp.status_code not in (200, 204):
            log.warning(f"_jira_update_labels: {patch_resp.status_code} — {patch_resp.text[:200]}")
    except Exception as e:
        log.error(f"_jira_update_labels: {e}")


def jira_add_comment(issue_key: str, text: str):
    """Adds a plain-text comment to a Jira issue."""
    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/comment"
    payload = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": text}]}
            ]
        }
    }
    try:
        requests.post(url, json=payload, auth=_jira_auth(), headers=_jira_headers(), timeout=10)
    except Exception as e:
        log.error(f"jira_add_comment: {e}")


# ------------------------------------------------
# PENDING REQUESTS STORE
# ------------------------------------------------

def load_pending() -> dict:
    """Load pending approval requests from disk."""
    if not os.path.exists(PENDING_FILE):
        return {}
    try:
        with open(PENDING_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_pending(data: dict):
    """Atomically save pending approval requests to disk."""
    tmp = PENDING_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, PENDING_FILE)


# ------------------------------------------------
# ADMIN HELPERS
# ------------------------------------------------

def is_admin(user_id: str) -> bool:
    """Returns True if the Slack user is in the configured admin list."""
    return user_id in SLACK_ADMIN_USER_IDS


def build_approval_blocks(jira_key: str, summary_text: str, requester_name: str, jira_url: str) -> list:
    """Build the Slack Block Kit approval card."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🔔  Proxy Change Request",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Ticket:*  `{jira_key}`\n"
                    f"*Status:*  🟡 Pending Approval"
                ),
            },
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": "🔗 View in Jira", "emoji": True},
                "url": jira_url,
                "action_id": "jira_link_button",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": summary_text},
        },
        {"type": "divider"},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"👤 *Requester:* {requester_name}  ·  "
                        f"📅 {timestamp}"
                    ),
                }
            ],
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅  Approve", "emoji": True},
                    "style": "primary",
                    "action_id": "squid_approve",
                    "value": jira_key,
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Confirm Approval"},
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"Are you sure you want to *approve* `{jira_key}`?\n\n"
                                "This will execute the proxy change immediately."
                            ),
                        },
                        "confirm": {"type": "plain_text", "text": "Yes, Approve"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌  Reject", "emoji": True},
                    "style": "danger",
                    "action_id": "squid_reject",
                    "value": jira_key,
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Confirm Rejection"},
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"Are you sure you want to *reject* `{jira_key}`?\n\n"
                                "The requester will be notified."
                            ),
                        },
                        "confirm": {"type": "plain_text", "text": "Yes, Reject"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
            ],
        },
    ]


def _update_approval_card(client, entry: dict, status_text: str, actor_name: str):
    """Replace the approval card buttons with a resolved status banner."""
    msg_ts  = entry.get("slack_message_ts")
    msg_ch  = entry.get("slack_message_channel")
    if not msg_ts or not msg_ch:
        return

    jira_key  = entry.get("jira_key", "???")
    command   = entry.get("command", "unknown")
    requester = entry.get("requester_name", "unknown")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Determine the status indicator
    is_approved = "approved" in status_text.lower()
    status_icon = "🟢" if is_approved else "🔴"
    status_label = "Approved" if is_approved else "Rejected"

    # Reconstruct a summary from the stored args
    args = entry.get("args", {})
    detail_parts = []
    if args.get("ip"):
        detail_parts.append(f"*Client IP:* `{args['ip']}`")
    if args.get("domain"):
        detail_parts.append(f"*Target:* `{args['domain']}`")
    if args.get("hours"):
        detail_parts.append(f"*Extension:* `{args['hours']}h`")
    if args.get("time_text"):
        detail_parts.append(f"*Duration:* {args['time_text']}")
    detail_text = "\n".join(detail_parts) if detail_parts else "_No details available_"

    try:
        client.chat_update(
            channel=msg_ch,
            ts=msg_ts,
            text=status_text,
            blocks=[
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{status_icon}  Request {status_label} — {jira_key}",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Command:* `/{command}`\n"
                            f"{detail_text}"
                        ),
                    },
                },
                {"type": "divider"},
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"👤 Requested by *{requester}*  ·  "
                                f"⚡ {status_label} by *{actor_name}*  ·  "
                                f"📅 {timestamp}"
                            ),
                        }
                    ],
                },
            ],
        )
    except Exception as e:
        log.error(f"_update_approval_card: {e}")


def _submit_ticket(command_name: str, summary: str, description: str, args: dict,
                   user_id: str, user_name: str, channel_id: str,
                   summary_text: str) -> tuple:
    """
    Core helper called by every slash command handler.
    Creates the Jira ticket, saves it to pending_requests.json,
    posts the approval card, and returns the jira_key (or None on error).
    """
    try:
        jira_key, jira_id = jira_create_ticket(summary, description, command_name)
    except Exception as e:
        return None, str(e)

    jira_url = f"{JIRA_BASE_URL}/browse/{jira_key}"
    entry = {
        "jira_key":          jira_key,
        "jira_id":           jira_id,
        "command":           command_name,
        "args":              args,
        "requester_id":      user_id,
        "requester_name":    user_name,
        "requester_channel": channel_id,
        "created_at":        datetime.now(timezone.utc).timestamp(),
        "status":            "pending",
        "slack_message_ts":       None,
        "slack_message_channel":  None,
    }

    with pending_lock:
        pending = load_pending()
        pending[jira_key] = entry
        save_pending(pending)

    # Post approval card to admin channel
    if SLACK_ADMIN_CHANNEL:
        try:
            msg_result = app.client.chat_postMessage(
                channel=SLACK_ADMIN_CHANNEL,
                text=f"🎫 Proxy Change Request {jira_key} — awaiting approval",
                blocks=build_approval_blocks(jira_key, summary_text, user_name, jira_url)
            )
            with pending_lock:
                pending = load_pending()
                if jira_key in pending:
                    pending[jira_key]["slack_message_ts"]      = msg_result["ts"]
                    pending[jira_key]["slack_message_channel"] = SLACK_ADMIN_CHANNEL
                    save_pending(pending)
        except Exception as e:
            log.error(f"_submit_ticket: failed to post approval card: {e}")
    else:
        log.warning("SLACK_ADMIN_CHANNEL not set — approval card not sent.")

    return jira_key, None


# ------------------------------------------------
# EXECUTE PROXY CHANGE (called after admin approval)
# Runs in a background thread — do NOT hold any locks when calling this.
# ------------------------------------------------

def _post_to_channel(channel_id: str, text: str):
    """Fire-and-forget message to a Slack channel."""
    if not channel_id:
        return
    try:
        app.client.chat_postMessage(channel=channel_id, text=text)
    except Exception as e:
        log.error(f"_post_to_channel: {e}")


def audit_log(text: str):
    """Post an audit log message to the SLACK_ALERT_CHANNEL if configured."""
    if SLACK_ALERT_CHANNEL:
        try:
            app.client.chat_postMessage(channel=SLACK_ALERT_CHANNEL, text=f"📝 *Audit Log:*\n{text}")
        except Exception as e:
            log.error(f"audit_log: {e}")


def execute_proxy_change(entry: dict, approver_id: str, approver_name: str):
    """
    Execute the actual Squid proxy change for an approved request.
    Designed to run in a background thread.
    Posts updates to the requester's channel.
    """
    command_name      = entry["command"]
    args              = entry["args"]
    requester_channel = entry.get("requester_channel")
    jira_key          = entry["jira_key"]

    def post(text, audit=False):
        _post_to_channel(requester_channel, text)
        if audit:
            audit_log(f"*[Ticket {jira_key}]*\n{text}")

    try:
        # ── /allow ──────────────────────────────────────────────────
        if command_name == "allow":
            ip               = args["ip"]
            domain           = args["domain"]
            expiry_timestamp = args.get("expiry_timestamp")
            time_text        = args.get("time_text", "indefinitely ♾️")
            is_dest_ip       = args.get("is_dest_ip", False)
            deps             = set()

            if is_dest_ip:
                post(f"⚙️ Allowing destination IP `{domain}` for client `{ip}`...")
            else:
                special_map = load_special_domains()
                ext = tldextract.extract(domain)
                root_domain  = f"{ext.domain}.{ext.suffix}"
                matched_app  = special_map.get(root_domain)

                if matched_app:
                    post(f"⚙️ Applying *{matched_app}* override for `{ip}`...")
                    base = classify(domain)
                    if base:
                        deps.add(base)
                else:
                    post(f"⚙️ Processing `{domain}` for `{ip}`...")
                    deps = discover(domain, post)
                    base = classify(domain)
                    if base:
                        deps.add(base)

            with lock:
                db = load_domains()
                db[f"{ip}:{domain}"] = {
                    "ip":      ip,
                    "domain":  domain,
                    "deps":    list(deps),
                    "expires": expiry_timestamp
                }
                save_domains(db)
                rebuild_ip_file(ip, db)

            regenerate_squid_configs()
            rebuild_override_configs()

            target_label = "Destination IP" if is_dest_ip else "Domain"
            post(
                f"✅ *Access granted* (approved by <@{approver_id}>)\n"
                f"• Client IP: `{ip}`\n"
                f"• {target_label}: `{domain}`\n"
                f"• Dependencies: `{len(deps)}`\n"
                f"• Expiry: {time_text}\n"
                f"⚙️ Reloading Squid...",
                audit=True
            )
            reload_squid(channel=requester_channel)

        # ── /deny ───────────────────────────────────────────────────
        elif command_name == "deny":
            ip     = args["ip"]
            domain = args["domain"]
            key    = f"{ip}:{domain}"
            not_found = False

            with lock:
                db = load_domains()
                if key not in db:
                    not_found = True
                else:
                    del db[key]
                    save_domains(db)
                    rebuild_ip_file(ip, db)

            if not_found:
                post(f"⚠️ `{domain}` not found for `{ip}` — may have already been removed.")
            else:
                regenerate_squid_configs()
                rebuild_override_configs()
                post(
                    f"🚫 *Access removed* (approved by <@{approver_id}>)\n"
                    f"`{domain}` removed from `{ip}`. ⚙️ Reloading Squid...",
                    audit=True
                )
                reload_squid(channel=requester_channel)

        # ── /extend ─────────────────────────────────────────────────
        elif command_name == "extend":
            ip     = args["ip"]
            domain = args["domain"]
            hours  = args["hours"]
            extra_seconds = hours * 3600
            key    = f"{ip}:{domain}"
            result = None

            with lock:
                db = load_domains()
                if key not in db:
                    result = "not_found"
                else:
                    db_entry = db[key]
                    now = datetime.now(timezone.utc).timestamp()
                    if not db_entry.get("expires"):
                        result = "no_expiry"
                    else:
                        base_time = max(now, db_entry["expires"])
                        db_entry["expires"] = base_time + extra_seconds
                        db[key] = db_entry
                        save_domains(db)
                        result = "ok"

            if result == "not_found":
                post(f"⚠️ No active rule found for `{domain}` on `{ip}`")
            elif result == "no_expiry":
                post(f"⚠️ `{domain}` for `{ip}` has no expiry to extend.")
            else:
                post(
                    f"⏱️ *Extended access* (approved by <@{approver_id}>)\n"
                    f"• IP: `{ip}`\n"
                    f"• Domain: `{domain}`\n"
                    f"• Added: `{hours}h`",
                    audit=True
                )

        # ── /full-net ────────────────────────────────────────────────
        elif command_name == "full-net":
            ip        = args["ip"]
            safe_name = ip.replace(".", "_")
            path      = os.path.join(FULLNET_DIR, f"{ip}.conf")
            rule = (
                f"# Override for {ip}\n"
                f"acl fullnet_{safe_name} src {ip}\n"
                f"http_access allow fullnet_{safe_name}\n"
            )
            with lock:
                with open(path, "w") as f:
                    f.write(rule)
            post(
                f"🔓 *Full Internet Enabled* for `{ip}` "
                f"(approved by <@{approver_id}>). ⚙️ Reloading Squid...",
                audit=True
            )
            reload_squid(channel=requester_channel)

        # ── /lock-net ────────────────────────────────────────────────
        elif command_name == "lock-net":
            ip           = args["ip"]
            path         = os.path.join(FULLNET_DIR, f"{ip}.conf")
            did_disable  = False
            with lock:
                if os.path.exists(path):
                    with open(path, "w") as f:
                        f.write("# Disabled by /lock-net command\n")
                    did_disable = True

            if did_disable:
                post(
                    f"🔒 *Restrictions Restored* for `{ip}` "
                    f"(approved by <@{approver_id}>). ⚙️ Reloading Squid...",
                    audit=True
                )
                reload_squid(channel=requester_channel)
            else:
                post(f"⚠️ No full-net override found for `{ip}`")

        # ── Close Jira ticket: Approved ───────────────────────────────
        jira_transition_ticket(jira_key, "Approved")
        _jira_update_labels(jira_key, add_labels=["approved"], remove_labels=["pending-approval"])
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        jira_add_comment(
            jira_key,
            f"APPROVED — executed by {approver_name} at {timestamp}"
        )

    except Exception as e:
        log.error(f"execute_proxy_change [{jira_key}]: {e}")
        post(f"❌ Error executing approved request `{jira_key}`: {e}")


# ------------------------------------------------
# DOMAIN DISCOVERY WITH PLAYWRIGHT
# ------------------------------------------------

def discover(domain, respond):
    """
    Dependency scanner using Playwright.
    - Follows redirects (tracks final URL)
    - Captures lazy/deferred resources (scroll + interactions)
    - Scans multiple pages (root + login + common subpages)
    - Captures iframes via framenavigated
    """
    discovered = set()
    respond("🔎 Searching...")

    # Load filter config fresh on every scan — no restart needed after edits
    social_ad_blocklist, functional_resource_types = load_filter_config()

    # If the requested domain is itself in the blocklist (e.g. youtube.com),
    # temporarily lift that entire blocklist category for THIS scan only.
    # This lets the domain's own CDNs be discovered as dependencies instead
    # of being silently blocked.
    effective_blocklist = set(social_ad_blocklist)
    ext_info = tldextract.extract(domain)
    requested_root = f"{ext_info.domain}.{ext_info.suffix}"

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
            log.warning(f"Error lifting blocklist for {domain}: {e}")

    def capture_requests(page):
        """Attach request interceptor to a page."""

        def is_noise(host: str) -> bool:
            host = host.lower().lstrip(".")
            if host in effective_blocklist:
                return True
            ext = tldextract.extract(host)
            root = f"{ext.domain}.{ext.suffix}"
            return root in effective_blocklist

        def on_request(req):
            try:
                if req.resource_type not in functional_resource_types:
                    return
                host = urlparse(req.url).hostname
                if not host:
                    return
                if is_noise(host):
                    return
                d = classify(host)
                if d:
                    discovered.add(d)
            except Exception:
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
            except Exception:
                pass

        page.on("request", on_request)
        page.on("framenavigated", on_frame)

    def interact_page(page):
        """Simulate user interactions to trigger lazy loads."""
        try:
            for scroll_y in [300, 600, 1000, 1500, 2000]:
                page.mouse.wheel(0, scroll_y)
                page.wait_for_timeout(500)
            page.mouse.move(640, 400)
            page.wait_for_timeout(500)
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
        except Exception:
            pass

    with sync_playwright() as p:
        browser = None
        try:
            browser = p.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-sandbox"]
            )
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800}
            )

            # Page 1: Root domain
            page = context.new_page()
            capture_requests(page)

            try:
                response = page.goto(
                    "https://" + domain,
                    timeout=30000,
                    wait_until="domcontentloaded"
                )
                if response:
                    final_url  = response.url
                    final_host = urlparse(final_url).hostname
                    if final_host:
                        d = classify(final_host)
                        if d:
                            discovered.add(d)
                        if final_host != domain:
                            respond(f"↪️ Redirect detected: {final_host}")
                interact_page(page)
            except Exception as e:
                respond(f"⚠️ Root scan warning: {e}")
            finally:
                page.close()

        except Exception as e:
            respond(f"⚠️ Scanner error: {str(e)}")
        finally:
            if browser:
                browser.close()

    respond(f"✅ {len(discovered)} dependencies found")
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
        # Phase 1 — Minimal lock scope: only DB reads/writes
        # FIX: heavy I/O (file writes, regenerate_squid_configs) moved
        # OUTSIDE the lock. The previous version moved these back inside,
        # which blocks all other threads (commands, monitor) for the full
        # duration of config regeneration.
        # -----------------------------
        with lock:
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
                    entry = db[key]
                    log.info(
                        f"expiry_worker: expired — IP={entry['ip']} domain={entry['domain']}"
                    )
                    audit_log(
                        f"⏰ *Access Expired*\n"
                        f"• Client IP: `{entry['ip']}`\n"
                        f"• Domain/IP: `{entry['domain']}`"
                    )
                    del db[key]
                save_domains(db)
                changed = True

            if changed:
                db_snapshot = dict(db)

        # -----------------------------
        # Phase 2 — Heavy I/O outside lock
        # -----------------------------
        if changed and db_snapshot is not None:
            client_ips = {e["ip"] for e in db_snapshot.values()}
            for ip in client_ips:
                rebuild_ip_file(ip, db_snapshot)

            for filename in os.listdir(LIST_DIR):
                if filename.endswith(".dst.txt"):
                    base = filename[:-8]
                elif filename.endswith(".txt"):
                    base = filename[:-4]
                else:
                    continue
                try:
                    ipaddress.ip_address(base)
                except ValueError:
                    continue
                if base not in client_ips:
                    open(os.path.join(LIST_DIR, filename), "w").close()

            regenerate_squid_configs()
            rebuild_override_configs()
            reload_squid()

        time.sleep(60)


# ------------------------------------------------
# SLASH COMMANDS — now create Jira tickets + request approval
# ------------------------------------------------

@app.command("/allow")
def allow_cmd(ack, respond, command):
    ack()
    args = command["text"].split()
    if len(args) < 2:
        respond("Usage: `/allow <client_ip> <domain|destination_ip> [Nh]`")
        return

    ip, raw_target = args[0], args[1]
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

    is_dest_ip = is_destination_ip(raw_target)
    if is_dest_ip:
        domain = canonical_destination_ip(raw_target)
    else:
        domain = normalize(raw_target)
        if not validate_domain(domain):
            respond(f"❌ Invalid domain: {domain}")
            return

    target_label = "Destination IP" if is_dest_ip else "Domain"
    summary = f"[ALLOW] {ip} → {domain} ({time_text}) — @{command['user_name']}"
    description = (
        f"Proxy Change Request\n\n"
        f"Command:       /allow\n"
        f"Client IP:     {ip}\n"
        f"{target_label}: {domain}\n"
        f"Duration:      {time_text}\n"
        f"Requester:     {command['user_name']} ({command['user_id']})\n"
        f"Requested at:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
    )
    summary_text = (
        f"*Command:* `/allow`\n"
        f"*Client IP:* `{ip}`\n"
        f"*{target_label}:* `{domain}`\n"
        f"*Duration:* {time_text}"
    )
    cmd_args = {
        "ip": ip, "domain": domain,
        "is_dest_ip": is_dest_ip,
        "expiry_timestamp": expiry_timestamp,
        "time_text": time_text
    }

    jira_key, err = _submit_ticket(
        "allow", summary, description, cmd_args,
        command["user_id"], command["user_name"], command["channel_id"],
        summary_text
    )
    if err:
        respond(f"❌ Failed to create Jira ticket: {err}")
        return

    jira_url = f"{JIRA_BASE_URL}/browse/{jira_key}"
    respond(
        f"🎫 *Request submitted — {jira_key}*\n"
        f"• Client IP: `{ip}`\n"
        f"• {target_label}: `{domain}`\n"
        f"• Duration: {time_text}\n"
        f"• Status: ⏳ Awaiting admin approval\n"
        f"🔗 {jira_url}"
    )


# ------------------------------------------------
# DENY
# ------------------------------------------------

@app.command("/deny")
def deny_cmd(ack, respond, command):
    ack()
    args = command["text"].split()

    if len(args) != 2:
        respond("Usage: `/deny <client_ip> <domain|destination_ip>`")
        return

    ip, raw_target = args

    if not validate_ip(ip):
        respond(f"❌ Invalid IP: {ip}")
        return

    domain = (
        canonical_destination_ip(raw_target)
        if is_destination_ip(raw_target)
        else normalize(raw_target)
    )

    target_label = "Destination IP" if validate_ip(domain) else "Domain"
    summary = f"[DENY] {ip} → {domain} — @{command['user_name']}"
    description = (
        f"Proxy Change Request\n\n"
        f"Command:       /deny\n"
        f"Client IP:     {ip}\n"
        f"{target_label}: {domain}\n"
        f"Requester:     {command['user_name']} ({command['user_id']})\n"
        f"Requested at:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
    )
    summary_text = (
        f"*Command:* `/deny`\n"
        f"*Client IP:* `{ip}`\n"
        f"*{target_label}:* `{domain}`"
    )
    cmd_args = {"ip": ip, "domain": domain}

    jira_key, err = _submit_ticket(
        "deny", summary, description, cmd_args,
        command["user_id"], command["user_name"], command["channel_id"],
        summary_text
    )
    if err:
        respond(f"❌ Failed to create Jira ticket: {err}")
        return

    jira_url = f"{JIRA_BASE_URL}/browse/{jira_key}"
    respond(
        f"🎫 *Request submitted — {jira_key}*\n"
        f"• Client IP: `{ip}`\n"
        f"• {target_label}: `{domain}`\n"
        f"• Status: ⏳ Awaiting admin approval\n"
        f"🔗 {jira_url}"
    )


# ------------------------------------------------
# EXTEND
# ------------------------------------------------

@app.command("/extend")
def extend_cmd(ack, respond, command):
    ack()
    args = command["text"].split()

    if len(args) != 3:
        respond("Usage: `/extend <client_ip> <domain|destination_ip> <Nh>`")
        return

    ip, raw_target, time_str = args

    if not validate_ip(ip):
        respond(f"❌ Invalid IP: {ip}")
        return

    domain = (
        canonical_destination_ip(raw_target)
        if is_destination_ip(raw_target)
        else normalize(raw_target)
    )

    try:
        hours = float(time_str[:-1])
        if not time_str.endswith("h") or hours <= 0:
            raise ValueError
    except ValueError:
        respond("❌ Time must be like `1h`, `1.5h`, `24h`")
        return

    target_label = "Destination IP" if validate_ip(domain) else "Domain"
    summary = f"[EXTEND] {ip} → {domain} (+{hours}h) — @{command['user_name']}"
    description = (
        f"Proxy Change Request\n\n"
        f"Command:       /extend\n"
        f"Client IP:     {ip}\n"
        f"{target_label}: {domain}\n"
        f"Extension:     {hours}h\n"
        f"Requester:     {command['user_name']} ({command['user_id']})\n"
        f"Requested at:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
    )
    summary_text = (
        f"*Command:* `/extend`\n"
        f"*Client IP:* `{ip}`\n"
        f"*{target_label}:* `{domain}`\n"
        f"*Extension:* `{hours}h`"
    )
    cmd_args = {"ip": ip, "domain": domain, "hours": hours}

    jira_key, err = _submit_ticket(
        "extend", summary, description, cmd_args,
        command["user_id"], command["user_name"], command["channel_id"],
        summary_text
    )
    if err:
        respond(f"❌ Failed to create Jira ticket: {err}")
        return

    jira_url = f"{JIRA_BASE_URL}/browse/{jira_key}"
    respond(
        f"🎫 *Request submitted — {jira_key}*\n"
        f"• Client IP: `{ip}`\n"
        f"• {target_label}: `{domain}`\n"
        f"• Extension: `{hours}h`\n"
        f"• Status: ⏳ Awaiting admin approval\n"
        f"🔗 {jira_url}"
    )


# ------------------------------------------------
# FULL NET
# ------------------------------------------------

@app.command("/full-net")
def fullnet_cmd(ack, respond, command):
    ack()
    ip = command["text"].strip()
    if not validate_ip(ip):
        respond("❌ Invalid IP")
        return

    summary = f"[FULL-NET] {ip} — unrestricted access — @{command['user_name']}"
    description = (
        f"Proxy Change Request\n\n"
        f"Command:       /full-net\n"
        f"Client IP:     {ip}\n"
        f"Effect:        Grants unrestricted internet access\n"
        f"Requester:     {command['user_name']} ({command['user_id']})\n"
        f"Requested at:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
    )
    summary_text = (
        f"*Command:* `/full-net`\n"
        f"*Client IP:* `{ip}`\n"
        f"*Effect:* 🔓 Unrestricted internet access"
    )
    cmd_args = {"ip": ip}

    jira_key, err = _submit_ticket(
        "full-net", summary, description, cmd_args,
        command["user_id"], command["user_name"], command["channel_id"],
        summary_text
    )
    if err:
        respond(f"❌ Failed to create Jira ticket: {err}")
        return

    jira_url = f"{JIRA_BASE_URL}/browse/{jira_key}"
    respond(
        f"🎫 *Request submitted — {jira_key}*\n"
        f"• Client IP: `{ip}`\n"
        f"• Effect: 🔓 Full internet access\n"
        f"• Status: ⏳ Awaiting admin approval\n"
        f"🔗 {jira_url}"
    )


# ------------------------------------------------
# LOCK NET
# ------------------------------------------------

@app.command("/lock-net")
def locknet_cmd(ack, respond, command):
    ack()
    ip = command["text"].strip()
    if not validate_ip(ip):
        respond("❌ Invalid IP")
        return

    summary = f"[LOCK-NET] {ip} — restore restrictions — @{command['user_name']}"
    description = (
        f"Proxy Change Request\n\n"
        f"Command:       /lock-net\n"
        f"Client IP:     {ip}\n"
        f"Effect:        Revokes full-net access, restores normal restrictions\n"
        f"Requester:     {command['user_name']} ({command['user_id']})\n"
        f"Requested at:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
    )
    summary_text = (
        f"*Command:* `/lock-net`\n"
        f"*Client IP:* `{ip}`\n"
        f"*Effect:* 🔒 Restore normal restrictions"
    )
    cmd_args = {"ip": ip}

    jira_key, err = _submit_ticket(
        "lock-net", summary, description, cmd_args,
        command["user_id"], command["user_name"], command["channel_id"],
        summary_text
    )
    if err:
        respond(f"❌ Failed to create Jira ticket: {err}")
        return

    jira_url = f"{JIRA_BASE_URL}/browse/{jira_key}"
    respond(
        f"🎫 *Request submitted — {jira_key}*\n"
        f"• Client IP: `{ip}`\n"
        f"• Effect: 🔒 Restore restrictions\n"
        f"• Status: ⏳ Awaiting admin approval\n"
        f"🔗 {jira_url}"
    )


# ------------------------------------------------
# LIST  (read-only — instant, no ticket needed)
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
        domain  = rule["domain"]
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
# APPROVAL ACTION HANDLERS
# ------------------------------------------------

@app.action("squid_approve")
def handle_approve(ack, body, client):
    ack()
    actor_id   = body["user"]["id"]
    actor_name = body["user"].get("name", actor_id)

    if not is_admin(actor_id):
        try:
            client.chat_postEphemeral(
                channel=body["channel"]["id"],
                user=actor_id,
                text="⛔ You are not authorized to approve proxy requests."
            )
        except Exception as e:
            log.error(f"handle_approve: ephemeral error: {e}")
        return

    jira_key = body["actions"][0]["value"]

    # Claim the request atomically
    with pending_lock:
        pending = load_pending()
        entry   = pending.get(jira_key)

        if not entry:
            try:
                client.chat_postEphemeral(
                    channel=body["channel"]["id"],
                    user=actor_id,
                    text=f"⚠️ Request `{jira_key}` not found. It may have already been processed."
                )
            except Exception:
                pass
            return

        if entry["status"] != "pending":
            try:
                client.chat_postEphemeral(
                    channel=body["channel"]["id"],
                    user=actor_id,
                    text=f"⚠️ `{jira_key}` has already been *{entry['status']}*."
                )
            except Exception:
                pass
            return

        entry["status"] = "approved"
        pending[jira_key] = entry
        save_pending(pending)

    # Update the approval card immediately
    _update_approval_card(
        client, entry,
        f"✅ *{jira_key}* approved by *{actor_name}* — executing...",
        actor_name
    )

    # Execute the proxy change in a background thread
    threading.Thread(
        target=execute_proxy_change,
        args=(entry, actor_id, actor_name),
        daemon=True
    ).start()


@app.action("squid_reject")
def handle_reject(ack, body, client):
    ack()
    actor_id   = body["user"]["id"]
    actor_name = body["user"].get("name", actor_id)

    if not is_admin(actor_id):
        try:
            client.chat_postEphemeral(
                channel=body["channel"]["id"],
                user=actor_id,
                text="⛔ You are not authorized to reject proxy requests."
            )
        except Exception as e:
            log.error(f"handle_reject: ephemeral error: {e}")
        return

    jira_key = body["actions"][0]["value"]

    # Claim the request atomically
    with pending_lock:
        pending = load_pending()
        entry   = pending.get(jira_key)

        if not entry:
            try:
                client.chat_postEphemeral(
                    channel=body["channel"]["id"],
                    user=actor_id,
                    text=f"⚠️ Request `{jira_key}` not found."
                )
            except Exception:
                pass
            return

        if entry["status"] != "pending":
            try:
                client.chat_postEphemeral(
                    channel=body["channel"]["id"],
                    user=actor_id,
                    text=f"⚠️ `{jira_key}` has already been *{entry['status']}*."
                )
            except Exception:
                pass
            return

        entry["status"] = "rejected"
        pending[jira_key] = entry
        save_pending(pending)

    # Update the approval card
    _update_approval_card(
        client, entry,
        f"❌ *{jira_key}* rejected by *{actor_name}*",
        actor_name
    )

    # Notify requester
    requester_channel = entry.get("requester_channel")
    if requester_channel:
        try:
            jira_url = f"{JIRA_BASE_URL}/browse/{jira_key}"
            client.chat_postMessage(
                channel=requester_channel,
                text=(
                    f"❌ *Your request was rejected — {jira_key}*\n"
                    f"• Rejected by: <@{actor_id}>\n"
                    f"🔗 {jira_url}"
                )
            )
            audit_log(f"❌ *[Ticket {jira_key}] Rejected*\n• Rejected by <@{actor_id}>")
        except Exception as e:
            log.error(f"handle_reject: failed to notify requester: {e}")

    # Close Jira ticket: Rejected
    # jira_transition_ticket tries 'Rejected' → "Won't Do" → 'Cancelled' → 'Done'
    def _close():
        jira_transition_ticket(jira_key, "Rejected")
        _jira_update_labels(jira_key, add_labels=["rejected"], remove_labels=["pending-approval"])
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        jira_add_comment(jira_key, f"REJECTED — by {actor_name} at {timestamp}")

    threading.Thread(target=_close, daemon=True).start()


@app.action("jira_link_button")
def handle_jira_link(ack, body):
    """No-op handler — the Jira button uses a URL action, but Slack still sends an interaction payload."""
    ack()


# ------------------------------------------------
# SQUID MONITOR WORKER
# ------------------------------------------------

def squid_monitor_worker():
    if not SLACK_ALERT_CHANNEL:
        log.warning("SLACK_ALERT_CHANNEL not set. Squid crash alerts disabled.")
        return

    squid_was_down = False

    while True:
        try:
            result    = subprocess.run(["systemctl", "is-active", "squid"], capture_output=True, text=True)
            is_active = result.stdout.strip() == "active"
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            if not is_active and not squid_was_down:
                squid_was_down = True
                log.error("Squid status monitor: Squid is offline!")
                try:
                    app.client.chat_postMessage(
                        channel=SLACK_ALERT_CHANNEL,
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
                        channel=SLACK_ALERT_CHANNEL,
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
    rebuild_override_configs()
    reload_squid()

    threading.Thread(target=expiry_worker,       daemon=True).start()
    threading.Thread(target=squid_monitor_worker, daemon=True).start()

    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    print("🚀 Slack Squid Bot is active — Jira ticketing enabled.")
    handler.start()