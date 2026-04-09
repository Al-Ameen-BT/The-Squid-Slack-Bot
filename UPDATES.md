# UPDATES.md — Squid Slack Bot

> **Session Date:** 2026-04-09  
> **Updated By:** Antigravity AI  
> **Scope:** Bug fixes, security hardening, dependency filtering, audit logging

---

## v1.1.0 — 2026-04-09

---

### 🐛 Bug Fixes

#### 1. `/lock-net` — Deadlock Fixed
**File:** `bot.py`  
**Severity:** 🔴 Critical

`reload_squid()` was being called **inside** the `with lock:` block. Since `reload_squid()` also acquires the same non-reentrant `threading.Lock()` internally, every call to `/lock-net` would cause a **permanent deadlock**, freezing the bot.

**Fix:** Introduced a `did_disable` flag. All file operations happen inside the lock; `reload_squid()` is called after the lock is released.  
Also added the missing `validate_ip()` guard that was absent from this command.

---

#### 2. `/deny` — HTTP Call Inside Lock Fixed
**File:** `bot.py`  
**Severity:** 🔴 High

`respond()` (a Slack HTTP API call) was being made while holding `lock`, blocking the expiry worker and all other concurrent commands for the duration of the network round-trip.

**Fix:** Introduced a `not_found` boolean flag; all state decisions are made inside the lock, and `respond()` is called after the lock exits.

---

#### 3. `/extend` — HTTP Calls Inside Lock Fixed (×2)
**File:** `bot.py`  
**Severity:** 🔴 High

Two early-exit `respond()` calls (`"rule not found"` and `"no expiry"`) were inside the `with lock:` block — same issue as `/deny`.

**Fix:** Introduced a `result` string code (`"not_found"` / `"no_expiry"` / `"ok"`). The lock block only performs data operations; all three `respond()` calls happen after the lock is released.

---

#### 4. `save_domains()` — Atomic Write to Prevent JSON Corruption
**File:** `bot.py`  
**Severity:** 🟡 Medium

`open(DOMAINS_FILE, "w")` truncates the file immediately on open. If the bot was killed (SIGKILL, OOM, power loss) between the truncation and the write completing, `domains.json` would be left **empty or corrupt**, wiping all domain rules on next startup.

**Fix:** Now writes to a `.tmp` file first, then uses `os.replace()` which is **atomic on Linux** — the file is always either the old version or the new version, never corrupt.

```python
# Before
with open(DOMAINS_FILE, "w") as f:
    json.dump(data, f, indent=2)

# After
tmp = DOMAINS_FILE + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=2)
os.replace(tmp, DOMAINS_FILE)  # atomic
```

---

#### 5. `/list` — Three Sub-Issues Fixed
**File:** `bot.py`  
**Severity:** 🟡 Medium

| Sub-issue | Fix |
|-----------|-----|
| `load_domains()` called without the lock — risk of reading a half-written file | Wrapped in `with lock:` |
| Already-expired entries (within the 60s cleanup window) shown as active | Added `entry["expires"] > now` filter |
| No length guard — long domain lists could silently exceed Slack's ~4000 char limit | Truncates at 3800 chars with a visible `*(truncated)*` notice |

---

### 🔒 Security / Correctness

#### 6. Dependency Discovery — Noisy Domain Filtering
**File:** `bot.py`, `filter_config.json` (new)  
**Severity:** 🟡 Medium (functional regression)

The Playwright-based scanner was capturing **every network request** a webpage makes, including Facebook Like buttons, YouTube embeds, Google Analytics, ad scripts, and tracking pixels. This caused unrelated and potentially dangerous domains (e.g. `facebook.com`, `youtube.com`) to be automatically whitelisted in Squid ACLs.

**Three-layer fix applied:**

1. **Social/Ad Blocklist** — ~50 domains across social media, analytics, live chat widgets, and ad networks are hard-blocked during discovery regardless of how they appear on the scanned page.

2. **Resource Type Filter** — Only `script`, `fetch`, `xhr`, `document`, `websocket`, `eventsource` request types are counted as real dependencies. `image`, `media`, and `font` requests (tracking pixels, social share icons, video embeds) are ignored.

3. **YouTube CDNs removed from default CDN fallback** — `googlevideo.com` and `ytimg.com` were in the hardcoded CDN fallback list, causing any site with a YouTube embed to automatically whitelist them. Removed.

---

### ✨ New Features

#### 7. External Filter Config (`filter_config.json`)
**File:** `filter_config.json` (new), `bot.py`

The social/ad blocklist and functional resource types are now stored in an **external JSON file** instead of being hardcoded in `bot.py`.

- Edit `filter_config.json` to add or remove blocked domains
- **No bot restart required** — the config is loaded fresh on every `/allow` scan
- Organized into labeled categories: `social_media`, `analytics_and_tracking`, `live_chat_and_crm`, `ad_networks`
- Falls back to a safe built-in default set if the file is missing or malformed

**To add a new blocked domain:**
```json
"social_media": [
  "newsite.com"
]
```

---

#### 8. Dedicated Audit Log Channel (`SLACK_LOG_CHANNEL`)
**File:** `bot.py`, `.env.example`

All bot actions and Squid health events are now posted to a single dedicated Slack channel for traceability.

**Events logged:**

| Event | Tag |
|-------|-----|
| `/allow` success | `✅ [ALLOW]` |
| `/deny` success | `✅ [DENY]` |
| `/extend` success / skipped / not found | `✅ / ⚠️ [EXTEND]` |
| `/full-net` granted | `🔓 [FULL-NET]` |
| `/lock-net` applied | `🔒 [LOCK-NET]` |
| Squid went offline | `🚨 [SQUID-DOWN]` |
| Squid recovered | `✅ [SQUID-RECOVERY]` |

Each entry includes: **who** ran the command, **what** the parameters were, **when** it happened (UTC timestamp), and the **outcome**.

`SLACK_ALERT_CHANNEL` has been **removed** — crash alerts now go to `SLACK_LOG_CHANNEL` along with audit logs, consolidating all bot activity into one place.

**Setup:**
```env
# .env
SLACK_LOG_CHANNEL=C0XXXXXXXXX
```

> To retain 15 days of history: **Slack Admin → Policies → Message Retention → set channel to 15 days**  
> (Requires Slack Pro plan or higher)

---

### 📁 Files Changed

| File | Change |
|------|--------|
| `bot.py` | Deadlock fix, lock fixes (×2), atomic write, /list fixes, discovery filtering, audit logging |
| `filter_config.json` | **New** — external blocklist and resource type config |
| `.env.example` | Removed `SLACK_ALERT_CHANNEL`, added `SLACK_LOG_CHANNEL` |

---

### 🔧 Migration Notes

#### If upgrading from a previous version:

1. **Remove** `SLACK_ALERT_CHANNEL` from your `.env` file — it is no longer used.
2. **Add** `SLACK_LOG_CHANNEL=<your-channel-id>` to your `.env` file.
3. **Place** `filter_config.json` in the same directory as `bot.py` (it will be auto-created with defaults on first run if missing).
4. **Restart** the bot: `sudo systemctl restart slack-squid-proxy`

---
