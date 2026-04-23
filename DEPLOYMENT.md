# Deployment Guide

This document covers the server-side environment setup, installation, and deployment of the Slack Squid Proxy Automation bot.

## Prerequisites

1. **Squid Proxy Manager:** `squid` must be actively installed and operating on the target machine.
2. **Python Environment:** Python 3.x and `pip` required.
3. **Slack App & Workspace:** You need a Slack App configured with Socket Mode ON. You will need:
   - `SLACK_APP_TOKEN` (starts with `xapp-`)
   - `SLACK_BOT_TOKEN` (starts with `xoxb-`)
   - Two dedicated channels: one for Admins to approve requests, one for system crash alerts.
4. **Jira Integration:** You must have a Jira Cloud instance with an active project, and generate an API Token for your bot user or service account.

## 1. Directory Scaffolding

The python bot needs to manage and manipulate specific ACL file locations that are piped into your core `squid.conf`. Let's set up the target directories if they aren't already explicitly configured by your server structure:

```bash
sudo mkdir -p /etc/squid/conf.d/fullnet
sudo mkdir -p /etc/squid/conf.d/override
sudo mkdir -p /etc/squid/lists/groups
sudo mkdir -p /etc/squid/special_apps
```

By default, the script looks for an external file `/etc/squid/cdn_domains.txt` to avoid blocking common global CDNs (e.g. Cloudflare, Akamai etc). Optional, but recommended.

## 2. Python Environment & Dependencies

It's highly recommended to deploy this within the designated directory:

```bash
sudo mkdir -p /opt/The-Squid-Slack-Bot
sudo cp -r ./* /opt/The-Squid-Slack-Bot/
cd /opt/The-Squid-Slack-Bot

# Set up configuration credentials
cp .env.example .env
nano .env 
```

Ensure your `.env` is fully populated with both Slack Tokens, Slack Admin User IDs, Slack Channel IDs, and Jira credentials:
- `SLACK_ADMIN_CHANNEL` and `SLACK_ALERT_CHANNEL`
- `SLACK_ADMIN_USER_IDS` (comma separated)
- `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, and `JIRA_PROJECT_KEY`

```bash
# Install required packages
pip install -r requirements.txt

# Install the Chromium headless browser required for deep-scanning dependencies
playwright install chromium
playwright install-deps
```

## 3. Persistent Data & Automation

The bot maintains its internal state via local JSON files within its installation directory:
- `domains.json`: Stores all currently active IP/Domain allow-lists and their computed expirations.
- `pending_requests.json`: Ensures Jira approval cards aren't lost if the bot is restarted.
- `filter_config.json`: Lets you configure blocked root domains dynamically.

These files are auto-generated when the bot starts, but require the bot to have write permissions in its own installation directory.

## 4. Permissions Setup

The bot runs as **root** under systemd. This is required because the VM enforces a kernel-level `no_new_privs` flag that permanently blocks `sudo` (which relies on the `setuid` bit to escalate privileges). Running as root avoids the escalation entirely.

> **Security note:** Root access is scoped down by the systemd unit's `ProtectSystem=strict` and `ReadWritePaths` directives, which prevent the bot from writing anywhere outside of `/etc/squid` and `/opt/The-Squid-Slack-Bot`. No additional sudoers configuration or `chown` is needed.

No further permission setup is required. Skip to Section 5.

## 5. Systemd Scheduling

Move the provided service file to systemd to keep the bot alive persistently, restart it on crashes, and hook startup to networking.

```bash
sudo cp slack-squid-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable slack-squid-proxy.service
sudo systemctl start slack-squid-proxy.service
```

### Checking Logs
Because standard stdout operations have been appropriately configured in the `.service` template, python `logging` dumps directly to the system journal:

```bash
sudo journalctl -u slack-squid-proxy.service -f
```
