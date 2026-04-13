# Deployment Guide

This document covers the server-side environment setup, installation, and deployment of the Slack Squid Proxy Automation bot.

## Prerequisites

1. **Squid Proxy Manager:** `squid` must be actively installed and operating on the target machine.
2. **Python Environment:** Python 3.x and `pip` required.
3. **Slack App:** You need a Slack App configured with Socket Mode ON. You will need:
   - `SLACK_APP_TOKEN` (starts with `xapp-`)
   - `SLACK_BOT_TOKEN` (starts with `xoxb-`)

## 1. Directory Scaffolding

The python bot needs to manage and manipulate specific ACL file locations that are piped into your core `squid.conf`. Let's set up the target directories if they aren't already explicitly configured by your server structure:

```bash
sudo mkdir -p /etc/squid/conf.d/fullnet
sudo mkdir -p /etc/squid/lists/groups
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
nano .env # Add your Slack Tokens here

# Install required packages
pip install -r requirements.txt

# Install the Chromium headless browser required for deep-scanning dependencies
playwright install chromium
playwright install-deps
```

## 3. Permissions Setup

The bot runs as **root** under systemd. This is required because the VM enforces a kernel-level `no_new_privs` flag that permanently blocks `sudo` (which relies on the `setuid` bit to escalate privileges). Running as root avoids the escalation entirely.

> **Security note:** Root access is scoped down by the systemd unit's `ProtectSystem=strict` and `ReadWritePaths` directives, which prevent the bot from writing anywhere outside of `/etc/squid`. No additional sudoers configuration or `chown` is needed.

No further permission setup is required. Skip to Section 4.


## 4. Systemd Scheduling

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
