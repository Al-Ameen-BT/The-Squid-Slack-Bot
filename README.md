# Slack Squid Proxy Automation

A ChatOps and automation tool for dynamically managing Squid Proxy Access Control Lists (ACLs) directly from Slack.

## Features

- **Dynamic Whitelisting:** Use Slack to allow specific local IP addresses to access targeted domains on the fly.
- **Deep Dependency Scanning:** When a domain is whitelisted, an invisible Playwright Chromium browser loads the site in the background, extracts all CDNs, third-party API hosts, and implicit redirect architectures, and adds them to the whitelist automatically. This ensures complex modern websites load perfectly on the first try without grueling manual log inspections.
- **Expiry Management:** Whitelisting is issued with optional strict expiration times (e.g., `1h`, `24h`), tracked via a background worker thread. Access auto-revokes once the time window expires.
- **Full Net Overrides:** Grant or strip total unfiltered internet access to priority hosts with a single click.
- **Secure Architecture:** Operates over Slack's secure Socket Mode meaning no webhooks or inbound public ports need to be exposed. Config file rebuilds and service hot-reloads are safeguarded using execution locks to prevent corruption under heavy concurrent use by multiple administrators.
- **Enterprise Approval Workflow:** Every access request automatically generates a tracked Jira ticket and posts an interactive Block Kit approval card to a dedicated admin channel.
- **Dynamic Slack UI:** Administrators see real-time state transitions and live progress bars (`[⬛⬛⬛⬜⬜]`) directly in Slack as the bot executes commands in the background.
- **Plugin-Style Overrides:** Easily support complex relay-based applications (like UltraViewer or TeamViewer) by dropping their domain/IP lists into a `/special_apps/` folder, which the bot automatically detects and provisions.
## Slack Commands

- `/allow <ip> <domain> [time]` - Grant domain access to an IP. Example time: `1h`, `1.5h`, `24h` (default: indefinitely).
- `/deny <ip> <domain>` - Instantly revoke access to a domain for a specific IP.
- `/extend <ip> <domain> <time>` - Extend the life of an existing domain whitelisting.
- `/list <ip>` - View all current actively whitelisted domains for an IP alongside their countdown to expiry.
- `/full-net <ip>` - Grant total unfiltered upstream internet allowance for an IP.
- `/lock-net <ip>` - Revoke any previously granted full-net status.

## Documentation

- Check [DEPLOYMENT.md](DEPLOYMENT.md) for server preparations, python environments, systemd scheduling, and architectural setup.
