# Sheep Feeds CLI

Command-line client for the **Sheep threat-intelligence feeds API** at
[sheep.byfranke.com](https://sheep.byfranke.com). Pulls curated feeds
(CVEs, ransomware victims, IOCs, APT infrastructure, ICS/SCADA
advisories, threat-intel articles) as JSON for use in SIEMs, SOAR
playbooks, scripts and ad-hoc terminal queries.

```
sheep-feeds list                      # list every feed with last update
sheep-feeds latest cve --count 20     # 20 most recent CVE entries
sheep-feeds get ransomware --since 2026-05-01 --json   # raw JSON
sheep-feeds stats cve                 # per-feed statistics
sheep-feeds summary                   # dashboard-style overview
sheep-feeds plan                      # show your plan, quota and active token

# Watch — local rules engine that pings you when feeds match
sheep-feeds watch add nginx-high --feed cve --contains nginx --severity high --notify desktop
sheep-feeds watch run --once          # one scan (cron / systemd timer)
sheep-feeds watch run                 # loop in the foreground / inside a service
```

---

## Why this exists

The same feeds the Sheep Discord bot broadcasts on `/feeds` and
`/blackfeeds` are also exposed as a REST API. This CLI wraps that API
so you can pipe the data straight into your tooling without writing a
client every time.

Sample uses we have shipped to customers:

- **SIEM ingest:** cron job that calls
  `sheep-feeds get cve --since "$LAST" --json | jq …` and pushes new
  rows into Wazuh / Splunk / Elastic.
- **SOAR playbooks:** workflow node (Tines, Shuffle, your own
  Python worker, etc.) that polls
  `sheep-feeds latest ransomware --count 50 --json` and filters by
  country/sector before paging the incident team.
- **Daily digest:** scheduled job (cron, Kubernetes CronJob, GitHub
  Actions on a schedule) that runs `sheep-feeds summary` and prints
  to a shared terminal in the SOC.
- **Spot-check from terminal:** `sheep-feeds get cve --severity high`
  to glance at the high-severity bucket before standup.

---

## Install

### Quick

```bash
curl -fsSL https://raw.githubusercontent.com/byfranke/sheep-feeds-cli/main/install.sh | bash
```

The installer clones the repo into `~/.sheep-feeds-cli`, installs
dependencies, drops a `sheep-feeds` symlink in `/usr/local/bin` (or
`~/.local/bin` if that's not writable), and runs the interactive setup
wizard.

### Manual

```bash
git clone https://github.com/byfranke/sheep-feeds-cli.git ~/.sheep-feeds-cli
cd ~/.sheep-feeds-cli
pip install -r requirements.txt
python3 setup.py
```

### Uninstall

```bash
~/.sheep-feeds-cli/uninstall.sh
```

---

## Configure

The setup wizard (`setup.py`) does three things:

1. Asks for your API token (starts with `shp_`).
2. Encrypts it with a master password (PBKDF2-HMAC-SHA256, 600k iters)
   in `~/.sheep-feeds-cli/config.ini` (mode 0600).
3. Optionally installs `sheep-feeds` system-wide.

You enter the master password **once per terminal session** — the CLI
caches the decrypted token in a per-session file under `/tmp/` (mode
0600, owner-only) so subsequent commands run without prompting.

### Token resolution order

```
$SHEEP_API_TOKEN  (env var, highest priority — useful for CI/CD)
system keyring     (when populated by setup.py and available)
encrypted config   (config.ini decrypted with master password)
--token <value>    (one-shot override, never persisted)
```

You **don't need** the CLI to use keyring — setup.py only stores the
encrypted blob in the config file by default. The keyring path is for
non-interactive workflows where typing a master password isn't viable.

### Where to get a token

- Sheep Plus / Sheep Pro / Sheep Pro Max — sign up at
  [sheep.byfranke.com/pages/store](https://sheep.byfranke.com/pages/store),
  token is emailed to you.
- Black Sheep gift card — redeem on Discord with `/token`.

---

## Commands

### `sheep-feeds list`
List every feed and its last-update timestamp.

### `sheep-feeds categories`
Group feeds by category.

### `sheep-feeds summary`
Compact, dashboard-style overview of all feeds with item counts and
status. Useful for cron-driven monitoring.

### `sheep-feeds get <feed_id>` *(workhorse)*
Pulls items from a single feed.

Options:

| Flag | Default | Notes |
|---|---|---|
| `--limit` | 50 | Max items per call (1-500). |
| `--offset` | 0 | Pagination offset. |
| `--last` | none | Time-window shortcut: `24h`, `3d`, `2w`, or aliases `today` / `yesterday` / `week` / `month`. Caps at 30 days (server retention). Mutually exclusive with `--since`. |
| `--since` | none | ISO-8601 timestamp; items strictly after this. Use `--last` instead when you don't need to-the-second precision. |
| `--severity` | none | Substring match (case-insensitive) on `severity`. |
| `--category` | none | Substring match on `category`. |
| `--json` | off | Print the raw API JSON instead of a table. |

Examples:

```bash
# Everything from the last 24 hours
sheep-feeds get cve --last 24h

# Three days of ransomware leaks, as JSON ready to pipe into jq
sheep-feeds get ransomware --last 3d --json | jq '.items[].title'

# Last week of high-severity advisories
sheep-feeds get cve --last week --severity high

# Page 3 of ICS advisories (no time window)
sheep-feeds get ics_scada --limit 25 --offset 50
```

### `sheep-feeds latest <feed_id>`
Shortcut for the N newest items. Combine with `--last` to bound the
search window before picking the freshest ones.

```bash
sheep-feeds latest cve --count 20
sheep-feeds latest ioc_stream --count 5 --last 24h --json
```

### `sheep-feeds stats <feed_id>`
Per-feed statistics (counts by severity / category / source).

### `sheep-feeds plan`
Show your plan, status, period-end date, current-period token usage
and any parallel tokens bound to the same email. Useful as a pre-flight
check before scheduling a heavy ingest. Add `--json` for machine-readable
output.

```bash
sheep-feeds plan
sheep-feeds plan --json | jq '.usage.tokens_remaining'
```

---

## Watch — local alerts when feeds match

Watch turns the CLI into a quiet sentinel: define rules against the
feeds you care about, leave the agent running, get a desktop or
webhook alert the moment something new matches.

Watch consumes **zero AI tokens** — it only reads the feeds (already
free on every paid plan) and applies your rules locally.

### Building rules

```bash
# CVEs that mention nginx, severity high
sheep-feeds watch add nginx-high --feed cve --contains nginx --severity high --notify desktop

# Anything ransomware-related from a specific actor, alert in Slack
sheep-feeds watch add lockbit-radar --feed ransomware --contains lockbit \
    --notify "https://hooks.slack.com/services/AAA/BBB/CCC"

# Critical items across every feed, two channels
sheep-feeds watch add crit-fanout --feed '*' --severity critical \
    --notify desktop \
    --notify "https://your-soar.example/sheep-hook"

# Regex on title + content
sheep-feeds watch add cisco-asa --feed cve --regex "cisco\\s+asa" --notify desktop
```

Rule fields:

| Flag | Behaviour |
|---|---|
| `--feed <id>` | One of `cve`, `ransomware`, `threat_intel`, `apt_infrastructure`, `data_leak`, `ics_scada`, `kaspersky`, `ioc_stream`, `rss_news`, or `*` for every feed. |
| `--severity` | One of `low`, `medium`, `high`, `critical`. Matched as case-insensitive substring against the item's severity. |
| `--category` | Case-insensitive substring on the item's category. |
| `--contains` | Case-insensitive substring on title + content. |
| `--regex` | Python regex on title + content. Compiled once; input is capped to keep worst-case backtracking bounded. |
| `--notify` | Repeat per channel. Values: `desktop` (libnotify / osascript / PowerShell BurntToast with a stderr fallback), or any `https://` webhook URL (POST JSON, 10s timeout, no retry). |

All match conditions on a rule are AND-ed. A rule with **none** of
the match filters is rejected (would fire on every item).

### Listing and managing

```bash
sheep-feeds watch list                       # table
sheep-feeds watch list --json                # machine-readable
sheep-feeds watch pause nginx-high           # disable without removing
sheep-feeds watch resume nginx-high
sheep-feeds watch remove nginx-high          # delete the rule
```

### Inspecting hits

```bash
sheep-feeds watch hits                       # last 24h
sheep-feeds watch hits --last 7d
sheep-feeds watch hits --rule nginx-high
sheep-feeds watch hits --json --limit 500    # SIEM ingest
```

Hits are deduplicated by `(rule, feed, item_id)` — the same item never
fires the same rule twice.

### Running the watcher

```bash
# One-shot scan (perfect for cron / systemd timer)
sheep-feeds watch run --once

# Foreground loop — polls every N seconds (default 900)
sheep-feeds watch run
sheep-feeds watch run --interval 600         # every 10 minutes
```

### systemd user unit (recommended)

Drop this in `~/.config/systemd/user/sheep-feeds-watch.service`:

```ini
[Unit]
Description=Sheep Feeds Watch
After=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/sheep-feeds watch run --interval 900
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now sheep-feeds-watch
systemctl --user status sheep-feeds-watch
journalctl --user -u sheep-feeds-watch -f
```

### cron alternative

```cron
*/15 * * * * /usr/local/bin/sheep-feeds watch run --once >> ~/.sheep-feeds-cli/watch/cron.log 2>&1
```

### Where things live

| Path | Content |
|---|---|
| `~/.sheep-feeds-cli/watch/rules.yml` | Your rules (mode 0600, editable by hand). |
| `~/.sheep-feeds-cli/watch/hits.db` | SQLite log of every fired hit (mode 0600). |
| `~/.sheep-feeds-cli/watch/state.json` | Per-feed cursor so each cycle only asks for new items. |

The watch directory is created on first use with mode 0700.

### Caps and defaults

- Max 50 rules per install (anti-DoS for the local agent).
- Per-cycle fetch: 100 items per feed.
- Interval: 60 s minimum, 6 h maximum (default 900 s = 15 min).
- Webhook timeout: 10 s, no retry — the next cycle re-tries naturally
  for items not yet acknowledged as hits.

---

## Maintenance

```bash
sheep-feeds --about        # Product info, links, features
sheep-feeds --version      # Print the installed version
sheep-feeds --init         # Create an empty config.ini with mode 0600
sheep-feeds --setup        # Re-run the interactive setup wizard
sheep-feeds --update       # git pull + pip upgrade
sheep-feeds --logout       # Clear the per-session decrypted-token cache
```

To completely wipe Watch state without touching your token:

```bash
rm -rf ~/.sheep-feeds-cli/watch/
```

`--logout` removes only the per-shell cache under `/tmp/`. The encrypted
config file under `~/.sheep-feeds-cli/` is untouched; the next call asks
for the master password again.

---

## Available feeds

| `feed_id` | Content | Category |
|---|---|---|
| `cve` | Critical vulnerabilities (NVD) | vulnerabilities |
| `ransomware` | Ransomware victims from leak sites | ransomware |
| `threat_intel` | APT reports, malware analysis | threat_intelligence |
| `apt_infrastructure` | C2 / malware infra | infrastructure |
| `data_leak` | Data breaches and dumps | data_breach |
| `ics_scada` | ICS/SCADA advisories | ics |
| `kaspersky` | Kaspersky SecureList posts | threat_intelligence |
| `ioc_stream` | Real-time stream of malicious IPs/URLs/hashes | iocs |
| `rss_news` | Aggregated security news from vendor RSS sources | news |

The server is authoritative — the CLI keeps a local allowlist as a
typo guard but will still call the API if you pass a feed it doesn't
recognise. Run `sheep-feeds list` for the canonical, server-side list.

---

## Output

### Human (default)

Rich-rendered tables and panels. Auto-truncates long fields to keep the
terminal readable. Caps at 30 items by default; use `--limit` and
`--json` for more.

### JSON (`--json`)

Raw API response, pretty-printed, ready to pipe into `jq`, redirect
to a file, or feed into a downstream tool. This is the integration
mode — use it from cron, your SOAR / SIEM, or any pipeline tool.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | API error (rate limit, network, server, validation) |
| 2 | CLI usage error (missing token, bad argument) |
| 130 | Interrupted (Ctrl-C) |

These are stable — automation can branch on them.

---

## Security model

- Token never appears in command-line arguments unless you use `--token`
  (and even then it's stripped from any error output).
- Server fields are scrubbed of ASCII control chars and Rich-markup
  metacharacters before rendering — a hostile API response cannot
  forge clickable links or rewrite your terminal.
- Config file is mode 0600; the wizard refuses to load a config with
  loose permissions (warns to `chmod 600`).
- Encrypted token uses PBKDF2-HMAC-SHA256 with 600k iterations
  (OWASP 2023 recommendation) and a random per-install salt.
- Per-session decrypted-token cache (`/tmp/sheep-feeds-cli-sess-<uid>-<sid>`)
  uses `O_NOFOLLOW` to defeat symlink-pointing pre-plant attacks.

---

## Privacy & legal

- **Privacy Policy:** https://sheep.byfranke.com/pages/privacy.html
- **Terms of Service:** https://sheep.byfranke.com/pages/terms.html
- **Support:** support@byfranke.com
- **License:** byFranke License (see `LICENSE`).

---

## Roadmap

- Streaming mode for long-lived integrations (Server-Sent Events).
- Output adapters for OpenIOC / STIX 2.1 / MISP.
- Per-feed schema-aware output (CVSS-coloured table for `cve`, country
  flag emoji for `ransomware`, etc).

Issues and feature requests: https://github.com/byfranke/sheep-feeds-cli/issues
