# WebSec Scanner

An on-demand security scanning dashboard for **your own websites**. Enter a
domain, click scan, get a findings report with concrete remediation steps
for each issue. Supports recurring scheduled scans, change-tracking between
scans, subdomain discovery, email alerts on new issues, and multi-user
login so you can share access with people you trust.

**Want to put this on the internet so you can use it from anywhere, and
share logins with others?** See `DEPLOY.md` for step-by-step instructions
(Windows-friendly, no command line required) to host it for free on Render.

## What it checks today

**Passive checks (always run, no payloads sent):**
- Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Server/version info disclosure headers (Server, X-Powered-By, etc.)
- Cookie flags (Secure, HttpOnly, SameSite)
- TLS: expired/expiring certificates, outdated protocol versions (TLS 1.0/1.1/SSL), plain-HTTP targets
- Exposed sensitive files (.env, .git/config, backup files, phpinfo.php, .DS_Store, server-status, etc.)
- CORS misconfigurations (wildcard + credentials, origin reflection)

**Optional active checks:**
- [Nuclei](https://github.com/projectdiscovery/nuclei) integration — thousands of community-maintained templates for known CVEs and misconfigs. Runs automatically if `nuclei` is installed and on your PATH; otherwise skipped silently.

Every finding comes with a severity (info/low/medium/high/critical) and a
specific remediation.

## Feature overview

- **On-demand dashboard** — add domains, scan on demand, browse history
- **Scan diffing** — each scan is compared against the previous one for the
  same target; the dashboard shows New / Persisting / Resolved findings so
  you can see what actually changed
- **Subdomain discovery** — pulls subdomains from certificate transparency
  logs (crt.sh), a purely passive lookup against public records, not your
  server. Discovered subdomains of a confirmed domain can be scanned too.
- **Scheduled recurring scans** — set an interval per domain; runs in the
  background via an in-process scheduler while the app is running
- **Email alerts** — on scan failures and on new findings (new critical/high
  issues are always called out distinctly in the email body, regardless of
  which trigger fired)
- **SQLite storage** — all domains, scans, findings, schedules, and subdomain
  data live in one local file (`data/websec.db`), no server/DB setup needed

## Why there's a domain allowlist

You can only scan a domain after explicitly adding it and checking "I own /
am authorized to test this." Subdomains discovered for a confirmed domain
inherit that confirmation automatically; a brand new domain always needs its
own explicit confirmation. This is the right foundation if you ever extend
this beyond your own sites (client work, bug bounty, etc.), where proof of
authorization is a hard requirement anyway — built in now so there's no
rework later.

## Login

The dashboard is behind a login screen. On first run, if no users exist
yet, an admin account is created automatically:
- If `WEBSEC_ADMIN_USERNAME` / `WEBSEC_ADMIN_PASSWORD` env vars are set,
  those become the admin login.
- Otherwise a random password is generated and printed once to the server
  console — easy to miss, so setting the env vars yourself is simpler.

Once logged in as admin, use the **Users** tab to create logins for anyone
else who should have access (regular users can run scans, manage domains,
schedules, and alerts, but can't manage other users). Each person's own
password can be changed from the **Account** tab.

## Setup

```bash
cd websec-scanner
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Optional: install Nuclei for CVE/template scanning

```bash
# macOS
brew install nuclei

# Linux (via Go)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download a prebuilt binary:
# https://github.com/projectdiscovery/nuclei/releases
```

After installing, update templates once: `nuclei -update-templates`

If nuclei isn't installed, the dashboard just runs passive checks only.

### Optional: pre-configure email alerts via environment variables

Instead of filling in the Alerts tab in the UI, you can set these before
first run (only used if no config exists yet in the DB):

```bash
export WEBSEC_SMTP_HOST=smtp.gmail.com
export WEBSEC_SMTP_PORT=587
export WEBSEC_SMTP_USER=you@example.com
export WEBSEC_SMTP_PASSWORD=your_app_password
export WEBSEC_ALERT_FROM=you@example.com
export WEBSEC_ALERT_TO=you@example.com
```

For Gmail, use an [App Password](https://myaccount.google.com/apppasswords),
not your real password. Any SMTP provider works (SendGrid, Mailgun, your
own mail server, etc.) — just point `smtp_host`/`smtp_port` at it.

## Running

```bash
uvicorn dashboard.app:app --reload --port 8787
```

Open **http://127.0.0.1:8787**.

### Scan tab
1. Add a domain under "Verified Domains," check the ownership confirmation box.
2. Optionally click "Discover Subdomains" to pull in subdomains from certificate transparency logs.
3. Enter the domain (or click "Use" on a saved one) in "Run Scan," optionally include subdomains, click **Scan Now**.
4. Results show severity badges and fix instructions. After the first scan of a target, later scans show **New / Persisting / Resolved** filter tabs so you can see exactly what changed.

### Schedules tab
Set a domain + interval (minutes) to have it scanned automatically while the
app keeps running. "Run Now" triggers an off-cycle scan immediately;
"Pause"/"Resume" toggles without losing the schedule; "Delete" removes it.

> Scheduling here is **in-process** — it only runs while this app/server
> process is alive. For scans that need to happen even when the app isn't
> running, use system cron (Linux/macOS) or Task Scheduler (Windows) to call
> `POST /api/scan` on a timer instead — the API works the same either way.

### Alerts tab
Configure SMTP, pick which events should email you, and send a test alert
to confirm it's wired up correctly. If SMTP isn't configured, alerts are
just logged to the server console instead of failing.

## Project layout

```
websec-scanner/
  core/
    models.py            # Finding / ScanResult data classes
    db.py                 # SQLite layer: domains, scans, findings, schedules, alert config
    allowlist_compat.py    # shared domain-normalization helper
    orchestrator.py         # runs checks, persists results, computes diffs, fires alerts
    diff.py                   # new/resolved/persisting comparison logic
    alerts.py                  # SMTP email alerting
    scheduler.py                # APScheduler-backed recurring scans
  checks/
    headers.py            # security headers
    cookies.py              # cookie flags
    tls.py                    # cert/protocol checks
    exposure.py                 # sensitive file/path probing
    cors.py                       # CORS misconfig
    subdomains.py                  # crt.sh certificate transparency lookup
    nuclei.py                        # optional nuclei wrapper
  dashboard/
    app.py                 # FastAPI backend (all /api/* routes)
    templates/index.html     # single-page dashboard UI (Scan / Schedules / Alerts tabs)
  data/websec.db           # SQLite database (created on first run, gitignored)
```

## Extending it

Each check in `checks/` is a standalone async function that takes a
client/URL and returns a list of `Finding` objects — adding a new check
means adding a new file and wiring it into `core/orchestrator.py`'s
`run_scan()`. Natural next additions:
- Auth-aware scanning (crawl behind a login with a provided session cookie)
- Slack alerting alongside/instead of email (swap in a webhook call in `core/alerts.py`)
- A CLI entry point for system-cron-driven scans without the dashboard running
- A Rust rewrite of the concurrent request engine in `checks/` if you need
  much higher throughput later — the `Finding`/`ScanResult` schema and the
  FastAPI/dashboard/DB layers don't need to change, only the check runners
  would get swapped for calls into a Rust binary.

## A note on scope

This tool is built for scanning sites you own or are explicitly authorized
to test. The passive checks here (headers, exposed files, cookie flags, TLS
config, CORS, subdomain enumeration via public CT logs) are all read-only
GETs or public-record lookups — nothing here sends exploit payloads or
attempts to breach anything. Nuclei templates can include more active
probes; review which templates you're comfortable running, especially
before pointing this at production traffic.
