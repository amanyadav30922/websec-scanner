"""
Email alerting.

Pluggable SMTP config stored in the alert_config DB table (settable from
the dashboard, or pre-filled via environment variables on first run). If
SMTP isn't configured yet, alerts are logged to the console instead of
failing -- so the rest of the app works fine before you've set up email.

Alerts fire on:
  - scan failures (if alert_on_scan_failure)
  - any new finding (if alert_on_any_new_finding)
  - new critical/high findings specifically get called out distinctly in
    the email body even when "any new finding" is what triggered it
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.mime.text import MIMEText

from core import db
from core.diff import severity_rank


def bootstrap_from_env() -> None:
    """On first run, seed SMTP config from environment variables if the DB
    config is still empty. Lets you configure via .env instead of the UI."""
    cfg = db.get_alert_config()
    if cfg.get("smtp_host"):
        return  # already configured
    env_host = os.environ.get("WEBSEC_SMTP_HOST")
    if not env_host:
        return
    db.update_alert_config(
        smtp_host=env_host,
        smtp_port=int(os.environ.get("WEBSEC_SMTP_PORT", "587")),
        smtp_user=os.environ.get("WEBSEC_SMTP_USER"),
        smtp_password=os.environ.get("WEBSEC_SMTP_PASSWORD"),
        from_addr=os.environ.get("WEBSEC_ALERT_FROM"),
        to_addr=os.environ.get("WEBSEC_ALERT_TO"),
    )


def _is_configured(cfg: dict) -> bool:
    return bool(cfg.get("smtp_host") and cfg.get("from_addr") and cfg.get("to_addr"))


def _send(subject: str, body: str) -> tuple[bool, str]:
    cfg = db.get_alert_config()
    if not _is_configured(cfg):
        print(f"[alert:unconfigured] {subject}\n{body}\n")
        return False, "SMTP not configured; alert logged to console instead."

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = cfg["from_addr"]
    msg["To"] = cfg["to_addr"]

    try:
        if cfg.get("use_tls", 1):
            context = ssl.create_default_context()
            with smtplib.SMTP(cfg["smtp_host"], cfg.get("smtp_port") or 587, timeout=15) as server:
                server.starttls(context=context)
                if cfg.get("smtp_user"):
                    server.login(cfg["smtp_user"], cfg.get("smtp_password") or "")
                server.sendmail(cfg["from_addr"], [cfg["to_addr"]], msg.as_string())
        else:
            with smtplib.SMTP(cfg["smtp_host"], cfg.get("smtp_port") or 25, timeout=15) as server:
                if cfg.get("smtp_user"):
                    server.login(cfg["smtp_user"], cfg.get("smtp_password") or "")
                server.sendmail(cfg["from_addr"], [cfg["to_addr"]], msg.as_string())
        return True, "sent"
    except Exception as e:
        print(f"[alert:send_failed] {subject}: {e}")
        return False, str(e)


def notify_scan_failure(scan: dict) -> None:
    cfg = db.get_alert_config()
    if not cfg.get("alert_on_scan_failure", 1):
        return
    subject = f"[WebSec Scanner] Scan failed: {scan.get('target')}"
    body = (
        f"Scan of {scan.get('target')} failed.\n\n"
        f"Error: {scan.get('error')}\n"
        f"Scan ID: {scan.get('id')}\n"
        f"Started: {scan.get('started_at')}\n"
    )
    _send(subject, body)


def notify_diff(scan: dict, diff: dict) -> None:
    cfg = db.get_alert_config()
    new_findings = diff.get("new", [])
    if not new_findings:
        return

    crit_high = [f for f in new_findings if severity_rank(f["severity"]) >= severity_rank("high")]

    should_alert = False
    if cfg.get("alert_on_any_new_finding", 1):
        should_alert = True
    elif cfg.get("alert_on_new_critical_high", 1) and crit_high:
        should_alert = True

    if not should_alert:
        return

    target = scan.get("target")
    subject = (
        f"[WebSec Scanner] {len(crit_high)} new critical/high finding(s) on {target}"
        if crit_high else
        f"[WebSec Scanner] {len(new_findings)} new finding(s) on {target}"
    )

    lines = [f"New findings on {target} (scan {scan.get('id')}):\n"]
    if crit_high:
        lines.append("CRITICAL/HIGH:")
        for f in crit_high:
            lines.append(f"  - [{f['severity'].upper()}] {f['title']} -- {f.get('url', '')}")
        lines.append("")
    others = [f for f in new_findings if f not in crit_high]
    if others:
        lines.append("Other new findings:")
        for f in others:
            lines.append(f"  - [{f['severity'].upper()}] {f['title']} -- {f.get('url', '')}")
    lines.append(f"\nFull report: see dashboard, scan ID {scan.get('id')}")

    _send(subject, "\n".join(lines))


def send_test_alert() -> tuple[bool, str]:
    return _send(
        "[WebSec Scanner] Test alert",
        "This is a test alert from WebSec Scanner. If you received this, "
        "email alerting is configured correctly.",
    )
