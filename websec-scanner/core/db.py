"""
SQLite storage layer.

Single local file (data/websec.db), no server required. Replaces the
earlier JSON-file-per-scan approach now that we're tracking many domains,
scan history, schedules, subdomains, and alert config together.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "websec.db"
_lock = Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username)
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS domains (
    domain TEXT PRIMARY KEY,
    confirmed INTEGER NOT NULL DEFAULT 0,
    label TEXT,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subdomains (
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    PRIMARY KEY (domain, subdomain)
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    hostname TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname, started_at);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    check_name TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    url TEXT,
    remediation TEXT,
    "references" TEXT,
    source TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    interval_minutes INTEGER NOT NULL,
    use_nuclei INTEGER NOT NULL DEFAULT 1,
    include_subdomains INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_run_at TEXT,
    last_scan_id TEXT
);

CREATE TABLE IF NOT EXISTS alert_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    smtp_host TEXT,
    smtp_port INTEGER DEFAULT 587,
    smtp_user TEXT,
    smtp_password TEXT,
    from_addr TEXT,
    to_addr TEXT,
    use_tls INTEGER DEFAULT 1,
    alert_on_new_critical_high INTEGER DEFAULT 1,
    alert_on_any_new_finding INTEGER DEFAULT 1,
    alert_on_scan_failure INTEGER DEFAULT 1
);
"""


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        conn.execute("INSERT OR IGNORE INTO alert_config (id) VALUES (1)")
        conn.commit()


@contextmanager
def get_conn():
    with _lock:
        conn = sqlite3.connect(str(DB_PATH), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()


# ---------- domains ----------

def add_domain(domain: str, confirmed: bool, label: str = "") -> dict:
    from datetime import datetime, timezone
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO domains (domain, confirmed, label, added_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(domain) DO UPDATE SET confirmed=excluded.confirmed, label=excluded.label""",
            (domain, int(confirmed), label or domain, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    return get_domain(domain)


def get_domain(domain: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM domains WHERE domain = ?", (domain,)).fetchone()
        return dict(row) if row else None


def remove_domain(domain: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM domains WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM subdomains WHERE domain = ?", (domain,))
        conn.commit()


def list_domains() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM domains ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]


def is_domain_confirmed(hostname: str) -> bool:
    """A hostname is allowed if it (or its parent domain) is confirmed."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT confirmed FROM domains WHERE domain = ?", (hostname,)
        ).fetchone()
        if row:
            return bool(row["confirmed"])
        # check if it's a known discovered subdomain of a confirmed parent
        parts = hostname.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            row = conn.execute(
                """SELECT d.confirmed FROM domains d
                   JOIN subdomains s ON s.domain = d.domain
                   WHERE d.domain = ? AND s.subdomain = ?""",
                (parent, hostname),
            ).fetchone()
            if row:
                return bool(row["confirmed"])
        return False


# ---------- subdomains ----------

def add_subdomains(domain: str, subdomains: list[str]) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.executemany(
            """INSERT OR IGNORE INTO subdomains (domain, subdomain, discovered_at)
               VALUES (?, ?, ?)""",
            [(domain, sd, now) for sd in subdomains],
        )
        conn.commit()


def list_subdomains(domain: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM subdomains WHERE domain = ? ORDER BY subdomain", (domain,)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- scans / findings ----------

def save_scan(scan) -> None:
    """scan: core.models.ScanResult"""
    from urllib.parse import urlparse
    hostname = urlparse(scan.target).hostname or scan.target
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scans (id, target, hostname, started_at, finished_at, status, error)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 finished_at=excluded.finished_at, status=excluded.status, error=excluded.error""",
            (scan.id, scan.target, hostname, scan.started_at, scan.finished_at,
             scan.status, scan.error),
        )
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan.id,))
        conn.executemany(
            """INSERT INTO findings
               (id, scan_id, check_name, title, severity, description, evidence, url,
                remediation, "references", source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (f.id, scan.id, f.check, f.title, f.severity.value, f.description,
                 f.evidence, f.url, f.remediation, json.dumps(f.references), f.source)
                for f in scan.findings
            ],
        )
        conn.commit()


def get_scan_dict(scan_id: str) -> dict | None:
    with get_conn() as conn:
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan_row:
            return None
        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    return _scan_to_dict(scan_row, finding_rows)


def list_scans(hostname: str | None = None, limit: int = 100) -> list[dict]:
    with get_conn() as conn:
        if hostname:
            rows = conn.execute(
                "SELECT * FROM scans WHERE hostname = ? ORDER BY started_at DESC LIMIT ?",
                (hostname, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        results = []
        for row in rows:
            finding_rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ?", (row["id"],)
            ).fetchall()
            results.append(_scan_to_dict(row, finding_rows))
        return results


def get_previous_scan(hostname: str, before_scan_id: str) -> dict | None:
    """Most recent completed scan for this hostname, before the given scan."""
    with get_conn() as conn:
        current = conn.execute(
            "SELECT started_at FROM scans WHERE id = ?", (before_scan_id,)
        ).fetchone()
        if not current:
            return None
        row = conn.execute(
            """SELECT * FROM scans WHERE hostname = ? AND status = 'completed'
               AND started_at < ? ORDER BY started_at DESC LIMIT 1""",
            (hostname, current["started_at"]),
        ).fetchone()
        if not row:
            return None
        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (row["id"],)
        ).fetchall()
    return _scan_to_dict(row, finding_rows)


def _scan_to_dict(scan_row, finding_rows) -> dict:
    findings = []
    counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in finding_rows:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        findings.append({
            "id": f["id"],
            "check": f["check_name"],
            "title": f["title"],
            "severity": f["severity"],
            "description": f["description"],
            "evidence": f["evidence"],
            "url": f["url"],
            "remediation": f["remediation"],
            "references": json.loads(f["references"]) if f["references"] else [],
            "source": f["source"],
        })
    return {
        "id": scan_row["id"],
        "target": scan_row["target"],
        "hostname": scan_row["hostname"],
        "started_at": scan_row["started_at"],
        "finished_at": scan_row["finished_at"],
        "status": scan_row["status"],
        "error": scan_row["error"],
        "summary": counts,
        "findings": findings,
    }


# ---------- schedules ----------

def add_schedule(target: str, interval_minutes: int, use_nuclei: bool,
                  include_subdomains: bool) -> dict:
    import uuid
    from datetime import datetime, timezone
    sid = str(uuid.uuid4())[:8]
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO schedules
               (id, target, interval_minutes, use_nuclei, include_subdomains, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, 1, ?)""",
            (sid, target, interval_minutes, int(use_nuclei), int(include_subdomains),
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    return get_schedule(sid)


def get_schedule(schedule_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
        return dict(row) if row else None


def list_schedules() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def set_schedule_enabled(schedule_id: str, enabled: bool) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (int(enabled), schedule_id))
        conn.commit()


def delete_schedule(schedule_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        conn.commit()


def mark_schedule_run(schedule_id: str, scan_id: str) -> None:
    from datetime import datetime, timezone
    with get_conn() as conn:
        conn.execute(
            "UPDATE schedules SET last_run_at = ?, last_scan_id = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), scan_id, schedule_id),
        )
        conn.commit()


# ---------- alert config ----------

def get_alert_config() -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM alert_config WHERE id = 1").fetchone()
        return dict(row) if row else {}


def update_alert_config(**kwargs) -> dict:
    allowed = {
        "smtp_host", "smtp_port", "smtp_user", "smtp_password", "from_addr",
        "to_addr", "use_tls", "alert_on_new_critical_high",
        "alert_on_any_new_finding", "alert_on_scan_failure",
    }
    fields = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not fields:
        return get_alert_config()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with get_conn() as conn:
        conn.execute(f"UPDATE alert_config SET {set_clause} WHERE id = 1", list(fields.values()))
        conn.commit()
    return get_alert_config()


# ---------- users ----------

def create_user(username: str, password_hash: str, is_admin: bool = False) -> None:
    from datetime import datetime, timezone
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, int(is_admin), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()


def get_user(username: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def list_users() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT username, is_admin, created_at FROM users ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in rows]


def count_users() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()
        return row["c"]


def delete_user(username: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        conn.commit()


def update_user_password(username: str, password_hash: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username)
        )
        conn.commit()


# ---------- sessions ----------

def create_session(token: str, username: str, ttl_hours: int = 24 * 14) -> None:
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=ttl_hours)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, username, now.isoformat(), expires.isoformat()),
        )
        conn.commit()


def get_session_user(token: str) -> dict | None:
    from datetime import datetime, timezone
    with get_conn() as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if not row:
            return None
        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return None
        user_row = conn.execute(
            "SELECT username, is_admin FROM users WHERE username = ?", (row["username"],)
        ).fetchone()
        return dict(user_row) if user_row else None


def delete_session(token: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
