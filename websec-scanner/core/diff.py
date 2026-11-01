"""
Scan diffing: compare a scan's findings against the previous scan for the
same hostname, classifying each finding as new, resolved, or persisting.

Findings are matched by (check, url) -- the same check firing on the same
URL across two scans is treated as "the same issue still there", not a new
one, even if wording in description changed slightly.
"""
from __future__ import annotations


def _key(finding: dict) -> tuple[str, str]:
    return (finding.get("check", ""), finding.get("url", ""))


def diff_scans(current: dict, previous: dict | None) -> dict:
    """Returns {"new": [...], "resolved": [...], "persisting": [...]}"""
    current_findings = current.get("findings", [])
    if previous is None:
        return {
            "new": current_findings,
            "resolved": [],
            "persisting": [],
            "has_baseline": False,
        }

    previous_findings = previous.get("findings", [])
    current_keys = {_key(f): f for f in current_findings}
    previous_keys = {_key(f): f for f in previous_findings}

    new = [f for k, f in current_keys.items() if k not in previous_keys]
    resolved = [f for k, f in previous_keys.items() if k not in current_keys]
    persisting = [f for k, f in current_keys.items() if k in previous_keys]

    return {
        "new": new,
        "resolved": resolved,
        "persisting": persisting,
        "has_baseline": True,
        "previous_scan_id": previous.get("id"),
        "previous_started_at": previous.get("started_at"),
    }


def severity_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)


def has_notable_new_findings(diff: dict, min_severity: str = "high") -> bool:
    threshold = severity_rank(min_severity)
    return any(severity_rank(f.get("severity", "info")) >= threshold for f in diff.get("new", []))
