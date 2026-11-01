"""
Core data models shared across the scanner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class Finding:
    """A single issue discovered during a scan."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    check: str = ""                # e.g. "missing_security_header"
    title: str = ""                # human readable title
    severity: Severity = Severity.INFO
    description: str = ""          # what was found
    evidence: str = ""             # raw evidence (header value, response snippet, etc.)
    url: str = ""                  # specific URL/endpoint where found
    remediation: str = ""          # concrete fix
    references: list[str] = field(default_factory=list)
    source: str = "passive"        # "passive" | "nuclei" | "active"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "check": self.check,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "url": self.url,
            "remediation": self.remediation,
            "references": self.references,
            "source": self.source,
        }


@dataclass
class ScanResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: str = ""
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    finished_at: Optional[str] = None
    status: str = "running"        # running | completed | failed
    error: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "error": self.error,
            "summary": self.severity_summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def severity_summary(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
            reverse=True,
        )
