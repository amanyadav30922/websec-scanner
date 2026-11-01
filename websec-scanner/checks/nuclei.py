"""
Optional Nuclei integration.

Nuclei (https://github.com/projectdiscovery/nuclei) is a mature, widely-used
open-source scanner with thousands of community-maintained templates for
known CVEs and misconfigurations. Rather than reinventing exploit logic,
this module shells out to it (if installed) and normalizes its JSON output
into our Finding schema. If nuclei isn't installed, this is skipped silently
and the caller is told so.
"""
from __future__ import annotations

import asyncio
import json
import shutil

from core.models import Finding, Severity

NUCLEI_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def is_available() -> bool:
    return shutil.which("nuclei") is not None


async def run(base_url: str, timeout: int = 120) -> list[Finding]:
    """Run nuclei against base_url using default templates. Returns [] if
    nuclei is not installed or the scan fails/times out."""
    if not is_available():
        return []

    cmd = [
        "nuclei",
        "-u", base_url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-severity", "info,low,medium,high,critical",
        "-timeout", "10",
        "-rate-limit", "50",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, FileNotFoundError, OSError):
        try:
            proc.kill()
        except Exception:
            pass
        return []

    findings: list[Finding] = []
    for line in stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = obj.get("info", {})
        severity_str = (info.get("severity") or "info").lower()
        severity = NUCLEI_SEVERITY_MAP.get(severity_str, Severity.INFO)

        findings.append(Finding(
            check=f"nuclei_{obj.get('template-id', 'unknown')}",
            title=info.get("name", obj.get("template-id", "Nuclei finding")),
            severity=severity,
            description=info.get("description", "") or "Detected by a nuclei template; "
                        "see references for details.",
            evidence=obj.get("matched-at", obj.get("host", "")),
            url=obj.get("matched-at", base_url),
            remediation=_remediation_for(info),
            references=info.get("reference", []) or [],
            source="nuclei",
        ))

    return findings


def _remediation_for(info: dict) -> str:
    remediation = info.get("remediation")
    if remediation:
        return remediation
    classification = info.get("classification", {}) or {}
    cve_ids = classification.get("cve-id") or []
    if cve_ids:
        return (f"This matches known CVE(s): {', '.join(cve_ids)}. Update the affected "
                f"software/component to a patched version and check vendor advisories.")
    return ("Review the matched template's documentation on the nuclei-templates repo "
            "for the specific fix; generally this means patching/upgrading the affected "
            "software or correcting the flagged misconfiguration.")
