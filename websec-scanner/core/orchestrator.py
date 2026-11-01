"""
Scan orchestrator: runs all enabled checks against a target, persists to
SQLite, computes a diff against the previous scan, and fires alerts.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

from checks import headers as check_headers
from checks import cookies as check_cookies
from checks import tls as check_tls
from checks import exposure as check_exposure
from checks import cors as check_cors
from checks import nuclei as check_nuclei
from core import db
from core import alerts
from core.diff import diff_scans
from core.models import ScanResult


def _normalize_url(target: str) -> str:
    target = target.strip()
    if "://" not in target:
        target = "https://" + target
    return target.rstrip("/")


async def run_scan(target: str, use_nuclei: bool = True, send_alerts: bool = True) -> dict:
    base_url = _normalize_url(target)
    hostname = urlparse(base_url).hostname or ""

    result = ScanResult(target=base_url)

    if not db.is_domain_confirmed(hostname):
        result.status = "failed"
        result.error = (
            f"'{hostname}' is not in your verified domains list (or a confirmed "
            f"subdomain of one). Add and confirm the domain first."
        )
        result.finished_at = result.started_at
        db.save_scan(result)
        scan_dict = db.get_scan_dict(result.id)
        return scan_dict

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            headers={"User-Agent": "websec-scanner/0.1 (self-scan; contact: owner)"},
            verify=True,
        ) as client:
            passive_tasks = [
                check_headers.run(client, base_url),
                check_cookies.run(client, base_url),
                check_exposure.run(client, base_url),
                check_cors.run(client, base_url),
            ]
            passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)

            tls_results = await asyncio.gather(check_tls.run(base_url), return_exceptions=True)

            all_results = list(passive_results) + list(tls_results)

            if use_nuclei:
                nuclei_results = await check_nuclei.run(base_url)
                all_results.append(nuclei_results)

            for r in all_results:
                if isinstance(r, Exception):
                    continue
                result.findings.extend(r)

        result.status = "completed"
    except Exception as e:
        result.status = "failed"
        result.error = str(e)
    finally:
        from datetime import datetime, timezone
        result.finished_at = datetime.now(timezone.utc).isoformat()
        db.save_scan(result)

    scan_dict = db.get_scan_dict(result.id)

    if scan_dict["status"] == "failed":
        if send_alerts:
            alerts.notify_scan_failure(scan_dict)
        scan_dict["diff"] = None
        return scan_dict

    previous = db.get_previous_scan(hostname, result.id)
    diff = diff_scans(scan_dict, previous)
    scan_dict["diff"] = diff

    if send_alerts:
        alerts.notify_diff(scan_dict, diff)

    return scan_dict


async def run_scan_with_subdomains(target: str, use_nuclei: bool = True,
                                    include_subdomains: bool = False,
                                    send_alerts: bool = True) -> list[dict]:
    """Scans the primary target, and optionally all discovered+confirmed
    subdomains too. Returns a list of scan dicts."""
    hostname = urlparse(_normalize_url(target)).hostname or target
    targets = [target]

    if include_subdomains:
        subs = db.list_subdomains(hostname)
        targets.extend(s["subdomain"] for s in subs)

    results = []
    for t in targets:
        results.append(await run_scan(t, use_nuclei=use_nuclei, send_alerts=send_alerts))
    return results


def get_scan(scan_id: str) -> dict | None:
    scan = db.get_scan_dict(scan_id)
    if scan is None:
        return None
    previous = db.get_previous_scan(scan["hostname"], scan_id)
    scan["diff"] = diff_scans(scan, previous)
    return scan


def list_scans(target: str | None = None) -> list[dict]:
    hostname = urlparse(_normalize_url(target)).hostname if target else None
    return db.list_scans(hostname)
