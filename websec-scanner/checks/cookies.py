"""
Cookie flag checks (Secure, HttpOnly, SameSite).
"""
from __future__ import annotations

import httpx

from core.models import Finding, Severity


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return findings

    set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not set_cookie_headers:
        raw = resp.headers.get("set-cookie")
        set_cookie_headers = [raw] if raw else []

    for raw_cookie in set_cookie_headers:
        parts = [p.strip() for p in raw_cookie.split(";")]
        cookie_name = parts[0].split("=")[0] if parts else "unknown"
        lower = raw_cookie.lower()

        if "secure" not in lower:
            findings.append(Finding(
                check="cookie_missing_secure",
                title=f"Cookie '{cookie_name}' missing Secure flag",
                severity=Severity.MEDIUM,
                description="Without the Secure flag, this cookie can be sent over "
                             "unencrypted HTTP, exposing it to network interception.",
                evidence=raw_cookie,
                url=str(resp.url),
                remediation=f"Set the Secure attribute on '{cookie_name}' "
                             f"(e.g. res.cookie(name, val, {{secure: true}}) in Express, "
                             f"or Set-Cookie: {cookie_name}=...; Secure).",
                source="passive",
            ))

        if "httponly" not in lower:
            findings.append(Finding(
                check="cookie_missing_httponly",
                title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                severity=Severity.MEDIUM,
                description="Without HttpOnly, client-side JavaScript can read this cookie, "
                             "so a single XSS bug can be used to steal it (e.g. session theft).",
                evidence=raw_cookie,
                url=str(resp.url),
                remediation=f"Set the HttpOnly attribute on '{cookie_name}' unless it must "
                             f"be read by front-end JS.",
                source="passive",
            ))

        if "samesite" not in lower:
            findings.append(Finding(
                check="cookie_missing_samesite",
                title=f"Cookie '{cookie_name}' missing SameSite attribute",
                severity=Severity.LOW,
                description="No SameSite attribute means the cookie may be sent on "
                             "cross-site requests, increasing CSRF exposure.",
                evidence=raw_cookie,
                url=str(resp.url),
                remediation=f"Set SameSite=Lax (or Strict where possible) on '{cookie_name}'.",
                source="passive",
            ))

    return findings
