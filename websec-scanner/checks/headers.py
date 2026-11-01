"""
Security header checks.

Pure passive analysis: one GET request, inspect response headers.
No payloads sent, nothing exploited.
"""
from __future__ import annotations

import httpx

from core.models import Finding, Severity

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "title": "Missing HSTS header",
        "description": "The response does not include Strict-Transport-Security, so browsers "
                        "may connect over plain HTTP, exposing visitors to downgrade and "
                        "man-in-the-middle attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; "
                        "preload' to every HTTPS response. In nginx: "
                        "add_header Strict-Transport-Security \"max-age=31536000; "
                        "includeSubDomains; preload\" always;",
        "references": ["https://owasp.org/www-project-secure-headers/#http-strict-transport-security"],
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "title": "Missing Content-Security-Policy header",
        "description": "No CSP header means the browser enforces no restriction on which "
                        "scripts, styles, or frames can execute, increasing XSS impact.",
        "remediation": "Define a CSP tailored to your app, e.g. start with: "
                        "Content-Security-Policy: default-src 'self'; script-src 'self'; "
                        "object-src 'none'; frame-ancestors 'self'. Tighten iteratively using "
                        "report-only mode first.",
        "references": ["https://owasp.org/www-project-secure-headers/#content-security-policy"],
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "title": "Missing X-Content-Type-Options header",
        "description": "Without 'nosniff', some browsers may MIME-sniff responses, which can "
                        "turn an upload endpoint into a script execution vector.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' to all responses.",
        "references": ["https://owasp.org/www-project-secure-headers/#x-content-type-options"],
    },
    "X-Frame-Options": {
        "severity": Severity.LOW,
        "title": "Missing X-Frame-Options header",
        "description": "The page can be embedded in an iframe on another site, enabling "
                        "clickjacking attacks against logged-in users.",
        "remediation": "Add 'X-Frame-Options: DENY' (or SAMEORIGIN if you intentionally "
                        "frame your own pages), or rely on CSP 'frame-ancestors'.",
        "references": ["https://owasp.org/www-project-secure-headers/#x-frame-options"],
    },
    "Referrer-Policy": {
        "severity": Severity.INFO,
        "title": "Missing Referrer-Policy header",
        "description": "Without an explicit Referrer-Policy, full URLs (which may contain "
                        "tokens or sensitive query params) can leak to third parties via the "
                        "Referer header.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
        "references": ["https://owasp.org/www-project-secure-headers/#referrer-policy"],
    },
    "Permissions-Policy": {
        "severity": Severity.INFO,
        "title": "Missing Permissions-Policy header",
        "description": "No explicit policy restricting access to browser features "
                        "(camera, microphone, geolocation) for this origin and any iframes.",
        "remediation": "Add 'Permissions-Policy: geolocation=(), camera=(), microphone=()' "
                        "restricted to what your app actually needs.",
        "references": ["https://owasp.org/www-project-secure-headers/#permissions-policy"],
    },
}

LEAKY_HEADERS = {
    "Server": Severity.INFO,
    "X-Powered-By": Severity.LOW,
    "X-AspNet-Version": Severity.LOW,
    "X-AspNetMvc-Version": Severity.LOW,
}


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError as e:
        findings.append(Finding(
            check="connectivity",
            title="Could not connect to target",
            severity=Severity.INFO,
            description=f"Request to {base_url} failed: {e}",
            url=base_url,
            remediation="Verify the URL is reachable and not blocking automated clients.",
            source="passive",
        ))
        return findings

    headers = resp.headers

    for name, meta in RECOMMENDED_HEADERS.items():
        if name not in headers:
            findings.append(Finding(
                check=f"missing_header_{name.lower().replace('-', '_')}",
                title=meta["title"],
                severity=meta["severity"],
                description=meta["description"],
                url=str(resp.url),
                remediation=meta["remediation"],
                references=meta["references"],
                source="passive",
            ))

    for name, sev in LEAKY_HEADERS.items():
        if name in headers:
            findings.append(Finding(
                check=f"info_disclosure_header_{name.lower().replace('-', '_')}",
                title=f"Server discloses version info via '{name}' header",
                severity=sev,
                description=f"Response header '{name}: {headers[name]}' reveals software "
                             f"and/or version, helping attackers fingerprint known CVEs.",
                evidence=f"{name}: {headers[name]}",
                url=str(resp.url),
                remediation=f"Suppress or genericize the '{name}' header at the server/proxy "
                             f"level (e.g. 'server_tokens off;' in nginx, remove X-Powered-By "
                             f"in Express with app.disable('x-powered-by')).",
                source="passive",
            ))

    # Set-Cookie flags are checked in cookies.py, reusing this response where possible.
    return findings
