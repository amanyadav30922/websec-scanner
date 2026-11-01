"""
CORS misconfiguration check.

Sends a normal GET with an Origin header (standard browser behavior, not a
crafted payload) and inspects how Access-Control-Allow-Origin is echoed.
"""
from __future__ import annotations

import httpx

from core.models import Finding, Severity

PROBE_ORIGIN = "https://cors-probe.example.com"


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(
            base_url,
            headers={"Origin": PROBE_ORIGIN},
            follow_redirects=True,
            timeout=8.0,
        )
    except httpx.HTTPError:
        return findings

    acao = resp.headers.get("access-control-allow-origin")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()

    if acao == "*" and acac == "true":
        findings.append(Finding(
            check="cors_wildcard_with_credentials",
            title="CORS allows '*' origin together with credentials",
            severity=Severity.CRITICAL,
            description="Access-Control-Allow-Origin: * combined with "
                         "Access-Control-Allow-Credentials: true is invalid per spec and "
                         "dangerous where browsers permit it -- it can allow any site to "
                         "read authenticated responses.",
            evidence=f"Access-Control-Allow-Origin: {acao}; "
                     f"Access-Control-Allow-Credentials: {acac}",
            url=str(resp.url),
            remediation="Never combine a wildcard origin with credentialed requests. "
                         "Echo back a specific allowlisted origin instead of '*'.",
            source="passive",
        ))
    elif acao == PROBE_ORIGIN:
        findings.append(Finding(
            check="cors_reflects_arbitrary_origin",
            title="CORS reflects arbitrary Origin header",
            severity=Severity.HIGH,
            description="The server echoed back an arbitrary, unrecognized Origin "
                         "('" + PROBE_ORIGIN + "') in Access-Control-Allow-Origin, meaning "
                         "any website can make cross-origin requests and read responses "
                         "(especially dangerous if credentials are also allowed).",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            url=str(resp.url),
            remediation="Validate the Origin header against an explicit allowlist "
                         "server-side rather than reflecting whatever was sent.",
            source="passive",
        ))
    elif acao == "*":
        findings.append(Finding(
            check="cors_wildcard_origin",
            title="CORS allows any origin ('*')",
            severity=Severity.LOW,
            description="Access-Control-Allow-Origin is '*'. Fine for a public, "
                         "unauthenticated API; risky if this endpoint ever returns "
                         "user-specific or sensitive data.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            url=str(resp.url),
            remediation="Scope CORS to known frontend origins unless this is "
                         "intentionally a fully public API with no sensitive data.",
            source="passive",
        ))

    return findings
