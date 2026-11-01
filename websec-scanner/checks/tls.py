"""
TLS/SSL certificate and protocol checks.

Connects to port 443, inspects the certificate chain presented, checks
expiry and basic protocol version. Passive -- no handshake manipulation.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.models import Finding, Severity


def _get_cert_info(hostname: str, port: int = 443, timeout: float = 6.0) -> dict | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                return {"cert": cert, "protocol": proto}
    except Exception as e:
        return {"error": str(e)}


async def run(base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    hostname = parsed.hostname
    if not hostname:
        return findings

    if parsed.scheme != "https":
        findings.append(Finding(
            check="no_https",
            title="Site not served over HTTPS",
            severity=Severity.HIGH,
            description=f"The target was reached over '{parsed.scheme}'. All traffic, "
                         f"including any credentials or session cookies, is unencrypted.",
            url=base_url,
            remediation="Obtain a TLS certificate (e.g. free via Let's Encrypt/Certbot) "
                         "and redirect all HTTP traffic to HTTPS.",
            source="passive",
        ))
        return findings

    info = _get_cert_info(hostname)
    if info is None or "error" in info:
        err = info.get("error") if info else "unknown error"
        findings.append(Finding(
            check="tls_connection_failed",
            title="Could not establish TLS connection",
            severity=Severity.MEDIUM,
            description=f"TLS handshake to {hostname}:443 failed: {err}. This may indicate "
                         f"a misconfigured certificate, expired cert, or blocked port.",
            url=base_url,
            remediation="Verify the certificate is valid and the server is listening on 443.",
            source="passive",
        ))
        return findings

    cert = info["cert"]
    protocol = info["protocol"]

    if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(Finding(
            check="outdated_tls_protocol",
            title=f"Outdated TLS protocol negotiated: {protocol}",
            severity=Severity.HIGH,
            description=f"The server negotiated {protocol}, which has known weaknesses and "
                         f"is deprecated by major browsers.",
            evidence=protocol,
            url=base_url,
            remediation="Disable TLS 1.0/1.1 and SSLv3 server-side; require TLS 1.2 minimum, "
                         "prefer TLS 1.3.",
            source="passive",
        ))

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(Finding(
                    check="tls_cert_expired",
                    title="TLS certificate has expired",
                    severity=Severity.CRITICAL,
                    description=f"Certificate expired on {not_after}. Browsers will show "
                                 f"hard security warnings to all visitors.",
                    evidence=not_after,
                    url=base_url,
                    remediation="Renew the certificate immediately and set up auto-renewal "
                                 "(e.g. certbot renew via cron/systemd timer).",
                    source="passive",
                ))
            elif days_left < 14:
                findings.append(Finding(
                    check="tls_cert_expiring_soon",
                    title=f"TLS certificate expires in {days_left} day(s)",
                    severity=Severity.MEDIUM,
                    description=f"Certificate expires {not_after}.",
                    evidence=not_after,
                    url=base_url,
                    remediation="Renew the certificate before expiry; verify auto-renewal "
                                 "is actually working.",
                    source="passive",
                ))
        except ValueError:
            pass

    return findings
