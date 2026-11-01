"""
Exposed file / path checks.

Requests a fixed list of well-known sensitive paths and flags any that
return 200 with content that looks real (not a custom 404 page). This is
read-only GET traffic against paths that should not be public -- equivalent
to what a browser typing the URL would do, nothing exploit-like.
"""
from __future__ import annotations

import httpx

from core.models import Finding, Severity

# path -> (severity, title, description, remediation)
SENSITIVE_PATHS: dict[str, tuple[Severity, str, str, str]] = {
    ".env": (
        Severity.CRITICAL,
        "Exposed .env file",
        "The .env file is publicly accessible and may contain database "
        "credentials, API keys, or secrets.",
        "Remove .env from the web root / deployed bundle. Block dotfiles at "
        "the web server (e.g. nginx: 'location ~ /\\. { deny all; }') and "
        "ensure your deploy process never copies it into public/static dirs.",
    ),
    ".git/config": (
        Severity.HIGH,
        "Exposed .git directory",
        "The .git/config file is publicly readable, meaning the entire git "
        "history (including possibly old secrets or source code) can "
        "potentially be reconstructed by a visitor.",
        "Remove the .git directory from the deployed web root, or block "
        "access to it at the web server level.",
    ),
    "wp-config.php.bak": (
        Severity.CRITICAL,
        "Exposed WordPress config backup",
        "A backup of wp-config.php is publicly accessible, which typically "
        "contains database credentials in plaintext.",
        "Delete backup files from the web root; never leave .bak/.old/.orig "
        "copies of config files inside a publicly served directory.",
    ),
    "backup.zip": (
        Severity.HIGH,
        "Exposed backup archive",
        "A file named backup.zip is publicly accessible and may contain a "
        "full site or database dump.",
        "Remove backup archives from the web root; store backups outside "
        "the public directory.",
    ),
    "admin": (
        Severity.INFO,
        "Admin panel reachable at predictable path",
        "An admin interface responded at a commonly guessed path. Not a "
        "vulnerability by itself, but worth confirming it's protected by "
        "strong auth, rate limiting, and ideally IP allowlisting or MFA.",
        "Ensure the admin panel requires strong authentication and MFA, "
        "consider moving it off a guessable path or restricting by IP, and "
        "add rate limiting to the login endpoint.",
    ),
    "phpinfo.php": (
        Severity.HIGH,
        "Exposed phpinfo() page",
        "phpinfo.php reveals detailed server configuration, installed "
        "extensions, and sometimes environment variables.",
        "Delete phpinfo.php from production. Never leave debug/info "
        "endpoints reachable on a live server.",
    ),
    ".DS_Store": (
        Severity.LOW,
        "Exposed .DS_Store file",
        "A macOS .DS_Store file is publicly readable and can reveal the "
        "names of other files/directories on the server.",
        "Remove .DS_Store from the deployed directory and add it to "
        ".gitignore / deploy-ignore rules.",
    ),
    "server-status": (
        Severity.MEDIUM,
        "Exposed Apache server-status page",
        "mod_status is publicly reachable, revealing active requests, "
        "internal IPs, and URL patterns.",
        "Restrict /server-status to localhost/admin IPs only in your "
        "Apache config.",
    ),
    "config.json": (
        Severity.MEDIUM,
        "Potentially exposed config.json",
        "A config.json file is publicly accessible; verify it doesn't "
        "contain secrets.",
        "Move any sensitive config server-side, or restrict public access "
        "to this file.",
    ),
}

NOT_FOUND_MARKERS = ("404", "not found", "cannot get", "no such file")


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    base_url = base_url.rstrip("/")

    for path, (severity, title, description, remediation) in SENSITIVE_PATHS.items():
        url = f"{base_url}/{path}"
        try:
            resp = await client.get(url, follow_redirects=False, timeout=8.0)
        except httpx.HTTPError:
            continue

        if resp.status_code != 200:
            continue

        body_sample = resp.text[:500].lower() if resp.text else ""
        if any(marker in body_sample for marker in NOT_FOUND_MARKERS):
            continue
        if len(resp.content) < 10:
            continue

        findings.append(Finding(
            check=f"exposed_{path.replace('.', '_').replace('/', '_')}",
            title=title,
            severity=severity,
            description=description,
            evidence=f"HTTP {resp.status_code}, {len(resp.content)} bytes",
            url=url,
            remediation=remediation,
            source="passive",
        ))

    return findings
