"""
Subdomain discovery via certificate transparency logs (crt.sh).

Purely passive: queries a public CT log aggregator for certificates issued
for *.domain, no requests sent to the target itself. Results are names
other people/bots could just as easily find, so this doesn't disclose
anything that isn't already public.
"""
from __future__ import annotations

import re

import httpx

CRTSH_URL = "https://crt.sh/"


async def discover(domain: str, timeout: float = 20.0) -> list[str]:
    domain = domain.strip().lower().lstrip("*.")
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"})
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return []

    names: set[str] = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if not name or "@" in name:
                continue
            if not re.match(r"^[a-z0-9.\-]+$", name):
                continue
            if name == domain or name.endswith("." + domain):
                names.add(name)

    names.discard(domain)
    return sorted(names)
