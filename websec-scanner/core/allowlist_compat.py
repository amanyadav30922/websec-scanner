"""Small shared helper: extract a bare hostname from a URL or raw domain string."""
from __future__ import annotations

from urllib.parse import urlparse


def normalize_domain(target: str) -> str:
    target = target.strip()
    if "://" not in target:
        target = "https://" + target
    return (urlparse(target).hostname or "").lower()
