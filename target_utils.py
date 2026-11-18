"""Shared target-URL parsing: hostname for evidence keys, full URL for web tools."""

from typing import Optional, Tuple
from urllib.parse import urlparse


def parse_target_url(target: str) -> Tuple[str, Optional[str], Optional[int]]:
    """Split a URL-or-host target into (hostname, full_url, port).

    - ``https://host:8443/admin`` -> ``("host", "https://host:8443/admin", 8443)``
    - ``host``                   -> ``("host", None, None)``
    - ``https://host``           -> ``("host", "https://host", None)``
    """
    raw = (target or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        return parsed.hostname, raw, parsed.port
    return raw, None, None


def target_has_path(target: str) -> bool:
    """True when the target is a URL with a meaningful path (not ``/`` or empty)."""
    _, full_url, _ = parse_target_url(target)
    if not full_url:
        return False
    path = urlparse(full_url).path
    return bool(path and path != "/")
