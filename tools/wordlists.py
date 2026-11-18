"""
Shared wordlist resolution for content-discovery tools (ffuf / feroxbuster).

Content discovery needs a wordlist of paths/names to brute-force. Different
systems ship SecLists or the dirb package in different locations, and the
wrappers used to hard-code a single path that often did not exist, which
silently disabled discovery.

This helper scans a set of well-known candidates (plus the $FFUF_WORDLIST
env override) and returns the first existing wordlist, or None.
"""

import os
from pathlib import Path
from typing import Optional

# Common locations across installs (Ubuntu/Debian dirb, Kali, SecLists).
DEFAULT_WORDLIST_CANDIDATES = [
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/home/ubuntu/tools/seclists/seclists/Discovery/Web-Content/common.txt",
    "/opt/SecLists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
]


def _repo_root_candidates() -> list[str]:
    """A common.txt dropped in the CyberSwarm repo root (next to run.sh) is
    honored automatically — users often download one there instead of
    installing dirb/SecLists system-wide."""
    roots = [Path(__file__).resolve().parent.parent, Path.cwd()]
    return [str(r / "common.txt") for r in roots]


def find_wordlist(env_var: str = "FFUF_WORDLIST") -> Optional[str]:
    """Return an existing wordlist path, preferring the given env override."""
    env_path = os.environ.get(env_var)
    if env_path and Path(env_path).exists():
        return env_path
    for path in DEFAULT_WORDLIST_CANDIDATES + _repo_root_candidates():
        if Path(path).exists():
            return path
    return None


def default_wordlist_or(explicit: str = "") -> str:
    """Resolve a wordlist: explicit arg wins, else env/known locations.

    Returns '' when nothing can be found so callers can fail with a clear
    message instead of passing a path that does not exist.
    """
    if explicit:
        return explicit
    return find_wordlist() or ""
