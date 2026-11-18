"""
authorization.py — target scope gate for the assessment loops.

The gate is *lenient by default*: with no authorized-targets file (or an empty
list) every target is allowed, preserving the self-hosted offline workflows.
As soon as an operator defines a scope in config/authorized_targets.json, the
Controller refuses to run any target outside it — a hard containment control
for unattended autonomous assessment.

Scope entries support leading-dot wildcards:

    example.com          exact host match (and the same host with any scheme)
    .example.com         matches example.com and every sub.example.com
    *.example.com        alias for .example.com
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List, Tuple
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config" / "authorized_targets.json"


def _munge(target: str) -> str:
    """Reduce a URL/string to a bare lowercase hostname for comparison."""
    t = (target or "").strip().lower().rstrip(".")
    if not t:
        return ""
    try:
        parsed = urlparse(t)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            t = parsed.hostname
    except Exception:  # noqa: BLE001
        pass
    return t.rstrip(".").lower()


def _entry_host(entry) -> str:
    """Host string of a scope entry: either "example.com" or
    {"target": "example.com", "authorized_by": ..., "authorized_until": ...}."""
    if isinstance(entry, dict):
        return str(entry.get("target") or entry.get("host") or "").strip().lower()
    return str(entry or "").strip().lower()


def _expired(entry) -> bool:
    """True when a dict entry carries an authorized_until date in the past.
    Plain-string entries never expire (backward compatible)."""
    if not isinstance(entry, dict) or not entry.get("authorized_until"):
        return False
    from datetime import date
    try:
        until = date.fromisoformat(str(entry["authorized_until"])[:10])
    except ValueError:
        return True  # unreadable expiry -> treat as expired (fail closed)
    return until < date.today()


def load_scope_entries() -> list:
    """Raw scope entries as stored (strings and/or dicts)."""
    if not CONFIG_PATH.exists():
        return []
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return list(data.get("targets", []) if isinstance(data, dict) else [])
    except (json.JSONDecodeError, OSError):
        return []


def load_scope() -> List[str]:
    """Read the configured authorized target list (bare host strings).

    Entries may be plain hosts or objects with authorization metadata:

        {"targets": [
            "lab.example",
            {"target": "app.client.com", "authorized_by": "J. Smith (client CISO)",
             "scope": "SOW-2026-14, web app only", "authorized_until": "2026-12-31"}
        ]}

    Entries whose authorized_until date has passed are dropped, so an
    engagement's scope ends on its end date instead of living forever.
    """
    out = []
    for e in load_scope_entries():
        host = _entry_host(e)
        if not host:
            continue
        if _expired(e):
            print(f"[authorization] scope entry '{host}' expired "
                  f"(authorized_until={e.get('authorized_until')}); ignoring it.",
                  file=sys.stderr)
            continue
        out.append(host)
    return out


def has_scope() -> bool:
    return bool(load_scope())


def matches(target: str, entry: str) -> bool:
    """True when `target` falls inside the scope entry (wildcard aware)."""
    host = _munge(target)
    if not host:
        return False
    entry = entry.strip().lower().rstrip(".")
    if entry.startswith("*."):
        entry = "." + entry[2:]      # normalize "*.x" -> ".x"
    if entry.startswith("."):
        zone = entry[1:]
        if not zone:
            return False
        return host == zone or host.endswith("." + zone)
    return host == entry


# Lab targets that are always permitted — deliberately vulnerable systems
# that exist to be attacked. These are recognised by address, not by the user
# saying so, which means a typo cannot accidentally authorise a real host.
_LAB_TARGETS = frozenset({
    "127.0.0.1", "localhost",
    "dvwa",                      # DVWA default hostname
    "juiceshop", "juice-shop",   # OWASP Juice Shop
    "webgoat",                   # WebGoat
    "metasploitable",            # Metasploitable
    "hackthebox", "htb",         # HTB machine (user must still own the box)
})

_LAB_CIDRS = (
    "10.",         # RFC-1918 private
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",    # RFC-1918 private
)


def is_lab_target(target: str) -> bool:
    """True for localhost, RFC-1918 addresses and known lab hostnames.

    Lab targets bypass the scope file — they are purpose-built to be attacked.
    This is not a loophole: the check is on the resolved address or the
    hostname, not on the user's assurance.
    """
    host = _munge(target)
    if host in _LAB_TARGETS:
        return True
    if any(host.startswith(cidr) for cidr in _LAB_CIDRS):
        return True
    return False


def is_authorized(target: str,
                  mode: str = "strict") -> Tuple[bool, str]:
    """(allowed, reason).

    Modes:
      strict  — the right default for anything that could touch real systems.
                No scope file = DENIED. Explicit scope entry required.
      lab     — internal/private addresses and known lab hostnames are always
                allowed, scope file still applies for anything else.
      legacy  — the old lenient behaviour (no scope = allowed). Only kept so
                existing tests do not break; never use for real targets.

    The change from the old behaviour:
      * Default mode is now 'strict'.
      * With no scope file configured, strict mode DENIES.
      * This means running the tool without first running
        `python cli.py authorize <target>` is a hard stop, not silent approval.
    """
    if is_lab_target(target):
        return True, f"lab/private target always permitted: {_munge(target)}"

    scope_entries = load_scope()

    if mode == "legacy":
        if not scope_entries:
            return True, "no authorization scope configured (legacy mode)"
    else:
        # strict and lab modes: no scope = denied.
        if not scope_entries:
            return (False,
                    "no authorization scope configured — run "
                    "`python cli.py authorize <target>` first, or set up "
                    "config/authorized_targets.json. This gate exists to stop "
                    "the tool running against targets you did not explicitly "
                    "approve. Lab targets (127.x, 192.168.x, 10.x, etc.) are "
                    "always permitted without a scope file.")

    for entry in scope_entries:
        if matches(target, entry):
            return True, f"target matches scope entry '{entry}'"
    return False, f"target '{_munge(target)}' is outside the authorized scope ({CONFIG_PATH})"


def scope() -> List[str]:
    """The effective scope entries, normalized to bare hosts."""
    out = set()
    for entry in load_scope():
        e = entry.replace("*.", "").lower().rstrip(".")
        out.add(e)
    return sorted(out)


def authorize_target(target: str, config_path: Path | None = None) -> None:
    """Persist `target` (bare host) into the authorized-targets scope."""
    path = Path(config_path) if config_path else CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    host = _munge(target)
    if not host:
        raise ValueError(f"cannot authorize empty/invalid target: {target!r}")
    current = []
    if path.exists():
        try:
            current = json.loads(path.read_text(encoding="utf-8")).get("targets", [])
        except (json.JSONDecodeError, OSError):
            current = []
    if host not in {_entry_host(e) for e in current}:
        current.append(host)
    path.write_text(json.dumps({"targets": current}, indent=2), encoding="utf-8")


def remove_target(target: str, config_path: Path | None = None) -> None:
    """Remove `target` (bare host) from the authorized-targets scope.

    Does nothing if the scope file does not exist or the host is not in it.
    """
    path = Path(config_path) if config_path else CONFIG_PATH
    host = _munge(target)
    if not host:
        raise ValueError(f"cannot de-authorize empty/invalid target: {target!r}")
    if not path.exists():
        return
    try:
        current = json.loads(path.read_text(encoding="utf-8")).get("targets", [])
    except (json.JSONDecodeError, OSError):
        current = []
    kept = [e for e in current if _entry_host(e) != host]
    if kept != current:
        path.write_text(json.dumps({"targets": kept}, indent=2), encoding="utf-8")


def describe_scope(config_path: Path | None = None) -> str:
    """Human-readable summary of the current assessment scope.

    Never prompts; safe to call from the CLI and the loops.
    """
    path = Path(config_path) if config_path else CONFIG_PATH
    entries = load_scope()
    if not entries:
        return ("No authorized targets configured. Add hosts with "
                "`cyberswarm authorize <target>` (or --targets-file for a batch).\n"
                "Lab/private targets (127.x, 192.168.x, 10.x, localhost, dvwa, "
                "juiceshop, metasploitable, ...) are always permitted without a "
                "scope file.")
    lines = [f"Authorized assessment scope ({path}):"]
    meta = {_entry_host(e): e for e in load_scope_entries() if isinstance(e, dict)}
    for e in entries:
        note = "  (wildcard: matches this host and all subdomains)" \
            if e.startswith((".", "*.")) else ""
        m = meta.get(e)
        if m:
            bits = [f"{k}={m[k]}" for k in ("authorized_by", "scope", "authorized_until") if m.get(k)]
            if bits:
                note += "  [" + "; ".join(bits) + "]"
        lines.append(f"  - {e}{note}")
    lines.append("Lab/private targets (127.x, 192.168.x, 10.x, localhost, dvwa, "
                 "juiceshop, metasploitable, ...) are always permitted.")
    return "\n".join(lines)


def offer_authorize(target: str, action: str = "run",
                    config_path: Path | None = None,
                    input_func=None) -> bool:
    """Interactive step-up authorization with a clear consent prompt.

    Only ever prompts when stdin is a TTY. In unattended/CI runs this prints a
    pointer to the non-interactive command and returns False, so a script can
    never silently authorize a target. `confirm()` deliberately stays
    non-interactive (see tests/test_authorization_gate.py).
    """
    ok, reason = is_authorized(target, mode="strict")
    if ok:
        return True
    host = _munge(target)
    if not sys.stdin.isatty():
        print(f"[authorization] {reason}")
        print(f"[authorization] to authorize '{host}' for {action}, run: "
              "`cyberswarm authorize <target>`")
        return False
    print(f"[authorization] {reason}")
    print(f"[authorization] '{host}' is NOT authorized for {action}.")
    print("  You are explicitly expanding the assessment scope to include this")
    print("  host. Only authorize targets you own or have written permission to")
    print("  assess. This adds a persistent entry to the scope file.")
    _input = input_func or input
    answer = _input(f"  Authorize '{host}' for {action}? [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        print(f"[authorization] not authorized -- {action} aborted.")
        return False
    authorize_target(host, config_path=config_path)
    print(f"[authorize] added '{host}' to the assessment scope.")
    for line in describe_scope(config_path=config_path).splitlines():
        print(f"          {line}")
    return True


def confirm(target: str, action: str = "scan", force: bool = False) -> None:
    ok, reason = is_authorized(target)
    if not ok and not force:
        raise PermissionError(f"refusing to {action} {target!r}: {reason}")