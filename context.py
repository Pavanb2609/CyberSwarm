"""
context.py — per-engagement authentication state (credentialed testing).

Tools in CyberSwarm were originally one-shot: they took a target string and
ran. Real engagements -- authenticated scanning, cookie persistence across the
whole run, "test as user A vs user B" IDOR comparison -- need a single object
carrying the engagement's auth state that every tool can read and update.

EngagementContext provides:
  - persistent cookies (dict name -> value) collected by LOGIN_FILL etc.
  - extra auth headers (Bearer tokens, custom headers)
  - a short credential list, each tagged with an identity label
    (convention: "A", "B", ...; "anonymous" means no credentials)
  - base_url + user agent for HTTP tools

The Controller persists it into AssessmentState.metadata["engagement"] so it
survives runs and shows up in decision traces; ToolManager passes it to every
tool via **kwargs (tool.run(target, timeout, context=ctx)). Pure stdlib +
requests; no Pydantic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

ANONYMOUS = "anonymous"
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; CyberSwarm/cs-engage/1.0)"


@dataclass
class Credential:
    username: str
    password: str
    identity: str = ANONYMOUS
    source_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"username": self.username, "password": self.password,
                "identity": self.identity, "source_url": self.source_url}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Credential":
        return cls(
            username=str(d.get("username", "")),
            password=str(d.get("password", "")),
            identity=str(d.get("identity", ANONYMOUS)),
            source_url=str(d.get("source_url", "")),
        )


@dataclass
class EngagementContext:
    """Mutable per-target auth state threaded through every tool call."""

    target: str = ""
    base_url: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    credentials: List[Credential] = field(default_factory=list)
    identity: str = ANONYMOUS
    user_agent: str = DEFAULT_USER_AGENT

    # ── convenience accessors ───────────────────────────────────────────

    def identity_labels(self) -> List[str]:
        """Distinct non-anonymous identity labels among the supplied creds."""
        seen: List[str] = []
        for c in self.credentials:
            if c.identity and c.identity != ANONYMOUS and c.identity not in seen:
                seen.append(c.identity)
        return sorted(seen)

    def credential_for(self, identity: Optional[str] = None) -> Optional[Credential]:
        """First credential tagged with `identity` (falls back to the active
        identity, then any single credential)."""
        wanted = identity or self.identity
        if wanted and wanted != ANONYMOUS:
            for c in self.credentials:
                if c.identity == wanted:
                    return c
        if len(self.credentials) == 1:
            return self.credentials[0]
        return None

    def cookie_str(self) -> str:
        """'name1=value1; name2=value2' — header-ready."""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def update_cookies(self, cookies: Dict[str, str]) -> None:
        for k, v in (cookies or {}).items():
            if k and v is not None:
                self.cookies[k] = str(v)

    def update_headers(self, headers: Dict[str, str]) -> None:
        for k, v in (headers or {}).items():
            if k and v is not None:
                self.headers[str(k)] = str(v)

    def anonymized(self) -> "EngagementContext":
        """Copy with auth cleared (identity -> anonymous) for A-vs-B checks."""
        return EngagementContext(
            target=self.target, base_url=self.base_url,
            cookies={}, headers={}, credentials=list(self.credentials),
            identity=ANONYMOUS, user_agent=self.user_agent,
        )

    # ── serialization ───────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target, "base_url": self.base_url,
            "cookies": dict(self.cookies), "headers": dict(self.headers),
            "credentials": [c.to_dict() for c in self.credentials],
            "identity": self.identity, "user_agent": self.user_agent,
        }

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "EngagementContext":
        d = d or {}
        return cls(
            target=str(d.get("target", "")),
            base_url=str(d.get("base_url", "")),
            cookies={str(k): str(v) for k, v in (d.get("cookies") or {}).items()},
            headers={str(k): str(v) for k, v in (d.get("headers") or {}).items()},
            credentials=[Credential.from_dict(c) for c in (d.get("credentials") or [])],
            identity=str(d.get("identity", ANONYMOUS)),
            user_agent=str(d.get("user_agent", DEFAULT_USER_AGENT)),
        )


# ── loaders ───────────────────────────────────────────────────────────────

def _parse_credentials(data: Any) -> List[Credential]:
    """Accept several shapes:
      { "identities": {"A": {"username":..., "password":...}, ...} }
      { "users": [{"username","password","identity"?}, ...] }
      [ {"username","password","identity"?}, ... ]
      [ ["user","pass"], ... ]
    """
    out: List[Credential] = []
    idents = data.get("identities") if isinstance(data, dict) else None
    if isinstance(idents, dict):
        for label, entry in idents.items():
            if isinstance(entry, dict):
                out.append(Credential(
                    username=str(entry.get("username", "")),
                    password=str(entry.get("password", "")),
                    identity=str(label),
                    source_url=str(entry.get("source_url", "")),
                ))
        return out
    raw_users = data.get("users") if isinstance(data, dict) else None
    if raw_users is None and isinstance(data, list):
        raw_users = data
    for entry in raw_users or []:
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            out.append(Credential(username=str(entry[0]), password=str(entry[1])))
        elif isinstance(entry, dict):
            out.append(Credential(
                username=str(entry.get("username", "")),
                password=str(entry.get("password", "")),
                identity=str(entry.get("identity", ANONYMOUS)),
                source_url=str(entry.get("source_url", "")),
            ))
    return out


def _parse_cookies(data: Any) -> Dict[str, str]:
    """Accept a bare cookie dict, {"cookies": {...}}, or a (subset) HAR
    export whose first request carries cookies."""
    if isinstance(data, dict):
        if isinstance(data.get("cookies"), dict):
            return {str(k): str(v) for k, v in data["cookies"].items()}
        entries = data.get("log", {}).get("entries") if isinstance(data.get("log"), dict) else None
        if isinstance(entries, list) and entries:
            req = entries[0].get("request", {})
            return {str(c.get("name")): str(c.get("value"))
                    for c in (req.get("cookies") or []) if c.get("name")}
        return {str(k): str(v) for k, v in data.items()
                if not isinstance(v, (dict, list))}
    return {}


def load_engagement(target: str,
                    creds_file: Optional[str] = None,
                    cookies_file: Optional[str] = None,
                    base_url: Optional[str] = None,
                    identity: Optional[str] = None) -> EngagementContext:
    """Build an EngagementContext for `target` from optional files.

    creds_file:  JSON (identities/users/list shapes; see _parse_credentials)
    cookies_file: JSON cookie dict / HAR, or a raw "Cookie: a=b; c=d" header
    """
    ctx = EngagementContext(target=target, base_url=base_url or f"https://{target}")
    if identity:
        ctx.identity = identity

    if creds_file:
        path = Path(creds_file)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ValueError(f"cannot read creds file {creds_file}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"creds file {creds_file} is not valid JSON: {exc}") from exc
        ctx.credentials = _parse_credentials(data)

    if cookies_file:
        path = Path(cookies_file)
        try:
            blob = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"cannot read cookies file {cookies_file}: {exc}") from exc
        blob = blob.strip()
        if blob.lower().startswith("cookie:"):
            cookies: Dict[str, str] = {}
            for part in blob[len("cookie:"):].split(";"):
                if "=" in part:
                    k, _, v = part.strip().partition("=")
                    cookies[k.strip()] = v.strip()
            ctx.update_cookies(cookies)
        else:
            try:
                data = json.loads(blob)
            except json.JSONDecodeError:
                cookies = {}
                for part in blob.split(";"):
                    if "=" in part:
                        k, _, v = part.strip().partition("=")
                        cookies[k.strip()] = v.strip()
                ctx.update_cookies(cookies)
            else:
                ctx.update_cookies(_parse_cookies(data))
    return ctx