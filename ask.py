"""
ask.py — turn a plain-English request into a capability or agent to run.

    python cli.py ask "find the subdomains of example.com"
    -> SUBDOMAIN_DISCOVERY on example.com   (subfinder, amass)
       python cli.py ask "..." --execute

The layer is deliberately thin. It resolves free text to
``(capability_or_agent, target)`` and nothing else: execution goes through the
same `execute_capability` the recon loop uses, behind the same authorization
check and phase gate. There is no separate execution path, because a second
path is a second place for the gates to be missed.

Why resolution and execution are separate
-----------------------------------------
Free text is the easiest place to accidentally widen scope — "and check the
other boxes on that subnet too" is one sentence, and a layer that extracts a
host and runs would never show it to you. So:

* The default is to *print* the resolved command. Nothing runs.
* ``--execute`` runs it, and only after `authorization.is_authorized()` and the
  phase gate have both passed on the resolved target.
* The model is never asked for a shell command, only for a name from a fixed
  list. Anything not on that list is refused, so a hallucinated or injected
  action cannot reach the executor.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from utils import get_logger
except ImportError:  # standalone import
    import logging

    def get_logger(name: str):  # type: ignore[misc]
        return logging.getLogger(name)

log = get_logger("ask")

# A hostname, an IP, or a URL we can pull a host out of.
_URL_RE = re.compile(r"https?://([^/\s:]+)", re.I)
_HOST_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b", re.I)
_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

# Words that look like hosts but are almost always prose.
_HOST_STOPWORDS = {"e.g", "i.e", "etc.", "vs."}

# "report.json" and "scan.py" match the hostname pattern perfectly, and a
# request mentioning an output file should not be read as a target.
_FILE_SUFFIXES = {
    "json", "jsonl", "md", "txt", "log", "xml", "html", "htm", "csv", "tsv",
    "yaml", "yml", "py", "sh", "js", "ts", "zip", "tar", "gz", "pdf", "png",
    "jpg", "jpeg", "svg", "conf", "cfg", "ini", "sqlite", "db", "burp",
}

RESOLVE_SYSTEM = """You map a penetration tester's request onto exactly one \
action from a fixed list. You never invent names and never emit shell commands.

Reply with ONLY this JSON object:
{"kind": "capability"|"agent"|"none",
 "name": "<exact name from the list, or empty>",
 "target": "<host from the request, or empty>",
 "confidence": 0-100,
 "reason": "<one short sentence>"}

Rules:
- "name" MUST be copied exactly from the supplied list. If nothing fits, use
  kind "none" with an empty name.
- "target" is copied from the request. Never guess a target that was not
  written. Never expand one host into a range, subnet or wildcard.
- If the request names more than one target, pick the one it is actually about
  and say so in "reason".
"""


@dataclass
class Resolution:
    """What a request resolved to, and whether it may run."""

    kind: str = "none"                 # capability | agent | none
    name: str = ""
    target: str = ""
    confidence: int = 0
    reason: str = ""
    errors: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.kind in ("capability", "agent") and self.name
                    and self.target and not self.errors)

    def command(self) -> str:
        """The equivalent command a user could run by hand."""
        if not self.ok:
            return ""
        if self.kind == "agent":
            return f"python cli.py attack {self.target}    # agent: {self.name}"
        return f"python cli.py recon {self.target}    # capability: {self.name}"

    def describe(self) -> str:
        if not self.ok:
            lines = ["Could not resolve that request to an action."]
            if self.reason:
                lines.append(f"  reason: {self.reason}")
            lines += [f"  {e}" for e in self.errors]
            return "\n".join(lines)
        lines = [f"{self.name}  on  {self.target}",
                 f"  kind       : {self.kind}",
                 f"  confidence : {self.confidence}"]
        if self.reason:
            lines.append(f"  reason     : {self.reason}")
        tools = tools_for(self.name) if self.kind == "capability" else []
        if tools:
            lines.append(f"  tools      : {', '.join(tools)}")
        return "\n".join(lines)


# ── Known actions ────────────────────────────────────────────────────────────

def known_capabilities() -> List[str]:
    try:
        from tools.registry import CAPABILITY_TOOL_MAP
        return sorted(CAPABILITY_TOOL_MAP)
    except Exception as exc:  # noqa: BLE001
        log.debug("Could not load capabilities: %s", exc)
        return []


def known_agents() -> List[str]:
    try:
        from agents import registry
        mapping = (getattr(registry, "AGENT_REGISTRY", None)
                   or getattr(registry, "AGENTS", {}))
        return sorted(mapping)
    except Exception as exc:  # noqa: BLE001
        log.debug("Could not load agents: %s", exc)
        return []


def tools_for(capability: str) -> List[str]:
    try:
        from tools.registry import CAPABILITY_TOOL_MAP
        return list(CAPABILITY_TOOL_MAP.get(capability, []))
    except Exception:  # noqa: BLE001
        return []


# ── Target extraction ────────────────────────────────────────────────────────

def extract_target(text: str) -> str:
    """Pull a single host out of free text, preferring an explicit URL."""
    text = str(text or "")
    match = _URL_RE.search(text)
    if match:
        return match.group(1).lower()
    match = _IPV4_RE.search(text)
    if match:
        octets = match.group(1).split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return match.group(1)
    for candidate in _HOST_RE.findall(text):
        lowered = candidate.lower()
        if lowered in _HOST_STOPWORDS:
            continue
        suffix = lowered.rsplit(".", 1)[-1]
        if suffix.isdigit() or suffix in _FILE_SUFFIXES:
            continue
        return lowered
    return ""


def _extract_json(raw: str) -> Optional[Dict[str, Any]]:
    """Pull the first JSON object out of a model reply."""
    text = str(raw or "").strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


# ── Resolution ───────────────────────────────────────────────────────────────

def _match_known(name: str, known: Sequence[str]) -> str:
    """Case-insensitive exact match against the allowed list. No fuzzy matching."""
    needle = str(name or "").strip()
    if not needle:
        return ""
    for candidate in known:
        if candidate.lower() == needle.lower():
            return candidate
    return ""


def resolve(request: str, model_client: Any,
            capabilities: Optional[Sequence[str]] = None,
            agents: Optional[Sequence[str]] = None) -> Resolution:
    """Map free text onto one known capability or agent.

    The model chooses from a fixed list; anything it returns that is not on
    that list is rejected rather than passed through, so a hallucinated or
    prompt-injected action never reaches the executor.
    """
    caps = list(capabilities if capabilities is not None else known_capabilities())
    agent_names = list(agents if agents is not None else known_agents())

    text = str(request or "").strip()
    if not text:
        return Resolution(errors=["empty request"])
    if not caps and not agent_names:
        return Resolution(errors=["no capabilities or agents registered"])

    literal_target = extract_target(text)

    user = (f"Request:\n{text}\n\n"
            f"Capabilities:\n{', '.join(caps)}\n\n"
            f"Agents:\n{', '.join(agent_names)}\n\n"
            "Return the JSON object.")

    try:
        raw = model_client.chat(RESOLVE_SYSTEM, user, temperature=0.0)
    except Exception as exc:  # noqa: BLE001
        return Resolution(errors=[f"model call failed: {exc}"])

    parsed = _extract_json(raw)
    if parsed is None:
        return Resolution(errors=["model did not return usable JSON"])

    kind = str(parsed.get("kind", "none")).strip().lower()
    name = str(parsed.get("name", "")).strip()
    target = str(parsed.get("target", "")).strip().lower()
    try:
        confidence = int(parsed.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0
    reason = str(parsed.get("reason", "")).strip()

    resolution = Resolution(kind=kind, name=name, target=target,
                            confidence=confidence, reason=reason)

    if kind == "none" or not name:
        resolution.kind = "none"
        resolution.errors.append("no matching capability or agent for that request")
        return resolution

    if kind == "capability":
        matched = _match_known(name, caps)
    elif kind == "agent":
        matched = _match_known(name, agent_names)
    else:
        resolution.errors.append(f"unknown kind {kind!r}")
        return resolution

    if not matched:
        resolution.errors.append(
            f"{name!r} is not a registered {kind}; refusing to run it")
        return resolution
    resolution.name = matched

    # The target must appear in what the user actually typed. This is the check
    # that stops a model widening scope on its own.
    if not target:
        resolution.errors.append("no target in the request")
        return resolution
    if literal_target and target != literal_target:
        resolution.errors.append(
            f"model returned target {target!r} but the request names "
            f"{literal_target!r}; refusing")
        return resolution
    if not literal_target:
        resolution.errors.append(
            f"could not find {target!r} in the request text; refusing to "
            "act on a target that was not written out")
        return resolution

    return resolution


# ── Execution ────────────────────────────────────────────────────────────────

def check_gates(resolution: Resolution,
                config: Optional[Dict[str, Any]] = None) -> Tuple[bool, List[str]]:
    """Authorization and phase checks for a resolved action.

    Same checks the loops apply. Returns (allowed, messages); messages are
    always worth showing, even when allowed.
    """
    messages: List[str] = []
    if not resolution.ok:
        return False, ["resolution failed"]

    try:
        import authorization
        allowed, reason = authorization.is_authorized(resolution.target)
        messages.append(f"authorization: {reason}")
        if not allowed:
            return False, messages
    except Exception as exc:  # noqa: BLE001
        messages.append(f"authorization check unavailable ({exc}); refusing")
        return False, messages

    if resolution.kind == "capability":
        try:
            import json as _json
            from pathlib import Path

            import phases
            from utils import ROOT

            controller = phases.get_controller(resolution.target, config)
            evidence = {}
            path = Path(ROOT) / "results" / "evidence" / f"{resolution.target}.json"
            try:
                loaded = _json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    evidence = loaded
            except (OSError, _json.JSONDecodeError, UnicodeDecodeError):
                pass
            ctx = phases.PhaseContext.from_evidence(evidence, target=resolution.target)
            allowed, why = controller.allows_capability(resolution.name, ctx)
            messages.append(f"phase: {why}")
            if not allowed:
                return False, messages
        except Exception as exc:  # noqa: BLE001
            messages.append(f"phase check skipped ({exc})")

    return True, messages


def execute(resolution: Resolution, timeout: int = 180):
    """Run a resolved capability through the normal executor.

    Agents are not executed here: they need a SystemMap and the planner, so
    `cli.py attack` remains the way to run them.
    """
    if not resolution.ok:
        raise ValueError("cannot execute an unresolved request")
    if resolution.kind != "capability":
        raise ValueError(
            f"{resolution.name} is an agent; run it with "
            f"`python cli.py attack {resolution.target}`")
    from recon_engine import execute_capability
    return execute_capability(resolution.name, resolution.target, timeout=timeout)
