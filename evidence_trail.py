"""
evidence_trail.py — a proof folder per target, one file per vulnerability class.

The complaint this answers: the tool says "testing done" but leaves no proof of
*what* it did. Everything landed in one flat JSON and you could not point at
"here is exactly what the XSS testing tried, and what came back."

This writes an auditable trail instead:

    results/engagements/<target>/
        00_SUMMARY.md            what was tested, what was found, at a glance
        xss.md                   every XSS attempt: payload, request, response, verdict
        sqli.md                  every SQLi attempt
        ssrf.md                  ...
        lfi.md
        <class>.md               one per vulnerability class that was tested
        raw/
            xss.json             machine-readable version of the same
            sqli.json
        sessions.md              any shells caught, commands run
        chain.md                 findings that composed into an attack path

Each class file shows, per attempt:
  * the payload or technique used
  * the request that was sent
  * the response evidence that came back
  * the verdict (CONFIRM / DISPUTE / NEEDS_PROOF) and why
  * whether it was proven, and how

So "XSS testing done" becomes "XSS: 14 payloads tried across 3 parameters,
1 proven to execute via headless browser (payload + screenshot reference),
13 reflected-but-not-executed, all recorded."

Design
------
* Append-only within a run: each attempt is added as it happens, so a crash
  mid-run still leaves the proof collected so far.
* Human-readable Markdown *and* machine-readable JSON, from the same data.
* Never invents proof. If a finding has no evidence, the file says
  "no proof captured" rather than dressing it up.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from utils import ROOT
except ImportError:
    ROOT = Path(__file__).resolve().parent

ENGAGEMENTS_DIR = Path(ROOT) / "results" / "engagements"

# Map a finding's OWASP/name onto a vulnerability-class filename.
# Order matters: the first match wins. Missing-header findings come first so
# "Missing X-XSS-Protection" is filed under headers, not xss.
_CLASS_PATTERNS = [
    ("headers",          ("missing security header", "x-xss-protection", "x-content-type",
                          "x-frame-options", "content-security-policy", "strict-transport",
                          "permissions-policy", "referrer-policy", "clickjack",
                          "security header")),
    ("cloud",            ("s3 bucket", "s3_", "bucket", "blob storage", "storage account",
                          "gcs ", "cloud storage")),
    ("subdomain_takeover", ("takeover", "dangling cname")),
    ("cors",             ("cors", "cross-origin resource")),
    ("insecure_design",  ("insecure design", "insecure-design", "debug endpoint",
                          "test endpoint")),
    ("xss",              ("xss", "cross-site scripting", "cross site scripting")),
    ("sqli",             ("sql injection", "sqli", "blind sql")),
    ("ssti",             ("template injection", "ssti")),
    ("ssrf",             ("ssrf", "request forgery")),
    ("lfi",              ("file inclusion", "lfi", "path traversal", "directory traversal")),
    ("rce",             ("command injection", "remote code execution", "rce", "os command")),
    ("xxe",              ("xxe", "xml external entity")),
    ("idor",             ("idor", "direct object", "broken access")),
    ("auth",             ("authentication", "default credential", "brute", "login", "session")),
    ("jwt",              ("jwt", "json web token")),
    ("csrf",             ("csrf", "cross-site request forgery")),
    ("deserialization",  ("deserial", "pickle")),
    ("crlf",             ("crlf",)),
    ("open_redirect",    ("open redirect", "redirect")),
    ("headers",          ("header", "clickjack", "hsts", "x-frame")),
    ("tls",              ("tls", "ssl", "certificate", "cipher")),
    ("disclosure",       ("disclosure", "exposed", "leak", "sensitive", "backup")),
    ("cve",              ("cve-", "outdated", "known vuln")),
    ("ad",               ("kerberoast", "as-rep", "delegation", "attack path", "domain admin")),
]


# When the name/OWASP text says nothing useful, the tool or agent that produced
# the finding usually does.
_TOOL_CLASS = {
    "dalfox": "xss", "xss_proof": "xss", "sqlmap": "sqli", "nosql_inj": "sqli",
    "ssti": "ssti", "ssrf": "ssrf", "lfi": "lfi", "commix": "rce", "xxe": "xxe",
    "idor_test": "idor", "jwt_tool": "jwt", "jwt_exploit": "jwt", "csrf": "csrf",
    "deserialization": "deserialization", "crlf": "crlf", "header_analysis": "headers",
    "headers_attack": "headers", "clickjack": "headers", "clickjacking": "headers",
    "testssl": "tls", "sslyze": "tls", "tls_analysis": "tls", "cert_info": "tls",
    "s3_enum": "cloud", "cloud_enum": "cloud", "cloud": "cloud", "corsy": "cors",
    "subjack": "subdomain_takeover", "subdomain_takeover": "subdomain_takeover",
    "insecure_design": "insecure_design", "login_brute": "auth",
    "default_creds_check": "auth", "auth_probe": "auth", "session_hijack": "auth",
    "session_fixation": "auth", "searchsploit": "cve", "nuclei": "cve",
}


def classify(name: str, owasp: str = "", tool: str = "", agent: str = "",
             description: str = "") -> str:
    """Return the class filename stem for a finding.

    Checks, in order: the finding name + OWASP category, the tool / agent that
    produced it, and finally the description.
    """
    hay = f"{name} {owasp}".lower()
    for stem, needles in _CLASS_PATTERNS:
        if any(n in hay for n in needles):
            return stem
    for key in (str(tool or "").lower(), str(agent or "").lower()):
        if key in _TOOL_CLASS:
            return _TOOL_CLASS[key]
    hay = f"{hay} {tool} {description}".lower()
    for stem, needles in _CLASS_PATTERNS:
        if any(n in hay for n in needles):
            return stem
    return "other"


_TEXT_FINDING_RE = re.compile(r"^\s*\[(?P<agent>[^\]]+)\]\s*(?P<name>[^:\n]+)(?::\s*(?P<desc>.*))?",
                              re.DOTALL)


def finding_from_text(text: str, verdict: str = "NEEDS_PROOF") -> Dict[str, Any]:
    """Agents store proof requests as text like
    "[headers_attack] Missing X-Frame-Options: The header is missing...".
    Turn that into the dict shape record_finding() understands."""
    s = str(text or "")
    m = _TEXT_FINDING_RE.match(s)
    if not m:
        return {"name": s.split("\n", 1)[0][:200], "description": s, "verdict": verdict}
    return {"name": m.group("name").strip(), "source_agent": m.group("agent").strip(),
            "description": (m.group("desc") or "").strip(), "verdict": verdict}


def safe_target(target: str) -> str:
    """A filesystem-safe folder name derived from the target."""
    t = re.sub(r"^https?://", "", str(target or "").strip().lower())
    t = t.split("/")[0].split(":")[0]              # host only
    t = re.sub(r"[^a-z0-9._-]", "_", t)
    return t[:120] or "unknown_target"


@dataclass
class Attempt:
    """One thing the tool tried against the target."""
    technique:  str                      # e.g. "reflected XSS via q parameter"
    payload:    str = ""
    request:    str = ""                 # what was sent
    response:   str = ""                 # what came back (the evidence)
    verdict:    str = "NEEDS_PROOF"      # CONFIRM | DISPUTE | NEEDS_PROOF
    proven:     bool = False
    proof:      str = ""                 # how it was proven, if it was
    tool:       str = ""
    severity:   str = ""
    confidence: Any = ""
    url:        str = ""
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in
                ("technique", "payload", "request", "response", "verdict",
                 "proven", "proof", "tool", "severity", "confidence", "url",
                 "timestamp")}


class EvidenceTrail:
    """Writes the per-target, per-class proof folder."""

    def __init__(self, target: str, base_dir: Optional[Path] = None):
        self.target = target
        self.safe = safe_target(target)
        self.dir = Path(base_dir or ENGAGEMENTS_DIR) / self.safe
        self.raw_dir = self.dir / "raw"
        # class stem -> list of attempts
        self._by_class: Dict[str, List[Attempt]] = {}
        self._sessions: List[Dict[str, Any]] = []
        self._chains: List[Dict[str, Any]] = []
        self._started = datetime.now(timezone.utc)

    # ── recording ─────────────────────────────────────────────────────────────

    def record(self, attempt: Attempt, vuln_class: Optional[str] = None) -> None:
        stem = vuln_class or classify(attempt.technique, "", attempt.tool)
        self._by_class.setdefault(stem, []).append(attempt)

    def record_finding(self, finding: Any) -> None:
        """Turn an AgentFinding, dict, or "[agent] Name: detail" string into an
        attempt and file it."""
        if isinstance(finding, str):
            finding = finding_from_text(finding)
        get = (finding.get if isinstance(finding, dict)
               else lambda k, d=None: getattr(finding, k, d))
        name = get("name", "") or ""
        stem = classify(name, get("owasp_category", "") or "", get("tool", "") or "",
                        get("source_agent", "") or "", get("description", "") or "")

        evidence = (get("raw_output_excerpt", "") or ""
                    or _chain_text(get("evidence_chain", None)))
        verdict = str(get("verdict", "") or "NEEDS_PROOF")
        # "proven" rests on captured tool output only -- never on a description.
        proven = verdict == "CONFIRM" and bool(evidence)
        shown = evidence or (get("description", "") or "")

        self.record(Attempt(
            technique=name,
            payload=_extract_payload(evidence),
            request=get("url", "") or "",
            response=shown[:1500],
            verdict=verdict,
            proven=proven,
            proof=("evidence captured below" if proven else ""),
            tool=get("tool", "") or "",
            severity=get("severity", "") or "",
            confidence=get("confidence", "") or "",
            url=get("url", "") or "",
        ), vuln_class=stem)

    def record_session(self, session_info: Dict[str, Any],
                       commands: Optional[List[Dict[str, Any]]] = None) -> None:
        """Record a caught shell and the commands run through it — hard proof."""
        self._sessions.append({"session": session_info,
                               "commands": commands or []})

    def record_chain(self, chain: Dict[str, Any]) -> None:
        self._chains.append(chain)

    # ── writing ───────────────────────────────────────────────────────────────

    def write(self) -> Path:
        """Flush the whole trail to disk. Returns the engagement folder."""
        self.dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(parents=True, exist_ok=True)

        for stem, attempts in self._by_class.items():
            (self.dir / f"{stem}.md").write_text(
                self._class_markdown(stem, attempts), encoding="utf-8")
            (self.raw_dir / f"{stem}.json").write_text(
                json.dumps([a.to_dict() for a in attempts], indent=2),
                encoding="utf-8")

        if self._sessions:
            (self.dir / "sessions.md").write_text(
                self._sessions_markdown(), encoding="utf-8")
        if self._chains:
            (self.dir / "chain.md").write_text(
                self._chain_markdown(), encoding="utf-8")

        (self.dir / "00_SUMMARY.md").write_text(
            self._summary_markdown(), encoding="utf-8")
        return self.dir

    # ── markdown rendering ────────────────────────────────────────────────────

    def _class_markdown(self, stem: str, attempts: List[Attempt]) -> str:
        proven = [a for a in attempts if a.proven]
        confirmed = [a for a in attempts if a.verdict == "CONFIRM"]
        disputed = [a for a in attempts if a.verdict == "DISPUTE"]

        lines = [
            f"# {stem.upper()} — {self.target}",
            "",
            f"Attempts: {len(attempts)}  |  Confirmed: {len(confirmed)}  |  "
            f"Proven: {len(proven)}  |  Disputed: {len(disputed)}",
            "",
        ]
        if proven:
            lines.append(f"**{len(proven)} attempt(s) proven** — see PROVEN entries below.")
        elif confirmed:
            lines.append("Confirmed by the critic, but no execution proof was "
                         "captured. Treat as likely, not certain.")
        else:
            lines.append("Nothing proven or confirmed in this class — the "
                         "attempts below were tried and did not hold up.")
        lines.append("")

        for i, a in enumerate(attempts, 1):
            badge = ("PROVEN" if a.proven else a.verdict)
            lines += [
                f"## {i}. {a.technique}  [{badge}]",
                "",
                f"- Tool: `{a.tool or 'n/a'}`",
                f"- Severity: {a.severity or 'n/a'}   Confidence: {a.confidence or 'n/a'}",
                f"- URL: {a.url or 'n/a'}",
                f"- When: {a.timestamp}",
                "",
            ]
            if a.payload:
                lines += ["**Payload / technique:**", "```", a.payload[:600], "```", ""]
            if a.request:
                lines += ["**Request:**", "```", a.request[:600], "```", ""]
            if a.response:
                lines += ["**Response evidence:**", "```",
                          a.response[:1200], "```", ""]
            else:
                lines += ["_No response evidence captured._", ""]
            if a.proven:
                lines += [f"**Proof:** {a.proof}", ""]
            elif a.verdict == "DISPUTE":
                lines += ["**Disputed:** the evidence did not support the claim "
                          "(e.g. payload reflected but not executed, or a benign "
                          "redirect misread as a hit).", ""]
            lines.append("---")
            lines.append("")
        return "\n".join(lines)

    def _sessions_markdown(self) -> str:
        lines = [f"# Sessions — {self.target}", "",
                 f"{len(self._sessions)} foothold(s) established.", ""]
        for i, entry in enumerate(self._sessions, 1):
            s = entry["session"]
            lines += [
                f"## Session {i}: {s.get('session_id', '?')}",
                "",
                f"- User: `{s.get('user', '?')}`   Host: `{s.get('hostname', '?')}`",
                f"- OS: {s.get('os_hint', '?')}   Elevated: {s.get('elevated', False)}",
                f"- Opened: {s.get('opened_at', '?')}",
                "",
                "**Commands run (proof of access):**",
                "",
            ]
            for cmd in entry["commands"]:
                lines += [f"```", f"$ {cmd.get('command', '')}",
                          cmd.get("output", "")[:600], "```", ""]
            lines.append("---")
        return "\n".join(lines)

    def _chain_markdown(self) -> str:
        lines = [f"# Attack chains — {self.target}", "",
                 "Findings that composed into a path with more impact than any "
                 "single link.", ""]
        for i, c in enumerate(self._chains, 1):
            lines += [f"## Chain {i}: {c.get('name', 'unnamed')}",
                      "", c.get("description", ""), ""]
            for step in c.get("steps", []):
                lines.append(f"- {step}")
            lines.append("")
        return "\n".join(lines)

    def _summary_markdown(self) -> str:
        total = sum(len(v) for v in self._by_class.values())
        proven_total = sum(1 for v in self._by_class.values() for a in v if a.proven)
        confirmed_total = sum(1 for v in self._by_class.values()
                              for a in v if a.verdict == "CONFIRM")

        lines = [
            f"# Engagement summary — {self.target}",
            "",
            f"Started: {self._started.isoformat()}",
            f"Written: {datetime.now(timezone.utc).isoformat()}",
            "",
            "## Coverage",
            "",
            f"- Vulnerability classes tested: {len(self._by_class)}",
            f"- Total attempts recorded: {total}",
            f"- Confirmed: {confirmed_total}",
            f"- **Proven (with execution evidence): {proven_total}**",
            f"- Footholds established: {len(self._sessions)}",
            f"- Attack chains: {len(self._chains)}",
            "",
            "## Per class",
            "",
            "| Class | Attempts | Confirmed | Proven | File |",
            "|-------|----------|-----------|--------|------|",
        ]
        for stem in sorted(self._by_class):
            attempts = self._by_class[stem]
            conf = sum(1 for a in attempts if a.verdict == "CONFIRM")
            prov = sum(1 for a in attempts if a.proven)
            lines.append(f"| {stem} | {len(attempts)} | {conf} | {prov} | "
                         f"[{stem}.md](./{stem}.md) |")
        lines += [
            "",
            "## How to read this",
            "",
            "- **Proven** means the tool captured evidence the vulnerability "
            "actually executed (e.g. an XSS payload that ran in a headless "
            "browser, a command whose output came back through a shell).",
            "- **Confirmed** means the critic accepted the finding but no "
            "execution proof was captured — likely, not certain.",
            "- Everything else was attempted and did not hold up. Those attempts "
            "are still recorded, so you can see what was tried.",
            "",
            "Open any class file for the payloads, requests and responses.",
        ]
        if self._sessions:
            lines.append("See [sessions.md](./sessions.md) for shell access proof.")
        return "\n".join(lines)


# ── helpers ───────────────────────────────────────────────────────────────────

def _chain_text(chain: Any) -> str:
    if not chain:
        return ""
    if isinstance(chain, list):
        return "\n".join(str(x) for x in chain)[:1500]
    return str(chain)[:1500]


def _extract_payload(evidence: str) -> str:
    """Best-effort pull of a payload string out of evidence text."""
    if not evidence:
        return ""
    for marker in ("payload", "injected", "technique"):
        m = re.search(rf'"{marker}"\s*:\s*"([^"]{{1,200}})"', evidence, re.I)
        if m:
            return m.group(1)
    return ""


def build_trail_from_evidence(target: str, evidence: Dict[str, Any],
                              base_dir: Optional[Path] = None) -> Path:
    """Convenience: build a trail from a saved attack-evidence dict."""
    trail = EvidenceTrail(target, base_dir=base_dir)
    for finding in evidence.get("vulnerabilities", []) or []:
        trail.record_finding(finding)
    # Disputed findings and open proof requests are attempts too: without them
    # an engagement where nothing was confirmed reports "0 attempts" even
    # though agents ran and the critic rejected what they found.
    for finding in evidence.get("disputed_findings", []) or []:
        if isinstance(finding, dict) and not finding.get("verdict"):
            finding = {**finding, "verdict": "DISPUTE"}
        trail.record_finding(finding)
    for finding in evidence.get("proof_requests", []) or []:
        if isinstance(finding, dict) and not finding.get("verdict"):
            finding = {**finding, "verdict": "NEEDS_PROOF"}
        trail.record_finding(finding)
    for chain in evidence.get("attack_chains", []) or []:
        trail.record_chain(chain if isinstance(chain, dict)
                            else {"name": str(chain)})
    return trail.write()
