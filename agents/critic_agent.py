"""
CriticAgent — adversarial reviewer of every finding before it enters memory.

Protocol: CONFIRM / DISPUTE / NEEDS_PROOF.
Final confidence = agent(40%) x critic(60%).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

import system_map as sm
from agents.base_agent import AgentFinding, BaseAgent, extract_json
from confidence import CONFIRM_FLOOR, ConfidenceEngine, llm_fallback_confidence
from utils import SEVERITY_ORDER

# MIN_CONFIRM_CONFIDENCE is the 0-100 twin of confidence.py's CONFIRM_FLOOR.
# The floor math itself lives in the ConfidenceEngine (single source of truth);
# this constant is kept only because the downgrade message quotes it.
MIN_CONFIRM_CONFIDENCE = int(round(CONFIRM_FLOOR * 100))  # == 50

# Minimum length of a raw tool-output excerpt before we treat it as genuine
# evidence rather than noise ('{}', '[]', an empty string, etc.).
MIN_EVIDENCE_LEN = 8

# Tools that never produce real artifact evidence on their own (pure LLM
# inference / recon passthrough). Findings stamped with these cannot be
# CONFIRM regardless of what the reviewing LLM says.
INFERENCE_TOOLS = {"", "analysis", "recon", "llm", "heuristic"}

# ── evidence QUALITY check ────────────────────────────────────────────────────
# The gate is not just "is there a non-empty excerpt"; it must be "does the
# excerpt look like ARTIFACT data a tool actually produced" rather than an
# LLM-written summary sentence. Findings like
#   "Missing security headers: strict-transport-security, content-security-policy, ..."
# carry 150+ chars yet are narration, not evidence, and used to slip past the
# length-only gate (the certifiedhacker.com 'Missing Security Headers' HIGH
# CONFIRM and the admin.html 'exposed auth endpoint' FP).

_NOISE_TOKENS = {
    "http", "https", "www", "com", "org", "net", "io",
    "url", "urls", "path", "paths", "status", "code", "http_status",
    "http_response", "response", "request", "the", "and", "for", "are",
    "was", "were", "has", "have", "with", "from", "that", "this",
    "these", "those", "not", "but", "page", "pages", "found", "list",
}

# claim-verb prose that marks an LLM-written sentence, not tool output
_NARRATION_MARKERS = (
    "identified", "detected", "missing", "possible", "likely", "exposed",
    "presents", "contains", "listed", "review", "check", "recommend",
)

_HEADER_LINE_RE = re.compile(r"(?m)^[A-Za-z][A-Za-z0-9_-]*:\s*\S")
_STATUS_MARK_RE = re.compile(r"\b(?:status|http_code|http-status)\b\s*[:=]\s*\d{3}", re.I)
_PROOF_MARK_RE = re.compile(
    r"\b(?:nonce|proof|screenshot|executed|reflected|succeeded|exploit|matched|recorded)\b", re.I)
_QUOTED_TOKEN_RE = re.compile(r'"[^"\n]{6,}"')
_HEX_BLOB_RE = re.compile(r"\\x[0-9a-f]{2}", re.I)
_TAGGED_CHAIN_RE = re.compile(r"(?m)^\[\s*\w[\w._-]*\s*\]\s*\S")


def _substantive_excerpt(raw: Any) -> bool:
    """True when `raw` looks like real artifact/response data that a tool
    emitted, False when it is prose or a bare identifier list (narration).

    This is intentionally conservative: borderline text is treated as
    NOT substantive so the LLM-leaning critic never gets to CONFIRM a
    finding whose only 'evidence' is its own sentence.
    """
    s = str(raw or "").strip()
    if len(s) < MIN_EVIDENCE_LEN:
        return False
    low = s.lower()

    # Artifact signals: header blocks, structured JSON, quoted payloads,
    # hex blobs, explicit status rows, tool-tagged chain entries, proof
    # vocabulary, or multi-line logs/attempt records.
    if _HEADER_LINE_RE.search(s):
        return True
    try:
        obj = json.loads(s)
        vals = obj if isinstance(obj, list) else (
            list(obj.values()) if isinstance(obj, dict) else [])
        if any(v is not None and v != "" and v != [] and v != {} for v in vals):
            return True
    except (TypeError, ValueError, AttributeError):
        pass
    if _QUOTED_TOKEN_RE.search(s):
        return True
    if _HEX_BLOB_RE.search(s):
        return True
    if _STATUS_MARK_RE.search(low):
        return True
    if _PROOF_MARK_RE.search(low):
        return True
    if _TAGGED_CHAIN_RE.search(s):
        return True
    if len([ln for ln in s.splitlines() if ln.strip()]) >= 3:
        return True

    # Narration / flat identifier lists are NOT artifact evidence.
    if any(marker in low for marker in _NARRATION_MARKERS):
        return False
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9_.-]{2,}", low)
    if len([w for w in words if w not in _NOISE_TOKENS]) < 3:
        return False
    return True


CRITIC_SYSTEM = """You are the CriticAgent for CyberSwarm — a skeptical security reviewer.
You examine a finding from another agent and determine if it is real. You are
adversarial: you actively look for false-positive explanations.

Answer:
1. Is the evidence sufficient to confirm this vulnerability?
2. What are the most likely false-positive explanations?
3. Does the raw output actually prove the claim, or just suggest it?
4. What additional proof would raise your confidence?

Output ONLY JSON:
{
  "verdict": "CONFIRM|DISPUTE|NEEDS_PROOF",
  "adjusted_confidence": <0-100>,
  "critique": "<2-3 sentences>",
  "false_positive_reasons": ["..."],
  "proof_needed": "<what would confirm this; empty if CONFIRM>"
}"""

CRITIC_BATCH_SYSTEM = """You are the CriticAgent for CyberSwarm — a skeptical security reviewer.
You examine MULTIPLE findings from one agent in a single pass. For each finding
decide the verdict. You are adversarial: you actively look for false-positive
explanations.

Verdict rules:
- CONFIRM: the finding's own evidence directly proves it. This includes live
  response evidence such as an HTTP 401/403 reply (auth IS enforced), a
  publicly listable bucket (`publicly_listable: true` / bucket listing
  succeeded), an explicit response header or status code that IS the finding,
  or a concrete vulnerable response. CONFIRM does not require exploiting data.
- NEEDS_PROOF: the claim is plausible but the raw output only suggests it and
  the false-positive explanation is at least as likely.
- DISPUTE: the evidence contradicts the claim, or a false positive is near-certain.

Findings carry "independent_sources": the number of independent tool outputs
behind the claim. Multiple independent sources strengthen a CONFIRM; a single
suggestive output should tend toward NEEDS_PROOF unless its own evidence is
direct.

For each finding output ONE review object. The "index" field MUST equal the
input finding's "index" so reviews map back exactly.

Output ONLY JSON:
{
  "reviews": [
    {
      "index": <input index>,
      "verdict": "CONFIRM|DISPUTE|NEEDS_PROOF",
      "adjusted_confidence": <0-100>,
      "critique": "<1-2 sentences>",
      "false_positive_reasons": ["..."],
      "proof_needed": "<what would confirm this; empty if CONFIRM>"
    }
  ]
}"""


class CriticAgent(BaseAgent):
    agent_name = "critic"

    def __init__(self, model_client, confidence_engine: ConfidenceEngine | None = None):
        super().__init__(model_client)
        self.engine = confidence_engine or ConfidenceEngine()

    def gate_verdict(self, verdict: str, agent_conf: Any,
                     critic_score: Any) -> tuple[int, str]:
        """Blend agent and critic scores and apply the CONFIRM floor gate.

        A CONFIRM verdict with a low blended confidence is a contradiction:
        "the evidence proves this" while "but I'm not very sure". If that
        passed straight through, MemoryAgent would store it as a real
        vulnerability indistinguishable from a CONFIRM at confidence 95.
        So a CONFIRM whose blended confidence is below the floor is
        downgraded to NEEDS_PROOF -- only verdicts the critic actually
        stands behind become confirmed vulnerabilities.
        """
        final_conf = int(round(self.engine.final_confidence(agent_conf, critic_score) * 100))
        final_conf = max(0, min(100, final_conf))
        v = str(verdict or "").upper()
        if v == "CONFIRM" and final_conf < MIN_CONFIRM_CONFIDENCE:
            return final_conf, "NEEDS_PROOF"
        return final_conf, v

    @staticmethod
    def has_real_evidence(f) -> bool:
        """Deterministic check that a finding carries genuine tool evidence,
        not just LLM narration.

        True iff it has a SUBSTANTIVE evidence_chain OR a SUBSTANTIVE raw
        excerpt OR 2+ independent tool sources. 'Substantive' means the text
        looks like tool artifact data (header blocks, structured JSON, payloads,
        status rows), not a claim-verb sentence the agent wrote about its own
        finding.
        """
        chain = getattr(f, "evidence_chain", None) or []
        if chain:
            text = "\n".join(str(x) for x in chain if x is not None)
            if _substantive_excerpt(text):
                return True
        raw = str(getattr(f, "raw_output_excerpt", "") or "").strip()
        if _substantive_excerpt(raw):
            return True
        return int(getattr(f, "independent_sources", 1) or 1) >= 2

    @staticmethod
    def calibrate_severity(name: str, severity: str) -> str:
        """Deterministic severity calibration: impact, not agent ambition.

        Header/clickjacking absence and bare 'path exists' observations are
        posture notes — they must not inflate the engagement risk to HIGH
        (the certifiedhacker.com 'Missing Security Headers' HIGH CONFIRM was
        a genuinely-missing header set, i.e. LOW). Real exploitation classes
        (SQLi, XSS, RCE, SSTI, ...) pass through untouched.
        """
        low_cap_hints = (
            "missing security header", "strict-transport-security",
            "content-security-policy", "x-content-type-options", "x-frame-options",
            "referrer-policy", "permissions-policy", "x-xss-protection",
            "clickjack", "frame-ancestors", "cookie flag", "session cookie",
            "set-cookie", "samesite",
            "server header disclosure",
        )
        info_cap_hints = (
            "fuzzed path", "login page exposed", "auth paths enforce",
            "authentication paths identified", "exposed authentication",
            "admin panel exposed", "admin.html", "default page",
            "server disclosure",
        )
        nm = str(name or "").lower()
        orig = str(severity or "INFO").upper()
        if orig not in SEVERITY_ORDER:
            orig = "INFO"
        idx = SEVERITY_ORDER.index(orig)
        if any(h in nm for h in info_cap_hints):
            idx = min(idx, SEVERITY_ORDER.index("INFO"))
        if any(h in nm for h in low_cap_hints):
            idx = min(idx, SEVERITY_ORDER.index("LOW"))
        return SEVERITY_ORDER[idx]

    def calibrate_finding(self, f) -> None:
        """Apply severity calibration onto a finding (marks why it changed)."""
        capped = self.calibrate_severity(
            str(getattr(f, "name", "") or ""),
            str(getattr(f, "severity", "INFO") or "INFO"))
        orig = str(getattr(f, "severity", "INFO") or "INFO").upper()
        if capped != orig:
            f.severity = capped
            if f.description and "[severity]" not in f.description:
                f.description += (f"\n[severity] calibrated {orig} -> {capped}: "
                                  f"posture/impact, not exploitable risk.")

    def evidence_gate(self, f) -> str | None:
        """Run before AND after LLM review. Returns a forced verdict override
        (currently only 'NEEDS_PROOF') when the findings' own evidence cannot
        possibly support a CONFIRM, or None to let the reviewing LLM decide.

        Two deterministic rules:
          1. pure-inference findings (tool='analysis'/'recon'/...) with no
             evidence are NEVER provable by this agent -> NEEDS_PROOF.
          2. any finding without real tool evidence cannot be CONFIRM,
             regardless of severity or LLM opinion -> NEEDS_PROOF.
        """
        if len(str(f.tool or "").strip()) == 0:
            return "NEEDS_PROOF" if not CriticAgent.has_real_evidence(f) else None
        if str(f.tool).lower() in INFERENCE_TOOLS:
            return "NEEDS_PROOF" if not CriticAgent.has_real_evidence(f) else None
        if not CriticAgent.has_real_evidence(f):
            return "NEEDS_PROOF"
        return None

    @staticmethod
    def _downgrade_to_needs_proof(f: "AgentFinding", reason: str) -> None:
        """Deterministically force a finding to NEEDS_PROOF with a low final
        confidence. Uses the established offline-fallback confidence so the
        value is a single, consistent constant; it is below the CONFIRM floor,
        so nothing contradictory survives."""
        f.critic_score = 0
        f.final_confidence = int(round(llm_fallback_confidence() * 100))
        f.verdict = "NEEDS_PROOF"
        if reason not in f.description:
            f.description = (f"{f.description}\n[EVIDENCE GATE]: {reason}".strip()
                             if f.description else f"[EVIDENCE GATE]: {reason}")
        f.false_positive_risk = "HIGH"

    @staticmethod
    def self_consistency_flags(verdict: str, adjusted_confidence: Any) -> List[str]:
        """Deterministic critic self-review: flag verdict/confidence conflicts."""
        try:
            conf = max(0, min(100, int(round(float(adjusted_confidence)))))
        except (TypeError, ValueError):
            conf = 50
        v = str(verdict or "").upper()
        flags: List[str] = []
        if v == "CONFIRM" and conf < MIN_CONFIRM_CONFIDENCE:
            flags.append("CONFIRM contradicts low confidence")
        if v == "DISPUTE" and conf >= 85:
            flags.append("DISPUTE at high confidence warrants proof of the false positive")
        if v == "NEEDS_PROOF" and conf >= 90:
            flags.append("NEEDS_PROOF at high confidence warrants an active proof step")
        return flags

    def _apply_review(self, finding: AgentFinding, result: Dict[str, Any]) -> None:
        """Apply one parsed review dict onto a finding (shared by batch + single)."""
        if not isinstance(result, dict):
            return
        try:
            critic_score = int(result.get("adjusted_confidence", finding.confidence))
        except (TypeError, ValueError):
            critic_score = finding.confidence
        critic_score = max(0, min(100, critic_score))
        finding.critic_score = critic_score
        verdict = str(result.get("verdict", "NEEDS_PROOF")).upper()
        if verdict not in ("CONFIRM", "DISPUTE", "NEEDS_PROOF"):
            verdict = "NEEDS_PROOF"
        final_conf, gated = self.gate_verdict(verdict, finding.confidence, critic_score)
        finding.final_confidence = final_conf

        if gated != verdict:
            # Contradiction guard (see gate_verdict): the low-confidence
            # CONFIRM is still visible in proof_requests, just not counted
            # as confirmed.
            finding.description += (
                f"\n[CRITIC]: verdict downgraded {verdict} -> NEEDS_PROOF "
                f"(final_confidence={finding.final_confidence} < {MIN_CONFIRM_CONFIDENCE} floor)")

        finding.verdict = gated
        critique = str(result.get("critique", "")).strip()
        if critique:
            finding.description += f"\n[CRITIC]: {critique}"
        proof = str(result.get("proof_needed", "")).strip()
        if proof and finding.verdict != "CONFIRM":
            finding.description += f"\n[PROOF NEEDED]: {proof}"
        # Deterministic override: a CONFIRM can never survive without real
        # tool evidence, whatever the reviewing LLM wanted.
        if finding.verdict == "CONFIRM" and self.evidence_gate(finding) == "NEEDS_PROOF":
            self._downgrade_to_needs_proof(
                finding, "CONFIRM rejected in evidence gate: no real tool output "
                         "(empty evidence_chain/excerpt) behind the claim.")

    def review_finding(self, finding: AgentFinding,
                       system_map: Dict[str, Any]) -> AgentFinding:
        self.calibrate_finding(finding)
        if self.evidence_gate(finding) == "NEEDS_PROOF":
            self._downgrade_to_needs_proof(
                finding, "No real tool output behind this finding; cannot CONFIRM "
                         "(deterministic evidence gate).")
            return finding
        ctx = sm.compress_for_llm(system_map, max_tech=5, max_paths=8)
        user = (
            "Finding to review:\n```json\n"
            f"{json.dumps(finding.to_dict(), indent=2)}\n```\n\n"
            "Recon context:\n```json\n"
            f"{json.dumps(ctx, indent=2)}\n```"
        )
        result = self._llm_json(CRITIC_SYSTEM, user, temperature=0.1)

        if result:
            self._apply_review(finding, result)
        else:
            # LLM unavailable -> conservative NEEDS_PROOF with a deterministic
            # low confidence, so unverified findings never masquerade as
            # confirmed vulnerabilities.
            finding.verdict = "NEEDS_PROOF"
            finding.critic_score = finding.confidence
            finding.final_confidence = int(round(llm_fallback_confidence() * 100))
        return finding

    def review_batch(self, findings: List[AgentFinding],
                     system_map: Dict[str, Any],
                     use_gate: bool = True) -> Dict[str, List[AgentFinding]]:
        """Review every finding for one agent in a SINGLE LLM call.

        use_gate=False runs the identical batch path with the deterministic
        evidence gate disabled -- the clean single-variable ablation for the
        gate (same prompt, same batching, same temperature; only the gate
        differs). Default True preserves deployed behaviour exactly.

        Fallback: if the model returns a malformed/partial batch (or is down),
        the missing findings are reviewed one-by-one and any verified reviews
        are still applied. This keeps the 1-call-per-agent speed win without
        ever losing a finding to a JSON parse failure.
        """
        buckets: Dict[str, List[AgentFinding]] = {
            "confirmed": [], "disputed": [], "needs_proof": []}
        if not findings:
            return buckets

        def _bucket_of(f: AgentFinding) -> str:
            verdict_bucket = {"CONFIRM": "confirmed", "DISPUTE": "disputed",
                              "NEEDS_PROOF": "needs_proof"}
            return verdict_bucket.get((f.verdict or "NEEDS_PROOF").upper(), "needs_proof")

        # Deterministic evidence gate runs BEFORE the LLM: findings with no
        # real tool evidence cannot be confirmed by any amount of model
        # enthusiasm, so don't pay the LLM to bless them (nor let it override
        # the gate in the rare all-gated case).
        gated = []                     # indexes skipped from LLM review
        for i, f in enumerate(findings):
            self.calibrate_finding(f)
            if use_gate and self.evidence_gate(f) == "NEEDS_PROOF":
                self._downgrade_to_needs_proof(
                    f, "No real tool output behind this finding; cannot CONFIRM "
                       "(deterministic evidence gate).")
                gated.append(i)
        if len(gated) == len(findings):
            for f in findings:
                buckets[_bucket_of(f)].append(f)
            return buckets

        ctx = sm.compress_for_llm(system_map, max_tech=8, max_paths=12)
        findings_ctx = [{"index": i, **f.to_dict()} for i, f in enumerate(findings)
                        if i not in gated]
        user = (
            f"Review these {len(findings_ctx)} findings in one pass. The 'index' of each "
            "finding must be echoed back in its review.\n\nFindings:\n```json\n"
            f"{json.dumps(findings_ctx, indent=2)}\n```\n\nRecon context:\n```json\n"
            f"{json.dumps(ctx, indent=2)}\n```"
        )
        result = self._llm_json(CRITIC_BATCH_SYSTEM, user, temperature=0.1)

        reviews: List[Dict[str, Any]] = []
        if result and isinstance(result.get("reviews"), list):
            reviews = [r for r in result["reviews"] if isinstance(r, dict)]

        # Always map reviews back to findings via the echoed 'index' field --
        # never assume the model returned them in input order, even when the
        # count happens to match. A same-count-but-reordered response used to
        # get zipped positionally here, silently attaching the wrong verdict
        # to the wrong finding.
        by_index: Dict[int, Dict[str, Any]] = {}
        for item in reviews:
            try:
                by_index[int(item.get("index", -1))] = item
            except (TypeError, ValueError):
                continue
        for i, f in enumerate(findings):
            if i in gated:
                buckets[_bucket_of(f)].append(f)
                continue
            item = by_index.get(i)
            if item is not None:
                self._apply_review(f, item)
            else:
                # missing/unmapped index -> per-finding fallback so no
                # finding is ever silently lost or mismatched
                self.review_finding(f, system_map)
            buckets[_bucket_of(f)].append(f)
        return buckets
