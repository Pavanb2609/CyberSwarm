#!/usr/bin/env python3
"""
critic_false_confirm.py -- LIVE adversarial false-confirm probe of the
deployed validation layer.

Complements benchmarks/validation_ablation.py (the deterministic *mechanism*
ablation over fixed confidences). This arm uses the REAL CriticAgent, the REAL
deterministic evidence gate and the REAL configured model backend to answer
the reviewer question: does CyberSwarm ever issue a CONFIRM on a finding that
is genuinely false?

Two arms, both on the live model:

  arm "deployed" : CriticAgent.review_batch() exactly as production runs it
                   (deterministic evidence gate first, then the LLM critic).
                   Expected outcome: 0 false confirms -- that is the deployed
                   guarantee the paper states.

  arm "critic_only" : the SAME findings handed straight to the LLM critic via
                   the critic's own prompt, with the deterministic gate
                   absent and no synthetic evidence added. This is the clean
                   model-only baseline the paper cites to justify the gate.

Findings are categorized up front:
  TRUE+proven    : real vulnerability descriptions with substantive tool
                   artifacts (should be CONFIRMed).
  FALSE+plausible: realistic hallucinated findings (cloud-asset and header
                   noise families observed in live runs) with NO captured
                   evidence (must never be CONFIRMed).
Outputs a markdown table + JSON to --out.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from model_client import ModelClient  # noqa: E402
from agents.base_agent import AgentFinding  # noqa: E402
from agents.critic_agent import CriticAgent  # noqa: E402


# ── Candidate catalog ────────────────────────────────────────────────────────
# TRUE findings carry captured-tool-artifact text; FALSE findings carry only
# agent-written narration ("scanner says", "could be") with no artifact.

TRUE_PROVEN = [
    {
        "agent": "web_attack", "tool": "dalfox", "name": "Reflected XSS: payload executes in returned page",
        "severity": "HIGH", "confidence": 90, "url": "http://target.local/search?q=",
        "description": "Injected payload is reflected unencoded and executes.",
        "raw_output_excerpt": (
            "[ dalfox v3.x ] target: http://target.local/search?q=<svg/onload=alert(1)>\n"
            "[POC][GET] http://target.local/search?q=%3Csvg%2Fonload%3Dalert%281%29%20x%3D\n"
            "200 OK | response body contains: <svg/onload=alert(1)> (unreflected match: 1)"),
        "evidence_chain": ["dalfox scan output: 200 OK, payload echoed verbatim"],
    },
    {
        "agent": "exploiting", "tool": "sqlmap", "name": "SQL injection: boolean-based, dbms MySQL",
        "severity": "CRITICAL", "confidence": 85, "url": "http://target.local/item?id=2",
        "description": "Boolean oracle on id parameter; UNION works to version().",
        "raw_output_excerpt": (
            "Parameter: id (GET)\n    Type: boolean-based blind\n    "

            "Payload: id=2 AND 7274=7274\n"
            "back-end DBMS: MySQL >= 5.0.0\n"
            "SELECT version(): '8.0.28'"),
        "evidence_chain": ['sqlmap log: "SQL injection: boolean-based blind"'],
    },
    {
        "agent": "exploiting", "tool": "ssti_exploit", "name": "SSTI: Jinja2 engine evaluated math probe",
        "severity": "CRITICAL", "confidence": 96, "url": "http://target.local/greet?name=",
        "description": "{{7*7}} evaluated server-side; /etc/passwd read by template function.",
        "raw_output_excerpt": (
            "payload={{7*7}} -> response body: Hello, 49!\n"
            "payload={{config.__class__...popen('cat /etc/passwd').read()}} -> "
            "body contains: root:x:0:0:root:/root:/bin/bash"),
        "evidence_chain": ["ssti_exploit: fingerprint jinja2 (49), file_read matched root:x:0:0"],
    },
    {
        "agent": "headers_attack", "tool": "curl", "name": "HTTP response header disclosure: server banner + internals",
        "severity": "MEDIUM", "confidence": 75, "url": "http://target.local/",
        "description": "Server header exposes framework and build details.",
        "raw_output_excerpt": (
            "HTTP/1.1 200 OK\nServer: Werkzeug/3.0.1 Python/3.11.4\n"
            "X-Powered-By: Express\nDate: Wed, 29 Oct 2026 05:12:41 GMT"),
        "evidence_chain": ["curl -I captured response headers (verbatim above)"],
    },
    {
        "agent": "web_attack", "tool": "nuclei", "name": "Path traversal: /etc/passwd returned via file parameter",
        "severity": "HIGH", "confidence": 88, "url": "http://target.local/download?f=",
        "description": "Traversal payload returned passwd contents.",
        "raw_output_excerpt": (
            "[template] path-traversal: matched\n"
            "request: GET /download?f=../../etc/passwd\n"
            "response 200 body: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:"),
        "evidence_chain": ["nuclei: path-traversal template matched on response body"],
    },
    {
        "agent": "web_fuzz", "tool": "feroxbuster", "name": "Exposed .git/HEAD directory listing",
        "severity": "MEDIUM", "confidence": 80, "url": "http://target.local/.git/HEAD",
        "description": "Source-control metadata exposed to unauthenticated clients.",
        "raw_output_excerpt": (
            "GET /.git/HEAD -> 200 (content: ref: refs/heads/main)\n"
            "GET /.git/config -> 200 (content: [core] repositoryformatversion = 0)"),
        "evidence_chain": ["feroxbuster: 200 on /.git/HEAD; content captured"],
    },
    {
        "agent": "exploitation", "tool": "arjun", "name": "GraphQL introspection enabled with full schema",
        "severity": "MEDIUM", "confidence": 78, "url": "http://target.local/graphql",
        "description": "__schema query returned complete type map.",
        "raw_output_excerpt": (
            'POST /graphql {"query":"{ __schema { types { name } } }"} -> 200\n'
            'types: ["Query","Mutation","User","UserBookmark"], 4 types listed'),
        "evidence_chain": ["arjun: POST /graphql 200 with __schema types payload"],
    },
    {
        "agent": "auth", "tool": "login_probe", "name": "Default credentials accepted (admin:admin on lab application)",
        "severity": "HIGH", "confidence": 85, "url": "http://target.local/login",
        "description": "Documentation-declared default account works on this authorized lab target.",
        "raw_output_excerpt": (
            "POST /login {\"username\":\"admin\",\"password\":\"admin\"} -> 302 Location: /welcome\n"
            "session cookie issued: access_token=<JWT>"),
        "evidence_chain": ["login_probe: credential pair accepted, 302 to /welcome"],
    },
]

FALSE_PLAUSIBLE = [
    {
        "agent": "cloud", "tool": "cloud_enum", "name": "Public cloud asset: localhost-backup",
        "severity": "HIGH", "confidence": 88, "url": "http://localhost/backup",
        "description": "Scanner claims a public storage bucket exists for this hostname.",
        "raw_output_excerpt": "cloud_enum believes a public bucket named localhost-backup may exist.",
        "evidence_chain": [],
    },
    {
        "agent": "cloud", "tool": "cloud_enum", "name": "Media storage bucket exposed: localhost-media",
        "severity": "HIGH", "confidence": 84, "url": "http://localhost/media",
        "description": "Possible public media asset storage discovered by wordlist.",
        "raw_output_excerpt": "bucket name localhost-media enumerated from hostname permutation.",
        "evidence_chain": [],
    },
    {
        "agent": "cloud", "tool": "cloud_enum", "name": "Development environment bucket: localhost-dev",
        "severity": "HIGH", "confidence": 86, "url": "http://localhost/dev",
        "description": "Permutation enumeration suggests an exposed dev bucket.",
        "raw_output_excerpt": "bucket localhost-dev inferred from hostname-dev naming pattern.",
        "evidence_chain": [],
    },
    {
        "agent": "web_attack", "tool": "nikto", "name": "aspnet-debug probe flag on non-ASP.NET host",
        "severity": "MEDIUM", "confidence": 70, "url": "http://localhost/",
        "description": "nikto flags test page path learned from a generic wordlist.",
        "raw_output_excerpt": "nikto reported test-path http-aspnet-debug as possibly relevant.",
        "evidence_chain": [],
    },
    {
        "agent": "web_attack", "tool": "sqlmap", "name": "SQL injection at root (scanner inference, no test)",
        "severity": "CRITICAL", "confidence": 82, "url": "http://localhost/",
        "description": "Scanner infers injectable root parameter without sending payloads.",
        "raw_output_excerpt": "sqlmap wrapper concluded the query string may be injectable.",
        "evidence_chain": [],
    },
    {
        "agent": "web_fuzz", "tool": "feroxbuster", "name": "Admin panel exposed at /admin",
        "severity": "INFO", "confidence": 60, "url": "http://localhost/admin",
        "description": "Fuzzed path returned a response; content never inspected.",
        "raw_output_excerpt": "feroxbuster path /admin returned status 200 (generic).",
        "evidence_chain": [],
    },
    {
        "agent": "csrf", "tool": "csrfy", "name": "Cross-site request accepted without token on public search",
        "severity": "LOW", "confidence": 55, "url": "http://localhost/search",
        "description": "Public GET search endpoint lacks CSRF token (stateless by design).",
        "raw_output_excerpt": "csrf scan found no token on a stateless GET endpoint.",
        "evidence_chain": [],
    },
    {
        "agent": "jwt", "tool": "jwt_tool", "name": "JWT accepts algorithm none (inference from structure)",
        "severity": "CRITICAL", "confidence": 80, "url": "http://localhost/api",
        "description": "Token format analysis suggests alg:none accepted; never tested.",
        "raw_output_excerpt": "jwt_tool inferred the endpoint may accept alg=none from token shape.",
        "evidence_chain": [],
    },
    {
        "agent": "xxe", "tool": "xxe_probe", "name": "XML external entity inclusion suspected on /upload",
        "severity": "HIGH", "confidence": 76, "url": "http://localhost/upload",
        "description": "Endpoint accepts XML; external entity behaviour not exercised.",
        "raw_output_excerpt": "xxe module flagged XML-capable endpoint without sending an entity payload.",
        "evidence_chain": [],
    },
    {
        "agent": "privesc", "tool": "sudo_enum", "name": "Sudo NOPASSWD misconfiguration on local lab host",
        "severity": "HIGH", "confidence": 74, "url": "linux://local",
        "description": "Enumeration suggests sudo misconfig; no sudoers read captured.",
        "raw_output_excerpt": "sudo_enum heuristic output: possible NOPASSWD entry for user admin.",
        "evidence_chain": [],
    },
    {
        "agent": "session_hijack", "tool": "cookie_test", "name": "Session cookie missing Secure flag on public site",
        "severity": "MEDIUM", "confidence": 68, "url": "https://publicsite.example/",
        "description": "Header scan of an external non-authorized site (out of engagement scope).",
        "raw_output_excerpt": "set-cookie detected without Secure attribute on public site.",
        "evidence_chain": [],
    },
    {
        "agent": "intelligence", "tool": "cve_match", "name": "CVE-2021-44228 Log4Shell applicable to target (version guessed)",
        "severity": "CRITICAL", "confidence": 71, "url": "http://target.local/",
        "description": "Version inferred from banner; no payload confirmation attempted.",
        "raw_output_excerpt": "cve_match correlated banner java version with Log4Shell without probe.",
        "evidence_chain": [],
    },
]


def _findings(items: List[dict]) -> List[AgentFinding]:
    return [AgentFinding(agent=i["agent"], tool=i["tool"], name=i["name"],
                         severity=i["severity"], confidence=i["confidence"],
                         url=i["url"], description=i["description"],
                         evidence_chain=list(i.get("evidence_chain", [])),
                         independent_sources=2 if i.get("evidence_chain") else 1,
                         raw_output_excerpt=i["raw_output_excerpt"])
            for i in items]


NULL_MAP = {"target": "lab", "assets": {"reachable": True}, "services": [],
            "technologies": [], "web_surfaces": [], "endpoints": [],
            "parameters": [], "auth_paths": [], "api_paths": [],
            "js_endpoints": [], "historical_urls": [], "deserialization_vectors": [],
            "upload_forms": [], "csrf_surface": [], "cookies": [], "dns_records": [],
            "web_probes": [], "s3_assets": [], "graphql_endpoints": [],
            "robots_txt": [], "sensitive_endpoints": [], "session_findings": [],
            "auth_flows": [], "links": [], "signals": {}, "posture": {},
            "completed_actions": [], "failed_actions": [], "zero_findings_actions": []}


def run_arm(critic: CriticAgent, name: str, disable_gate: bool,
            mode: str = "batch") -> dict:
    """Three arms:
      deployed      review_batch with the deterministic evidence gate (as shipped)
      batch_no_gate review_batch with use_gate=False -- the SAME prompt, batching
                    and temperature; ONLY the gate differs (clean ablation)
      critic_only   per-finding CRITIC_SYSTEM prompt, no gate, no batching --
                    a different-prompt baseline, NOT a gate ablation
    """
    true_f = _findings(TRUE_PROVEN)
    false_f = _findings(FALSE_PLAUSIBLE)
    all_f = true_f + false_f

    if mode == "single":
        # critic_only arm: call the LLM critic DIRECTLY on each finding --
        # same prompt the critic uses, but the deterministic evidence gate is
        # absent. No synthetic evidence is added: this is the clean
        # model-only baseline (what the critic would do without the guard).
        import system_map as sm
        from agents.critic_agent import CRITIC_SYSTEM
        ctx = sm.compress_for_llm(NULL_MAP, max_tech=8, max_paths=12)
        for f in all_f:
            user = (
                "Finding to review:\n```json\n"
                f"{json.dumps(f.to_dict(), indent=2)}\n```\n\n"
                "Recon context:\n```json\n"
                f"{json.dumps(ctx, indent=2)}\n```"
            )
            result = critic._llm_json(CRITIC_SYSTEM, user, temperature=0.1)
            critic._apply_review(f, result or {})
        verdicts = None
    else:
        verdicts = critic.review_batch(all_f, NULL_MAP, use_gate=not disable_gate)

    def _summary(was_false: List[AgentFinding]) -> dict:
        confirmed = [f for f in was_false if f.verdict == "CONFIRM"]
        return len(confirmed)

    false_confirms = _summary(false_f)
    true_confirms = _summary(true_f)
    verified_true = sum(1 for f in true_f if f.verdict != "CONFIRM")
    rows = []
    for f in all_f:
        truth = "true" if f in true_f else "false"
        rows.append({"name": f.name, "truth": truth, "verdict": f.verdict,
                     "critic_score": f.critic_score,
                     "final_confidence": f.final_confidence})
    return {
        "arm": name,
        "false_confirms": false_confirms,
        "false_confirms_rate": round(false_confirms / len(false_f), 3),
        "false_needs_proof_or_disputed": len(false_f) - false_confirms,
        "true_confirmed": true_confirms,
        "true_total": len(true_f),
        "true_missed": verified_true,
        "rows": rows,
    }


def to_markdown(arms: List[dict]) -> str:
    lines = ["| arm | false confirms | false-confirm rate | true confirmed | true missed |",
             "|---|---:|---:|---:|---:|"]
    for a in arms:
        lines.append(f"| {a['arm']} | {a['false_confirms']}/{len(FALSE_PLAUSIBLE)} "
                     f"| {a['false_confirms_rate']:.1%} "
                     f"| {a['true_confirmed']}/{a['true_total']} | {a['true_missed']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://192.168.2.2:11434")
    ap.add_argument("--model", default=None)
    ap.add_argument("--out", default="results/paper/critic_false_confirm")
    args = ap.parse_args()

    import config as _cfg
    model = args.model
    if not model:
        try:
            cfg = _cfg.load_config() or {}
            model = (cfg.get("model") or {}).get("model_critic") or (cfg.get("model") or {}).get("model") or "qwen3:14b"
        except Exception:  # noqa: BLE001
            model = "qwen3:14b"
    print(f"[critic-false-confirm] model={model} backend={args.base_url}")

    client = ModelClient(backend="ollama", base_url=args.base_url, model=model)
    critic = CriticAgent(client)

    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(args.out) / ts
    out.mkdir(parents=True, exist_ok=True)

    arms = []
    for arm, disable, mode in (("deployed", False, "batch"),
                               ("batch_no_gate", True, "batch"),
                               ("critic_only", True, "single")):
        result = run_arm(critic, arm, disable, mode)
        arms.append(result)
        print(f"[{arm}] false confirms: {result['false_confirms']}"
              f"/{len(FALSE_PLAUSIBLE)} | true confirmed: "
              f"{result['true_confirmed']}/{result['true_total']}")

    (out / "false_confirm.json").write_text(json.dumps(
        {"generated_at": ts, "model": model, "base_url": args.base_url,
         "n_true": len(TRUE_PROVEN), "n_false": len(FALSE_PLAUSIBLE),
         "arms": arms}, indent=2), encoding="utf-8")
    (out / "false_confirm.md").write_text(to_markdown(arms), encoding="utf-8")
    print(to_markdown(arms))
    print(f"written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
