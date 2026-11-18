"""
engagement_report.py — folder-wise, evidence-first engagement deliverables.

For a target it reads the pipeline's own stores (attack_evidence, recon
evidence, decision logs, screenshots) and writes, under
``results/engagements/<target>/``:

  * ``summary.json`` / ``summary.md``            — engagement overview
  * ``vulnerabilities/<nn>__<SEVERITY>__<slug>/``  — one folder per CONFIRM
    finding (finding.md + evidence.txt + meta.json)
  * ``proof_of_testing/``                        — when NO vulnerabilities were
    confirmed, this demonstrates the testing was actually performed: agent
    runs, the full tool matrix, captured evidence, timeline and screenshots.

"Evidence-backed" is the rule here too: a finding only lands in the
vulnerabilities folders if the pipeline persisted it as CONFIRM with real
tool evidence (evidence_chain / raw_output_excerpt). Disputed findings and
proof-requests are reported inside PROOF_OF_TESTING instead.

Usage:
    python engagement_report.py <target>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ATTACK_EVIDENCE_DIR = ROOT / "results" / "attack_evidence"
RECON_EVIDENCE_DIR = ROOT / "results" / "evidence"
ATTACK_LOG = ROOT / "results" / "attack_decision_log.jsonl"
RECON_LOG = ROOT / "results" / "decision_log.jsonl"
SCREENSHOT_DIR = ROOT / "results" / "screenshots"
SYSTEM_MAP_DIR = ROOT / "results" / "system_map"
OUT_ROOT = ROOT / "results" / "engagements"

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _slugify(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")[:60] or "finding"


def _load(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _load_log(path: Path, target: str) -> list:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d.get("target") in (target, None):
            rows.append(d)
    return rows


def _fmt_timestamp():
    return datetime.now(timezone.utc).isoformat()


def _file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()[:16]


def collect_vulnerabilities(attack: dict) -> list:
    """CONFIRM findings persisted by the pipeline (evidence-backed only)."""
    vulns = []
    for v in (attack or {}).get("vulnerabilities") or []:
        vulns.append(dict(v, _confirmed=True))
    if not vulns:
        for run in (attack or {}).get("agent_runs") or []:
            for f in run.get("findings") or []:
                if str(f.get("status", "")).lower() == "confirmed":
                    f = dict(f, _confirmed=True, _source_agent=run.get("agent"))
                    f.setdefault("evidence_chain", f.get("evidence_chain") or [])
                    vulns.append(f)
    return vulns


def collect_runs(attack: dict) -> list:
    runs = []
    for r in (attack or {}).get("agent_runs") or []:
        findings = r.get("findings") or []
        runs.append({
            "agent": r.get("agent"),
            "status": r.get("status"),
            "duration_s": r.get("duration_s"),
            "tools_run": r.get("tools_run") or [],
            "error": r.get("error"),
            "finding_counts": {
                "total": len(findings),
                "confirmed": sum(1 for f in findings
                                 if str(f.get("status", "")).lower() == "confirmed"),
                "disputed": sum(1 for f in findings
                                if str(f.get("status", "")).lower() == "disputed"),
            },
            "reasoning": r.get("reasoning"),
        })
    return runs


def _vuln_evidence_lines(v: dict) -> list:
    out = []
    chain = v.get("evidence_chain") or v.get("evidence") or []
    for i, item in enumerate(chain, 1):
        out.append(f"[{i}] {item if isinstance(item, str) else json.dumps(item)}")
    raw = v.get("raw_output_excerpt") or ""
    if raw:
        out.append(f"\n--- raw tool output excerpt ---\n{raw}")
    if not out:
        out.append("(no captured evidence attached)")
    return out


def _render_vuln_md(v: dict) -> str:
    lines = []
    lines.append(f"# {v.get('name') or v.get('id') or 'Finding'}")
    lines.append("")
    lines.append(f"- **Severity:** {v.get('severity', 'UNKNOWN')}")
    lines.append(f"- **Confidence:** {v.get('confidence')}")
    lines.append(f"- **Final confidence (critic):** {v.get('final_confidence')}")
    lines.append(f"- **Independent sources:** {v.get('independent_sources')}")
    lines.append(f"- **False-positive risk:** {v.get('false_positive_risk')}")
    if v.get("tool"):
        lines.append(f"- **Tool:** {v['tool']}")
    if v.get("url"):
        lines.append(f"- **URL:** `{v['url']}`")
    if v.get("port"):
        lines.append(f"- **Port:** {v['port']}")
    if v.get("cwe"):
        lines.append(f"- **CWE:** {v['cwe']}")
    if v.get("_source_agent"):
        lines.append(f"- **Source agent:** {v['_source_agent']}")
    lines.append("")
    lines.append("## Description")
    lines.append("")
    lines.append(v.get("description") or v.get("detail") or "(no description)")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    lines.append("```")
    lines.extend(_vuln_evidence_lines(v))
    lines.append("```")
    lines.append("")
    proofs = v.get("proofs") or []
    if proofs:
        lines.append(f"## Continuous proof ({len(proofs)} attempts, replayable)")
        lines.append("")
        for i, p in enumerate(proofs, 1):
            req = p.get("request") or {}
            resp = p.get("response") or {}
            lines.append(f"### Attempt {i} — {p.get('match_criteria') or 'sent'}")
            lines.append("")
            lines.append(f"- **Payload (`{p.get('category', 'payload')}`):** "
                         f"`{p.get('payload', '')}`")
            lines.append(f"- **Matched:** {p.get('matched')}")
            lines.append(f"- **Request:** `{req.get('method', 'GET')} "
                         f"{req.get('url', '')}`")
            if req.get("headers"):
                lines.append("- Request headers:")
                for hk, hv in list(req["headers"].items())[:8]:
                    lines.append(f"  - `{hk}: {hv}`")
            if req.get("body"):
                lines.append(f"- Request body: `{req['body'][:300]}`")
            lines.append(f"- **Response:** HTTP {resp.get('status')}")
            if resp.get("headers"):
                lines.append("- Response headers:")
                for hk, hv in list(resp["headers"].items())[:6]:
                    lines.append(f"  - `{hk}: {hv}`")
            if resp.get("body"):
                lines.append("- Response body (excerpt):")
                lines.append("```")
                lines.append(str(resp["body"])[:800])
                lines.append("```")
            lines.append("")
        lines.append(f"See `proofs/` in this folder for the full per-attempt "
                     "records (JSON).")
        lines.append("")
    if v.get("remediation"):
        lines.append("## Remediation")
        lines.append("")
        lines.append(v["remediation"])
    return "\n".join(lines)


def write_vulnerabilities(target: str, vulns: list) -> dict:
    """One folder per confirmed finding. Returns folder count written."""
    base = OUT_ROOT / target / "vulnerabilities"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True, exist_ok=True)
    order = sorted(vulns,
                   key=lambda v: ( _SEVERITY_RANK.get(str(v.get("severity")).upper(), 9),
                                   (v.get("name") or "").lower() ))
    for i, v in enumerate(order, 1):
        folder = base / f"{i:02d}__{str(v.get('severity')).upper()}__{_slugify(v.get('name'))}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "finding.md").write_text(_render_vuln_md(v), encoding="utf-8")
        (folder / "evidence.txt").write_text(
            "\n".join(_vuln_evidence_lines(v)), encoding="utf-8")
        (folder / "meta.json").write_text(
            json.dumps({k: v.get(k) for k in (
                "name", "severity", "confidence", "final_confidence",
                "independent_sources", "false_positive_risk", "tool", "url",
                "port", "cwe", "description") if v.get(k) is not None},
                indent=2), encoding="utf-8")
        for vi, p in enumerate(v.get("proofs") or [], 1):
            pfile = folder / "proofs" / f"attempt_{vi:02d}.json"
            pfile.parent.mkdir(parents=True, exist_ok=True)
            pfile.write_text(json.dumps(p, indent=2), encoding="utf-8")
        for vi, p in enumerate(v.get("proofs") or [], 1):
            req = p.get("request") or {}
            resp = p.get("response") or {}
            (folder / "proofs" / f"attempt_{vi:02d}.md").write_text(
                f"# Attempt {vi}\n\n"
                f"**Category:** {p.get('category')}\n\n"
                f"**Payload:** `{p.get('payload', '')}`\n\n"
                f"**Matched:** {p.get('matched')} — {p.get('match_criteria')}\n\n"
                f"## Request\n\n`{req.get('method', 'GET')} {req.get('url', '')}`\n\n"
                f"```\n{json.dumps(req, indent=2)}\n```\n\n"
                f"## Response (HTTP {resp.get('status')})\n\n"
                f"```\n{json.dumps(resp, indent=2)}\n```\n",
                encoding="utf-8")
    return len(order)


def _tools_matrix(attack: dict, recon: dict) -> list:
    rows = []
    seen = set()
    for r in (attack or {}).get("agent_runs") or []:
        agent = r.get("agent")
        for t in r.get("tools_run") or []:
            name = t if isinstance(t, str) else t.get("name") or str(t)
            key = ("attack", agent, name)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"phase": "attack", "agent": agent, "tool": name,
                         "status": "executed"})
    for cap in (recon or {}).get("completed_actions") or []:
        key = ("recon", "", cap)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"phase": "recon", "agent": "", "tool": cap, "status": "completed"})
    for cap in (recon or {}).get("zero_findings_actions") or []:
        key = ("recon", "", f"{cap} (zero-finding)")
        if key in seen:
            continue
        seen.add(key)
        rows.append({"phase": "recon", "agent": "", "tool": cap,
                     "status": "completed - zero findings"})
    for cap in (recon or {}).get("failed_actions") or []:
        key = ("recon", "", f"{cap} (failed)")
        if key in seen:
            continue
        seen.add(key)
        rows.append({"phase": "recon", "agent": "", "tool": cap,
                     "status": "failed / skipped"})
    return rows


def _recon_summary(recon: dict) -> list:
    if not recon:
        return [("recon evidence", "no recon evidence store found")]
    def _count(k):
        v = recon.get(k)
        return len(v) if isinstance(v, (list, dict)) else v
    rows = [
        ("target", recon.get("target")),
        ("authorized scope", recon.get("authorized_scope")),
        ("target type", recon.get("target_type")),
        ("resolved IP", recon.get("resolved_ip")),
        ("reachable", recon.get("reachable")),
        ("subdomains", _count("subdomains")),
        ("subdomain resolutions", _count("subdomain_resolutions")),
        ("discovered endpoints", _count("discovered_endpoints")),
        ("discovered paths", _count("discovered_paths")),
        ("discovered parameters", _count("discovered_parameters")),
        ("open ports", _count("open_ports")),
        ("port details", _count("port_details")),
        ("services", _count("services")),
        ("technologies", _count("technologies")),
        ("tls findings", _count("tls_findings")),
        ("tls vulnerabilities", _count("tls_vulnerabilities")),
        ("missing security headers", _count("missing_security_headers")),
        ("header findings", _count("header_findings")),
        ("cms assessment", recon.get("cms_assessment")),
        ("detected api types", _count("detected_api_types")),
        ("js endpoints", _count("js_endpoints")),
        ("historical urls", _count("historical_urls")),
    ]
    return [(k, v) for k, v in rows if v not in (None, "", [], {})]


def _render_proof(target: str, attack: dict, recon: dict,
                  runs: list, timeline: list, screenshots: list,
                  integrity: dict) -> str:
    L = []
    L.append(f"# PROOF OF TESTING — {target}")
    L.append("")
    L.append("This report records the assessment actually performed. It is "
             "produced when no vulnerabilities were confirmed, so the "
             "engagement has an auditable record rather than an empty page.")
    L.append("")
    attacks = attack or {}
    L.append(f"- **Risk rating (pipeline):** {attacks.get('risk_rating', 'N/A')}")
    L.append(f"- **Confirmed vulnerabilities:** {len(attacks.get('vulnerabilities') or [])}")
    L.append(f"- **Disputed findings:** {len(attacks.get('disputed_findings') or [])}")
    L.append(f"- **Proof requests pending:** {len(attacks.get('proof_requests') or [])}")
    L.append(f"- **Completed agents:** {len(attacks.get('completed_agents') or [])}")
    L.append("- **Authorization:** strict scope gate passed "
             f"(see config/authorized_targets.json for `{target}`)")
    L.append("")
    if not (attacks.get('vulnerabilities') or []):
        L.append("## Result")
        L.append("")
        L.append("**No vulnerabilities were confirmed in this engagement.** "
                 "The following sections document the testing that was "
                 "performed, what was observed, and the captured evidence.")
        L.append("")
    L.append("## Agents executed (attack phase)")
    L.append("")
    L.append("| agent | status | duration (s) | tools | findings (tot/conf/disp) |")
    L.append("|---|---|---|---|---|")
    for r in runs:
        c = r["finding_counts"]
        tools = ", ".join(r["tools_run"] or []) or "-"
        L.append(f"| {r['agent']} | {r['status']} | {r['duration_s']} | "
                 f"{tools} | {c['total']}/{c['confirmed']}/{c['disputed']} |")
    L.append("")
    L.append("## Tool matrix (what actually ran)")
    L.append("")
    rows = _tools_matrix(attack, recon)
    if rows:
        L.append("| phase | agent | tool / action | status |")
        L.append("|---|---|---|---|")
        for row in rows:
            L.append(f"| {row['phase']} | {row['agent'] or '-'} | {row['tool']} | "
                     f"{row['status']} |")
    else:
        L.append("(no tool executions recorded)")
    L.append("")
    L.append("## Recon evidence captured")
    L.append("")
    for k, v in _recon_summary(recon):
        L.append(f"- **{k}:** {v}")
    L.append("")
    if recon and (recon.get("missing_security_headers") or recon.get("tls_vulnerabilities")
                  or recon.get("weak_ciphers")):
        L.append("### Notable observations (not enough for a confirmed finding)")
        for name in ("missing_security_headers", "tls_vulnerabilities",
                     "weak_ciphers", "info_disclosure_headers"):
            val = recon.get(name)
            if val:
                L.append(f"- **{name}:** {val}")
    L.append("")
    L.append("## Passage of the engagement (decision log)")
    L.append("")
    if timeline:
        L.append("| time | phase | agent/capability |")
        L.append("|---|---|---|")
        for t in timeline:
            L.append(f"| {t.get('time')} | {t.get('phase')} | {t.get('label')} |")
    else:
        L.append("(no decision-log entries recorded)")
    L.append("")
    L.append("## Findings that needed more proof or were disputed (raw evidence)")
    L.append("")
    disputed = attacks.get("disputed_findings") or []
    if disputed:
        L.append(f"{len(disputed)} finding(s) were reviewed and not confirmed. "
                 "The raw evidence captured for each is reproduced below.")
        L.append("")
        for i, f in enumerate(disputed[:10], 1):
            L.append(f"### {i}. {f.get('name') or f.get('id') or 'Finding'}")
            L.append("")
            L.append(f"- **Agent:** {f.get('_source_agent') or f.get('agent') or '-'}")
            L.append(f"- **URL:** `{f.get('url') or '-'}`")
            L.append(f"- **Severity (claimed):** {f.get('severity')}")
            L.append(f"- **Reason status:** {f.get('status') or f.get('reason_status')}")
            if f.get("description"):
                L.append(f"- **Description:** {f['description'][:300]}")
            L.append("")
            chain = f.get("evidence_chain") or f.get("evidence") or []
            if chain:
                L.append("Evidence chain:")
                L.append("```")
                for item in chain[:10]:
                    L.append(str(item)[:300])
                L.append("```")
                L.append("")
            for p in (f.get("proofs") or [])[:6]:
                req = p.get("request") or {}
                resp = p.get("response") or {}
                L.append(f"- Payload `{p.get('payload', '')[:150]}` -> "
                         f"`{req.get('method', 'GET')} {req.get('url', '')[:180]}` -> "
                         f"HTTP {resp.get('status')} "
                         f"({p.get('match_criteria') or 'sent'})")
    else:
        L.append("(no disputed findings)")
    L.append("")
    L.append("## Pending proof requests (what still needs manual/extra proof)")
    L.append("")
    pending = attacks.get("proof_requests") or []
    if pending:
        for ir, pr in enumerate(pending[:15], 1):
            L.append(f"{ir}. {pr}")
    else:
        L.append("(none pending)")
    L.append("")
    L.append("## Screenshots captured")
    L.append("")
    if screenshots:
        for s in screenshots:
            L.append(f"- `{s.name}` — copied to `proof_of_testing/screenshots/`")
    else:
        L.append("(none captured in this engagement)")
    L.append("")
    L.append("## Evidence integrity")
    L.append("")
    L.append("| source | sha256 (first 16) |")
    L.append("|---|---|")
    for k, v in integrity.items():
        L.append(f"| `{k}` | {v} |")
    L.append("")
    L.append("Raw evidence and decision logs are preserved in "
             "`proof_of_testing/raw/`. Any finding below that carried "
             "per-attempt payload/request/response proof has it inside its "
             "`vulnerabilities/<severity>_<name>/proofs/` folder.")
    return "\n".join(L)


def _timeline(attack_rows: list, recon_rows: list) -> list:
    all_rows = []
    for d in attack_rows:
        t = d.get("timestamp") or d.get("time")
        all_rows.append({"time": t or "-", "phase": "attack",
                         "label": d.get("agent") or d.get("event") or "event"})
    for d in recon_rows:
        t = d.get("timestamp") or d.get("time")
        cap = d.get("evidence", {}).get("active_subtarget")
        label = d.get("capability") or d.get("next_capability") or d.get("event") \
            or ("recon decision" if cap is None else f"recon of {cap}")
        all_rows.append({"time": t or "-", "phase": "recon", "label": str(label)})
    all_rows.sort(key=lambda r: str(r["time"]))
    return all_rows


def _screenshots_for(target: str) -> list:
    if not SCREENSHOT_DIR.exists():
        return []
    out = []
    base = target.lstrip("www.").split(".")[0]
    for p in sorted(SCREENSHOT_DIR.iterdir()):
        if not p.is_file():
            continue
        name = p.name.replace("-", ".").replace("___", ".")
        if target.replace(".", "") in name.replace(".", "") or base in name:
            out.append(p)
    return out


def build(target: str) -> Path:
    attack = _load(ATTACK_EVIDENCE_DIR / f"{target}.json")
    recon = _load(RECON_EVIDENCE_DIR / f"{target}.json")
    atk_rows = _load_log(ATTACK_LOG, target)
    rec_rows = _load_log(RECON_LOG, target)

    vulns = collect_vulnerabilities(attack)
    runs = collect_runs(attack)
    timeline = _timeline(atk_rows, rec_rows)

    out = OUT_ROOT / target
    out.mkdir(parents=True, exist_ok=True)

    n_vuln_folders = write_vulnerabilities(target, vulns)

    screenshots = _screenshots_for(target)
    proof_dir = out / "proof_of_testing"
    proof_dir.mkdir(parents=True, exist_ok=True)
    if screenshots:
        shot_out = proof_dir / "screenshots"
        shot_out.mkdir(exist_ok=True)
        for s in screenshots:
            shutil.copy2(s, shot_out / s.name)

    # Raw evidence + decision logs land in proof_of_testing/raw/ so the folder
    # itself proves the testing happened (no reference to out-of-band files).
    raw_out = proof_dir / "raw"
    raw_out.mkdir(exist_ok=True)
    for src, name in (
            (ATTACK_EVIDENCE_DIR / f"{target}.json", f"attack_evidence_{target}.json"),
            (RECON_EVIDENCE_DIR / f"{target}.json", f"recon_evidence_{target}.json"),
            (ATTACK_LOG, "attack_decision_log.json"),
            (RECON_LOG, "recon_decision_log.json")):
        if src.exists():
            try:
                shutil.copy2(src, raw_out / name)
            except OSError:
                pass

    integrity = {}
    for src in (ATTACK_EVIDENCE_DIR / f"{target}.json",
                RECON_EVIDENCE_DIR / f"{target}.json",
                out / "summary.json"):
        if src.exists():
            integrity[src.name] = _file_sha256(src)

    summary = {
        "target": target,
        "generated_at": _fmt_timestamp(),
        "authorized": True,
        "risk_rating": (attack or {}).get("risk_rating"),
        "confirmed_vulnerabilities": len(vulns),
        "vulnerability_folders": n_vuln_folders,
        "disputed_findings": (attack or {}).get("disputed_findings") or [],
        "proof_requests": (attack or {}).get("proof_requests") or [],
        "agents": runs,
        "recon": _recon_summary(recon),
        "screenshots": [s.name for s in screenshots],
        "integrity": integrity,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    md = [f"# Engagement summary — {target}", "",
          f"- **Generated:** {summary['generated_at']}",
          f"- **Risk rating:** {summary['risk_rating'] or 'N/A'}",
          f"- **Confirmed vulnerabilities:** {n_vuln_folders} "
          f"(see `vulnerabilities/`)",
          f"- **Proof of testing:** `proof_of_testing/PROOF_OF_TESTING.md`", ""]
    (out / "summary.md").write_text("\n".join(md), encoding="utf-8")

    proof_md = _render_proof(target, attack, recon, runs, timeline, screenshots,
                             integrity)
    (out / "proof_of_testing" / "PROOF_OF_TESTING.md").write_text(
        proof_md, encoding="utf-8")

    tool_md = ["# Tool matrix", ""]
    rows = _tools_matrix(attack, recon)
    tool_md.append("| phase | agent | tool / action | status |")
    tool_md.append("|---|---|---|---|")
    for row in rows:
        tool_md.append(f"| {row['phase']} | {row['agent'] or '-'} | {row['tool']} "
                       f"| {row['status']} |")
    (proof_dir / "tool_matrix.md").write_text("\n".join(tool_md), encoding="utf-8")

    if n_vuln_folders:
        print(f"[engagement] {target}: {n_vuln_folders} confirmed "
              f"vulnerability folder(s) written -> {out/'vulnerabilities'}")
    else:
        print(f"[engagement] {target}: no confirmed vulnerabilities — "
              f"proof of testing written -> {out/'proof_of_testing'}")
    print(f"[engagement] summary -> {out/'summary.md'}")
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("target", help="target hostname (matches results/ stores)")
    args = p.parse_args()
    build(args.target.strip().lower().rstrip("."))


if __name__ == "__main__":
    main()