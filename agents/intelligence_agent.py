"""
IntelligenceAgent — enriches technologies and confirmed findings with
CVE / EPSS / CISA KEV / PoC intelligence. All sources are free public APIs.
Results are cached under results/cache/ and the agent degrades gracefully offline.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import system_map as sm
from agents.base_agent import AgentResult, BaseAgent

CACHE_DIR = Path(__file__).parent.parent / "results" / "cache"

INTEL_SYSTEM = """You are the IntelligenceAgent for CyberSwarm.
Assess the real-world exploitability of each technology/CVE. Output JSON:
{"enriched_findings": [
  {"technology","cve_id","epss_score","kev_listed","poc_available",
   "exploitation_likelihood","patch_available","severity_adjusted","confidence",
   "intelligence_summary"}],
 "overall_threat_level": "CRITICAL|HIGH|MEDIUM|LOW"}"""


def _fetch_json(url: str, timeout: int = 15) -> Optional[Any]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberSwarm/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return None


# Default freshness windows: CISA KEV is updated several times a week,
# EPSS scores are recalculated daily -- neither should be cached forever.
KEV_TTL_S = 24 * 3600          # 1 day
EPSS_TTL_S = 3 * 24 * 3600     # 3 days


def _cache_get(key: str, max_age_s: Optional[float] = None) -> Optional[Any]:
    """Read a cached value. If max_age_s is given and the entry is older
    than that (or has no timestamp, i.e. was written before TTLs existed),
    treat it as a miss so the caller refetches."""
    p = CACHE_DIR / f"{key}.json"
    if not p.exists():
        return None
    try:
        envelope = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(envelope, dict) or "_cached_at" not in envelope:
        return None  # pre-TTL cache format -> refetch rather than trust stale data forever
    if max_age_s is not None and (time.time() - envelope["_cached_at"]) > max_age_s:
        return None
    return envelope.get("data")


def _cache_set(key: str, data: Any) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    envelope = {"_cached_at": time.time(), "data": data}
    (CACHE_DIR / f"{key}.json").write_text(json.dumps(envelope), encoding="utf-8")


class IntelligenceAgent(BaseAgent):
    agent_name = "intelligence"
    owned_tools = ["searchsploit"]

    def should_run(self, smap: Dict[str, Any]) -> bool:
        return True  # always useful post-attack (enrichment also runs off memory/CVEs, not just smap techs)

    def run(self, target: str, smap: Dict[str, Any], memory: Dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        techs = [f"{t.get('name','')} {t.get('version','')}".strip() for t in smap.get("technologies", [])]
        techs = [t for t in techs if t]

        # 1. CISA KEV (cached, refreshed at most once per KEV_TTL_S)
        kev = _cache_get("cisa_kev", max_age_s=KEV_TTL_S)
        if kev is None:
            data = _fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            if data:
                kev = data.get("vulnerabilities", [])
                _cache_set("cisa_kev", kev)
        kev_cves = {e.get("cveID") for e in kev} if kev else set()

        # 2. searchsploit per tech
        exploit_map: Dict[str, List[Dict]] = {}
        for tech in techs[:8]:
            tr = self._run_tool("searchsploit", tech, timeout=60)
            if tr and tr.status == "success" and tr.results.get("exploit_candidates"):
                exploit_map[tech] = tr.results["exploit_candidates"][:5]
                result.tools_run.append(f"searchsploit({tech})")

        # 3. EPSS for CVEs referenced in findings / searchsploit
        cves = self._collect_cves(memory, exploit_map)
        epss: Dict[str, float] = {}
        for cve in list(cves)[:10]:
            cached = _cache_get(f"epss:{cve}", max_age_s=EPSS_TTL_S)
            if cached is not None:
                epss[cve] = cached
            else:
                data = _fetch_json(f"https://api.first.org/data/v1/epss?cve={cve}")
                try:
                    score = float(data["data"][0]["epss"])
                    epss[cve] = score
                    _cache_set(f"epss:{cve}", score)
                except Exception:  # noqa: BLE001
                    pass

        # 4. LLM enrichment only when there is something to enrich
        has_something = bool(techs and (exploit_map or epss or cves or kev_cves))
        if has_something:
            analysis = self._llm_json(INTEL_SYSTEM, json.dumps({
                "technologies": techs[:10],
                "searchsploit": exploit_map,
                "epss": epss,
                "kev_cves_sample": list(kev_cves)[:5],
                "findings": [v.get("name") for v in memory.get("vulnerabilities", [])][:10],
            }, indent=2), temperature=0.2)
        else:
            analysis = None
            result.reasoning = "No exploitable technology/CVE signal to enrich; skipped LLM."

        if analysis and analysis.get("enriched_findings"):
            for f in analysis["enriched_findings"]:
                result.findings.append(self._make_finding(
                    tool="intelligence", name=f.get("technology", "unknown tech"),
                    severity=f.get("severity_adjusted", "INFO"), confidence=f.get("confidence", 50),
                    description=f.get("intelligence_summary", ""),
                    false_positive_risk="LOW" if f.get("poc_available") else "MEDIUM",
                    raw_output_excerpt=json.dumps({
                        "cve": f.get("cve_id"), "epss": f.get("epss_score"),
                        "kev": f.get("kev_listed"), "poc": f.get("poc_available"),
                        "likelihood": f.get("exploitation_likelihood")})))
            result.reasoning = f"Threat level: {analysis.get('overall_threat_level', 'UNKNOWN')}"
        else:
            self._deterministic_enrichment(result, techs, exploit_map, epss, kev_cves)

        result.status = "success" if result.findings else "partial"
        return result

    def _collect_cves(self, memory: Dict[str, Any], exploit_map: Dict[str, List[Dict]]) -> set:
        cves = set()
        blob = json.dumps(exploit_map) + " " + json.dumps([v.get("name", "") for v in memory.get("vulnerabilities", [])])
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", blob))
        return cves

    def _deterministic_enrichment(self, result: AgentResult, techs: List[str],
                                  exploit_map: Dict[str, List[Dict]],
                                  epss: Dict[str, float], kev_cves: set) -> None:
        for tech in techs:
            candidates = exploit_map.get(tech, [])
            if candidates:
                result.findings.append(self._make_finding(
                    tool="searchsploit", name=f"Exploit candidates for {tech}",
                    severity="HIGH", confidence=70,
                    description="; ".join(c.get("title", c.get("path", "")) for c in candidates[:3])[:400],
                    false_positive_risk="MEDIUM"))
        for cve, score in epss.items():
            sev = "HIGH" if score >= 0.3 else "MEDIUM"
            kev = cve in kev_cves
            if score >= 0.3 or kev:
                result.findings.append(self._make_finding(
                    tool="intelligence", name=f"EPSS: {cve}", severity=sev, confidence=75,
                    description=f"EPSS score {score:.3f}"
                                + (f"; listed in CISA KEV (actively exploited)" if kev else ""),
                    false_positive_risk="LOW",
                    raw_output_excerpt=json.dumps({"cve": cve, "epss": score, "kev": kev})))
