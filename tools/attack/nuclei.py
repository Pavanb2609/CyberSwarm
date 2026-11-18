"""
Nuclei wrapper for VULN_SCAN capability.

Handles all nuclei output format variants:
  - JSONL (one dict per line) — nuclei v2
  - JSON array on one line   — nuclei v3+
  - Mixed lines               — some versions mix progress + JSON

Flag compatibility:
  - Uses -jsonl for v3+ (replaces the old -je /dev/stdout)
  - Falls back gracefully if output is not parseable
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class NucleiTool(Tool):
    name = "nuclei"
    capability = "VULN_SCAN"
    binary = "nuclei"
    allow_nonzero_exit = True   # nuclei exits 1 when findings exist

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"https://{target}"
        severity = kwargs.get("severity", "low,medium,high,critical")
        tags = kwargs.get("tags", "")

        # Use a temp file for JSON output — most reliable across nuclei versions
        self._out_file = Path(tempfile.mktemp(suffix=".jsonl"))

        cmd = [
            self.binary,
            "-u", url,
            "-o", str(self._out_file),
            "-jsonl",               # works in nuclei v2.9+ and v3
            "-severity", severity,
            "-silent",
            "-timeout", "10",
            "-retries", "1",
            "-rate-limit", "50",
        ]
        if tags:
            cmd += ["-tags", tags]
        cmd += ["-etags", "intrusive,dos,fuzz"]
        return cmd

    def _parse_obj(self, obj: Any) -> List[Dict]:
        """Normalise a single nuclei result object into our schema."""
        findings = []
        if isinstance(obj, list):
            for item in obj:
                findings.extend(self._parse_obj(item))
            return findings
        if not isinstance(obj, dict):
            return []
        info = obj.get("info", {})
        if not isinstance(info, dict):
            info = {}
        findings.append({
            "template_id": obj.get("template-id", ""),
            "name":        info.get("name", ""),
            "severity":    info.get("severity", "unknown").upper(),
            "description": info.get("description", "")[:300],
            "url":         obj.get("matched-at", obj.get("host", "")),
            "type":        obj.get("type", ""),
            "tags":        info.get("tags", []),
            "reference":   info.get("reference", [])[:3],
            "cvss_score":  info.get("classification", {}).get("cvss-score", None)
                           if isinstance(info.get("classification"), dict) else None,
            "cve_id":      info.get("classification", {}).get("cve-id", [])
                           if isinstance(info.get("classification"), dict) else [],
            "cwe_id":      info.get("classification", {}).get("cwe-id", [])
                           if isinstance(info.get("classification"), dict) else [],
        })
        return findings

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        findings = []

        # Primary: read from temp output file (most reliable)
        out_file = getattr(self, "_out_file", None)
        raw = ""
        if out_file and Path(out_file).exists():
            raw = Path(out_file).read_text(encoding="utf-8", errors="replace")
            Path(out_file).unlink(missing_ok=True)
        else:
            raw = stdout  # fallback to stdout

        # Parse every line — handle JSONL, JSON array, or mixed
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("[INF]") or line.startswith("[WRN]"):
                continue
            try:
                obj = json.loads(line)
                findings.extend(self._parse_obj(obj))
            except json.JSONDecodeError:
                # Nuclei sometimes prints progress lines — skip them
                continue

        # Deduplicate by template_id + url
        seen = set()
        deduped = []
        for f in findings:
            key = (f["template_id"], f["url"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return {
            "nuclei_findings": deduped,
            "count": len(deduped),
        }
