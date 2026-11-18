"""
WAFW00F wrapper — Web Application Firewall fingerprinting.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class Wafw00fTool(Tool):
    name = "wafw00f"
    capability = "WAF_DETECT"
    binary = "wafw00f"

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"https://{target}"
        out = tempfile.mktemp(suffix=".json")
        self._out = out
        return [self.binary, "-a", "-o", out, "-f", "json", url]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        findings = []
        path = getattr(self, "_out", None)
        data = ""
        if path and Path(path).exists():
            data = Path(path).read_text(encoding="utf-8", errors="replace")
            Path(path).unlink(missing_ok=True)
        if not data.strip():
            data = stdout
        try:
            obj = json.loads(data)
            entries = obj if isinstance(obj, list) else [obj]
            for e in entries:
                url = e.get("url") or e.get("host") or ""
                waf = e.get("firewall") or e.get("detected_waf")
                if isinstance(e.get("waf"), list):
                    for w in e["waf"]:
                        if isinstance(w, dict):
                            findings.append({
                                "url": url,
                                "waf_name": w.get("name", ""),
                                "waf_manufacturer": w.get("manufacturer", ""),
                            })
                elif waf and (e.get("detected") is True or str(waf).lower() != "none"):
                    findings.append({"url": url,
                                     "waf_name": waf,
                                     "waf_manufacturer": e.get("manufacturer", "")})
        except json.JSONDecodeError:
            # wafw00f plain-text fallback: "The site <url> is behind <WAF> (manufacturer)" / "is not behind any known WAFs"
            for line in (data or "").splitlines():
                low = line.lower()
                if "is behind" in low and "not behind" not in low:
                    findings.append({"url": line.split()[0], "waf_name": line, "waf_manufacturer": ""})
        return {"wafs_detected": findings, "count": len(findings)}
