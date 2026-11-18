"""
Sqlmap wrapper — SQL injection detection (non-destructive, batch).

Enhanced version with:
  - Configurable --level / --risk (default 1/1 for safety)
  - JSON output parsing for injection type, DBMS, parameter details
  - Cookie/header passthrough for authenticated testing
  - Forms mode (--forms) with optional target list
"""

import json
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class SqlmapTool(Tool):
    name = "sqlmap"
    capability = "SQLI_SCAN"
    binary = "sqlmap"
    allow_nonzero_exit = True

    def build_command(self, target: str, **kwargs) -> List[str]:
        level = str(kwargs.get("level", "1")).strip()
        risk = str(kwargs.get("risk", "1")).strip()
        cookie = kwargs.get("cookie", "")
        use_forms = kwargs.get("forms", True)
        headers = kwargs.get("headers", "")
        data = kwargs.get("data", "")
        method = kwargs.get("method", "")

        self._out_file = Path(tempfile.mktemp(suffix=".json"))
        cmd = [
            self.binary, "-u", target,
            "--batch", "--smart",
            "--level", level, "--risk", risk,
            "--disable-coloring", "--flush-session",
            "--timeout", "10", "--retries", "1",
            "--answers", "follow=N",
            "-o", str(self._out_file),
        ]
        if use_forms:
            cmd.append("--forms")
        if data:
            cmd += ["--data", data]
        if method:
            cmd += ["--method", method]
        if cookie:
            cmd += ["--cookie", cookie]
        if headers:
            for h in headers.split("\n"):
                h = h.strip()
                if h:
                    cmd += ["--headers", h]
        return cmd

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        data = f"{stdout}\n{stderr}"
        findings = []

        # Try JSON output file first (richer data)
        out_file = getattr(self, "_out_file", None)
        if out_file and out_file.exists():
            try:
                json_data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
                findings.extend(self._parse_json_output(json_data))
            except (json.JSONDecodeError, OSError):
                pass
            finally:
                out_file.unlink(missing_ok=True)

        # Fallback: regex parse on stdout/stderr
        if not findings:
            findings.extend(self._parse_text_output(data))

        return {"sqlmap_findings": findings, "count": len(findings)}

    @staticmethod
    def _parse_json_output(data: Any) -> List[Dict[str, Any]]:
        """Parse sqlmap's JSON output file (-o flag) for structured findings."""
        findings = []
        if not isinstance(data, dict):
            return findings

        # sqlmap JSON output has a "data" key with vulnerability details
        vulns = data.get("data", {})
        if not isinstance(vulns, dict):
            return findings

        for param, param_data in vulns.items():
            if not isinstance(param_data, dict):
                continue
            for inject_type, inject_data in param_data.items():
                if not isinstance(inject_data, dict):
                    continue
                title = inject_data.get("title", "")
                payload = inject_data.get("payload", "")
                dbms = inject_data.get("dbms", "")
                vector = inject_data.get("vector", "")
                place = inject_data.get("place", param)

                # Classify injection type
                inj_type = "unknown"
                title_lower = str(title).lower()
                if "boolean" in title_lower:
                    inj_type = "boolean_based"
                elif "time" in title_lower:
                    inj_type = "time_based"
                elif "union" in title_lower:
                    inj_type = "union_based"
                elif "error" in title_lower:
                    inj_type = "error_based"
                elif "stacked" in title_lower:
                    inj_type = "stacked_queries"

                findings.append({
                    "parameter": place,
                    "injection_type": inj_type,
                    "title": title[:200],
                    "payload": payload[:300],
                    "dbms": dbms,
                    "vector": vector,
                    "vulnerable": True,
                    "description": f"sqlmap: {inj_type} SQLi in parameter '{place}' — {title[:100]}",
                })

        return findings

    @staticmethod
    def _parse_text_output(data: str) -> List[Dict[str, Any]]:
        """Fallback: regex parse stdout/stderr when JSON output unavailable."""
        findings = []
        if re.search(r"is vulnerable", data, re.IGNORECASE) or "back-end DBMS" in data:
            m = re.search(r"(https?://\S+)", data)
            url = m.group(1) if m else ""

            # Try to extract parameter name
            param_match = re.search(r"Parameter:\s*['\"]?(\w+)", data)
            param = param_match.group(1) if param_match else ""

            # Try to extract injection type
            inj_type = "unknown"
            if "Boolean" in data:
                inj_type = "boolean_based"
            elif "Time" in data:
                inj_type = "time_based"
            elif "UNION" in data:
                inj_type = "union_based"
            elif "Error" in data:
                inj_type = "error_based"

            # Try to extract DBMS
            dbms_match = re.search(r"back-end DBMS:\s*(.+)", data)
            dbms = dbms_match.group(1).strip() if dbms_match else ""

            findings.append({
                "parameter": param,
                "injection_type": inj_type,
                "url": url,
                "dbms": dbms,
                "vulnerable": True,
                "description": f"sqlmap: {inj_type} SQLi"
                               + (f" in parameter '{param}'" if param else "")
                               + (f" — DBMS: {dbms}" if dbms else ""),
            })
        return findings
