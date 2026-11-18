"""
testssl.sh wrapper for comprehensive TLS/SSL analysis and vulnerability detection.

Wraps the testssl.sh tool (https://github.com/testssl/testssl.sh) which performs
17+ vulnerability checks including Heartbleed, POODLE, DROWN, ROBOT, BEAST,
SWEET32, FREAK, LOGJAM, LUCKY13, CCS Injection, Ticketbleed, CRIME, BREACH,
RC4 detection, renegotiation issues, and full protocol/cipher enumeration.

Operates in two modes:
  - mode="full"       : Complete scan (protocols, ciphers, cert, headers, vulns)
  - mode="vuln_only"  : Vulnerability-focused scan with severity filtering

Uses testssl.sh's --jsonfile-pretty output for machine-readable parsing.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.base import Tool, ToolResult


class TestSSLTool(Tool):
    name = "testssl"
    capability = "TLS_ANALYSIS"
    binary = "testssl"
    allow_nonzero_exit = True  # testssl exits non-zero when vulns found

    def _pick_port(self, kwargs) -> int:
        ports_arg = kwargs.get("ports")
        if ports_arg:
            candidates = [int(p) for p in str(ports_arg).split(",") if p.strip().isdigit()]
            for preferred in (443, 8443):
                if preferred in candidates:
                    return preferred
            if candidates:
                return candidates[0]
        return 443

    def build_command(self, target: str, **kwargs) -> List[str]:
        mode = kwargs.get("mode", "full")
        port = self._pick_port(kwargs)

        tmp_dir = tempfile.gettempdir()
        safe_target = target.replace("/", "_").replace(":", "_")
        self._out_file = os.path.join(tmp_dir, f"testssl_{safe_target}_p{port}.json")
        self._target = target
        self._port = port

        # Remove stale output file
        out_path = Path(self._out_file)
        if out_path.exists():
            out_path.unlink()

        cmd = [
            self._binary_path(),
            "--jsonfile-pretty", self._out_file,
            "--warnings", "batch",
            "--color", "0",
            "--quiet",
        ]

        if mode == "vuln_only":
            cmd += ["--vulnerabilities", "--severity", "MEDIUM"]

        cmd.append(f"{target}:{port}")
        return cmd

    def run(self, target: str, timeout: int = 600, **kwargs) -> ToolResult:
        problem = self.validate()
        if problem:
            return ToolResult(
                tool=self.name, status="not_installed",
                capability=self.capability, error=problem,
            )

        cmd = self.build_command(target, **kwargs)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, errors="replace",
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.name, status="timeout",
                capability=self.capability,
                error=f"Timed out after {timeout}s running testssl against {target}",
            )
        except FileNotFoundError as e:
            return ToolResult(
                tool=self.name, status="not_installed",
                capability=self.capability, error=str(e),
            )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        out_path = Path(self._out_file)
        if not out_path.exists():
            return ToolResult(
                tool=self.name, status="error",
                capability=self.capability,
                error=f"testssl produced no output file. stderr: {stderr[:500]}",
                raw_stdout=stdout, raw_stderr=stderr,
            )

        try:
            raw_json = out_path.read_text(encoding="utf-8", errors="replace")
            parsed = self.parse(raw_json, stderr)
        except Exception as e:
            return ToolResult(
                tool=self.name, status="error",
                capability=self.capability,
                error=f"parse failure: {e}",
                raw_stdout=stdout, raw_stderr=stderr,
            )
        finally:
            out_path.unlink(missing_ok=True)

        return ToolResult(
            tool=self.name, status="success",
            capability=self.capability,
            results=parsed,
            raw_stdout=stdout, raw_stderr=stderr,
        )

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON from testssl: {e}") from e

        # testssl --jsonfile-pretty produces:
        # { "Invocation":..., "scanResult": [ dns_record, {target_result}, ... ] }
        # The target_result object has nested arrays: protocols, ciphers,
        # vulnerabilities, serverDefaults, headerResponse, etc.
        scan_result = data.get("scanResult") if isinstance(data, dict) else data
        if not isinstance(scan_result, list):
            scan_result = []

        result: Dict[str, Any] = {
            "tls_reachable": True,
            "target": self._target if hasattr(self, "_target") else "",
            "port": self._port if hasattr(self, "_port") else 443,
            "testssl_version": data.get("version", "") if isinstance(data, dict) else "",
            "protocols": {},
            "ciphers": [],
            "certificate": {},
            "vulnerabilities": {},
            "server_defaults": {},
            "headers": {},
            "tls_findings": [],
            "weak_ciphers": [],
            "vuln_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "ok": 0},
        }

        # Find the target result object (skip DNS record entries)
        target_obj = None
        for entry in scan_result:
            if isinstance(entry, dict) and entry.get("targetHost"):
                target_obj = entry
                break

        if not target_obj:
            # Fallback: check if scanResult has a problem
            for entry in scan_result:
                if isinstance(entry, dict) and entry.get("id") == "scanProblem":
                    result["tls_reachable"] = False
                    result["tls_findings"].append(
                        f"SCAN PROBLEM: {entry.get('finding', 'unknown')}"
                    )
            return result

        # --- Parse protocols ---
        for p in target_obj.get("protocols", []):
            pid = p.get("id", "")
            sev = p.get("severity", "INFO").upper()
            finding = p.get("finding", "")
            result["protocols"][pid] = {"status": finding, "severity": sev}
            if sev not in ("OK", "INFO"):
                result["tls_findings"].append(f"PROTOCOL: {pid} - {finding} [{sev}]")

        # --- Parse ciphers ---
        for c in target_obj.get("ciphers", []):
            cid = c.get("id", "")
            sev = c.get("severity", "OK").upper()
            finding = c.get("finding", "")
            cwe = c.get("cwe", "")
            cve = c.get("cve", "")
            cipher_entry = {"id": cid, "cipher": finding, "severity": sev}
            if cwe:
                cipher_entry["cwe"] = cwe
            if cve:
                cipher_entry["cve"] = cve
            result["ciphers"].append(cipher_entry)
            if sev not in ("OK", "INFO"):
                wc = {"cipher": finding, "severity": sev}
                if cve:
                    wc["cve"] = cve
                result["weak_ciphers"].append(wc)
                result["tls_findings"].append(f"CIPHER: {finding} [{sev}]" + (f" ({cve})" if cve else ""))

        # --- Parse vulnerabilities ---
        for v in target_obj.get("vulnerabilities", []):
            vid = v.get("id", "")
            sev = v.get("severity", "OK").upper()
            finding = v.get("finding", "")
            cve = v.get("cve", "")
            cwe = v.get("cwe", "")
            vuln_entry = {"severity": sev, "finding": finding}
            if cve:
                vuln_entry["cve"] = cve
            if cwe:
                vuln_entry["cwe"] = cwe
            result["vulnerabilities"][vid] = vuln_entry

            if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                result["vuln_summary"][sev.lower()] = result["vuln_summary"].get(sev.lower(), 0) + 1
                result["tls_findings"].append(
                    f"VULN: {vid} - {finding} [{sev}]" + (f" ({cve})" if cve else "")
                )
            else:
                result["vuln_summary"]["ok"] = result["vuln_summary"].get("ok", 0) + 1

        # --- Parse server defaults (cert info) ---
        for sd in target_obj.get("serverDefaults", []):
            sid = sd.get("id", "")
            sev = sd.get("severity", "INFO").upper()
            finding = sd.get("finding", "")
            result["server_defaults"][sid] = {"finding": finding, "severity": sev}
            # Extract cert-specific fields
            if sid.startswith("cert_") or sid in ("TLS_extensions", "OCSP_stapling", "TLS_session_ticket"):
                result["certificate"][sid] = {"finding": finding, "severity": sev}
                if sev not in ("OK", "INFO"):
                    result["tls_findings"].append(f"CERT: {sid} - {finding} [{sev}]")

        # --- Parse header response ---
        for h in target_obj.get("headerResponse", []):
            hid = h.get("id", "")
            sev = h.get("severity", "INFO").upper()
            finding = h.get("finding", "")
            result["headers"][hid] = {"finding": finding, "severity": sev}
            if sev not in ("OK", "INFO"):
                result["tls_findings"].append(f"HEADER: {hid} - {finding} [{sev}]")

        # --- Parse cipher tests (BEAST, LUCKY13, etc.) ---
        for ct in target_obj.get("cipherTests", []):
            ctid = ct.get("id", "")
            sev = ct.get("severity", "OK").upper()
            finding = ct.get("finding", "")
            cve = ct.get("cve", "")
            cwe = ct.get("cwe", "")
            # These are already included in vulnerabilities but may have extra detail
            if ctid and ctid not in result["vulnerabilities"]:
                vuln_entry = {"severity": sev, "finding": finding}
                if cve:
                    vuln_entry["cve"] = cve
                if cwe:
                    vuln_entry["cwe"] = cwe
                result["vulnerabilities"][ctid] = vuln_entry
                if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    result["vuln_summary"][sev.lower()] = result["vuln_summary"].get(sev.lower(), 0) + 1
                    result["tls_findings"].append(
                        f"VULN: {ctid} - {finding} [{sev}]" + (f" ({cve})" if cve else "")
                    )

        # Count total findings
        result["total_findings"] = len(result["tls_findings"])

        return result
