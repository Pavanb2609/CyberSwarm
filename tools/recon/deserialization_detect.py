"""
DESERIALIZATION_DETECTION -- passive detection of insecure deserialization
vectors in HTTP responses.

Checks for:
  - Java serialization signatures (AC ED 00 05 magic bytes)
  - .NET ViewState without MAC validation
  - PHP unserialize() indicators
  - Python pickle opcodes
  - RMI/gRPC service references

Pure Python (urllib), no external binary.
"""

import re
import ssl
import urllib.request
from typing import Any

from tools.base import Tool, ToolResult

# ── Detection patterns ────────────────────────────────────────────────────

JAVA_SER_MAGIC = re.compile(r"AC\s*ED\s*00\s*05", re.IGNORECASE)

JAVA_CLASS_PATTERNS = [
    re.compile(r"java\.io\.ObjectInputStream", re.IGNORECASE),
    re.compile(r"java\.io\.Serializable", re.IGNORECASE),
    re.compile(r"javax\.rmi", re.IGNORECASE),
    re.compile(r"java\.rmi\.Remote", re.IGNORECASE),
]

VIEWSTATE_NO_MAC = [
    re.compile(r"__VIEWSTATE.*?encrypted\s*=\s*['\"]?false", re.IGNORECASE),
    re.compile(r" ViewStateMac.*?(?:disabled|false|0)", re.IGNORECASE),
]

PHP_UNSERIALIZE = [
    re.compile(r"\bunserialize\s*\(", re.IGNORECASE),
    re.compile(r"O:\d+:\"[A-Z]\w+\":\d+:\{", re.IGNORECASE),
    re.compile(r"__wakeup\s*\(", re.IGNORECASE),
]

PYTHON_PICKLE = [
    re.compile(r"__reduce__", re.IGNORECASE),
    re.compile(r"cos\b.*\bsystem\b", re.IGNORECASE),
]

RMI_GRPC = [
    re.compile(r"rmi://", re.IGNORECASE),
    re.compile(r"grpc\.io", re.IGNORECASE),
    re.compile(r"protobuf", re.IGNORECASE),
]


class DeserializationDetectionTool(Tool):
    """Passive detection of deserialization vectors in HTTP responses."""

    name = "deserialization_detect"
    capability = "DESERIALIZATION_DETECTION"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["python-urllib-deser-detect", target]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 30, **kwargs) -> ToolResult:
        full_url = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        endpoints = kwargs.get("endpoints") or []

        test_urls = [full_url]
        for ep in endpoints[:10]:
            ep_url = ep if ep.startswith("http") else f"{full_url.rstrip('/')}/{ep.lstrip('/')}"
            if ep_url not in test_urls:
                test_urls.append(ep_url)

        all_vectors = []
        for url in test_urls[:15]:
            vectors = self._scan_url(url, timeout)
            all_vectors.extend(vectors)

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"deserialization_vectors": all_vectors, "count": len(all_vectors),
                     "tested_urls": test_urls[:15]},
        )

    @staticmethod
    def _scan_url(url: str, timeout: int) -> list[dict[str, Any]]:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url, method="GET",
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-recon/1.0)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(50000).decode("utf-8", errors="replace")
        except Exception:
            return []

        vectors = []

        if JAVA_SER_MAGIC.search(body):
            vectors.append({"url": url, "type": "java_serialization",
                            "severity": "CRITICAL", "confidence": 85,
                            "description": "Java serialization magic bytes (AC ED 00 05)"})

        for pat in JAVA_CLASS_PATTERNS:
            match = pat.search(body)
            if match:
                vectors.append({"url": url, "type": "java_class_reference",
                                "severity": "HIGH", "confidence": 65,
                                "description": f"Java serializable class: {match.group(0)}"})
                break

        for pat in VIEWSTATE_NO_MAC:
            if pat.search(body):
                vectors.append({"url": url, "type": "viewstate_no_mac",
                                "severity": "CRITICAL", "confidence": 80,
                                "description": ".NET ViewState without MAC validation"})
                break

        for pat in PHP_UNSERIALIZE:
            match = pat.search(body)
            if match:
                vectors.append({"url": url, "type": "php_unserialize",
                                "severity": "HIGH", "confidence": 60,
                                "description": f"PHP indicator: {match.group(0).strip()[:100]}"})
                break

        for pat in PYTHON_PICKLE:
            if pat.search(body):
                vectors.append({"url": url, "type": "python_pickle",
                                "severity": "CRITICAL", "confidence": 70,
                                "description": "Python pickle deserialization indicator"})
                break

        for pat in RMI_GRPC:
            match = pat.search(body)
            if match:
                vectors.append({"url": url, "type": "rpc_service",
                                "severity": "MEDIUM", "confidence": 55,
                                "description": f"RPC service: {match.group(0)}"})
                break

        return vectors
