"""
ROBOTS_TXT_PARSER -- passive robots.txt analysis.

Extracts disallowed paths, internal API endpoints, sitemaps,
and information leakage from robots.txt.  Pure Python.
"""

import ssl
import urllib.error
import urllib.request
from typing import Any

from tools.base import Tool, ToolResult

# Paths that indicate sensitive/internal areas
SENSITIVE_PATHS = [
    "/admin", "/api", "/restapi", "/graphql", "/swagger", "/actuator",
    "/.git", "/.env", "/backup", "/config", "/debug", "/trace",
    "/phpinfo", "/server-status", "/datatool", "/internal",
    "/login", "/register", "/auth", "/oauth", "/token",
]

# Patterns indicating internal APIs
API_PATTERNS = ["/api/", "/restapi/", "/graphql", "/soap", "/wsdl", "/rpc"]


class RobotsTxtParserTool(Tool):
    """Passive robots.txt analysis."""

    name = "robots_txt"
    capability = "ROBOTS_TXT_ANALYSIS"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["python-robots-txt-parser", target]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 10, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        url = base.rstrip("/") + "/robots.txt"

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url, method="GET",
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-recon/1.0)"},
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            if not body or e.code in (404, 403):
                return ToolResult(tool=self.name, status="success", capability=self.capability,
                                  results={"found": False, "message": f"robots.txt returned {e.code}"})
        except Exception as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error=str(e))

        if not body.strip():
            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={"found": False, "message": "Empty robots.txt"})

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results=self._parse(body, base))

    @staticmethod
    def _parse(body: str, base_url: str) -> dict[str, Any]:
        disallowed = []
        allowed = []
        sitemaps = []
        internal_apis = []
        sensitive_paths = []
        internal_hosts = set()

        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            directive, value = parts[0].strip().lower(), parts[1].strip()

            if directive == "disallow" and value:
                disallowed.append(value)
                value_lower = value.lower()
                if any(p in value_lower for p in SENSITIVE_PATHS):
                    sensitive_paths.append(value)
                if any(p in value_lower for p in API_PATTERNS):
                    internal_apis.append(value)
            elif directive == "allow" and value:
                allowed.append(value)
            elif directive == "sitemap":
                sitemaps.append(value)

        # Extract internal hostnames from URLs in the file
        import re
        hosts = re.findall(r'https?://([a-zA-Z0-9._-]+\.(?:trip\.com|ctripcorp\.com))', body)
        internal_hosts = list(set(hosts))

        return {
            "found": True,
            "disallowed_count": len(disallowed),
            "disallowed_paths": disallowed,
            "allowed_paths": allowed,
            "sitemaps": sitemaps,
            "internal_apis": internal_apis,
            "sensitive_paths": sensitive_paths,
            "internal_hosts": internal_hosts,
            "severity": "HIGH" if internal_apis or internal_hosts else ("MEDIUM" if sensitive_paths else "INFO"),
        }
