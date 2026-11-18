"""
SENSITIVE_ENDPOINT_DETECT -- passive probing for common sensitive paths.

Probes .env, .git, actuator, swagger, phpinfo, etc. and reports status codes.
Pure Python.  Non-destructive: only sends GET requests.
"""

import ssl
import urllib.error
import urllib.request
from typing import Any

from tools.base import Tool, ToolResult

# Common sensitive endpoints to probe
SENSITIVE_ENDPOINTS = [
    ("/.env", "Environment file"),
    ("/.git/config", "Git config"),
    ("/.git/HEAD", "Git HEAD"),
    ("/.gitignore", "Git ignore"),
    ("/.svn/entries", "SVN entries"),
    ("/.DS_Store", "macOS metadata"),
    ("/actuator", "Spring Boot Actuator"),
    ("/actuator/health", "Actuator Health"),
    ("/actuator/env", "Actuator Environment"),
    ("/actuator/beans", "Actuator Beans"),
    ("/actuator/mappings", "Actuator Mappings"),
    ("/actuator/configprops", "Actuator Config Properties"),
    ("/swagger-ui/", "Swagger UI"),
    ("/swagger.json", "Swagger JSON"),
    ("/swagger-ui.html", "Swagger HTML"),
    ("/api-docs", "API Docs"),
    ("/openapi.json", "OpenAPI Spec"),
    ("/graphql", "GraphQL Endpoint"),
    ("/server-status", "Apache Server Status"),
    ("/server-info", "Apache Server Info"),
    ("/phpinfo.php", "PHP Info"),
    ("/debug/", "Debug Interface"),
    ("/trace/", "Trace Interface"),
    ("/console", "Debug Console"),
    ("/metrics", "Metrics Endpoint"),
    ("/robots.txt", "Robots.txt"),
    ("/sitemap.xml", "Sitemap"),
    ("/.htaccess", "Apache Config"),
    ("/.htpasswd", "Apache Passwords"),
    ("/web.config", "IIS Config"),
    ("/crossdomain.xml", "Cross Domain Policy"),
    ("/clientaccesspolicy.xml", "Silverlight Policy"),
    ("/backup/", "Backup Directory"),
    ("/config/", "Config Directory"),
    ("/dump/", "Data Dump"),
    ("/export/", "Export Endpoint"),
    ("/import/", "Import Endpoint"),
    ("/upload/", "Upload Endpoint"),
]

# Status codes that indicate the endpoint exists (even if blocked)
ACTIVE_STATUSES = {200, 301, 302, 307, 308, 400, 401, 403, 405, 406, 429, 500, 502}


class SensitiveEndpointDetectTool(Tool):
    """Passive sensitive endpoint detection."""

    name = "sensitive_endpoint_detect"
    capability = "SENSITIVE_ENDPOINT_DETECTION"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["python-sensitive-endpoint-detect", target]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 10, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        extra_paths = kwargs.get("endpoints", [])

        endpoints_to_check = [(p, d) for p, d in SENSITIVE_ENDPOINTS]
        for p in extra_paths:
            endpoints_to_check.append((p, "Custom endpoint"))

        found = []
        ctx = ssl.create_default_context()
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"}

        for path, description in endpoints_to_check:
            url = base.rstrip("/") + "/" if not path.startswith("/") else base.rstrip("/")
            url = base.rstrip("/") + path

            try:
                req = urllib.request.Request(url, method="GET", headers=headers)
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    status = resp.status
                    size = len(resp.read())
            except urllib.error.HTTPError as e:
                status = e.code
                size = len(e.read()) if e.fp else 0
            except Exception:
                continue

            if status in ACTIVE_STATUSES:
                severity = "INFO"
                if status == 200 and path in ("/.env", "/.git/config", "/.git/HEAD", "/actuator/env"):
                    severity = "CRITICAL"
                elif (status == 200 and path in ("/swagger-ui/", "/openapi.json", "/phpinfo.php")) or (status == 200 and "/actuator" in path):
                    severity = "HIGH"
                elif status == 403:
                    severity = "LOW"  # blocked but exists

                found.append({
                    "path": path,
                    "status": status,
                    "size": size,
                    "description": description,
                    "severity": severity,
                })

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={
                              "found": found,
                              "count": len(found),
                              "critical": [f for f in found if f["severity"] == "CRITICAL"],
                              "high": [f for f in found if f["severity"] == "HIGH"],
                              "tested_count": len(endpoints_to_check),
                          })
