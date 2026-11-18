"""
HEADER_ANALYSIS -- fetches HTTP response headers (HTTPS first, HTTP
fallback) and flags missing security headers plus any headers that leak
server/framework info. Also detects technologies from headers.

Pure Python (requests), no external binary needed.
"""

from typing import Any

import requests

from tools.base import Tool, ToolResult

# header -> what its absence means
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing -- allows protocol-downgrade / SSL-stripping attacks",
    "content-security-policy": "CSP missing -- weaker defense against XSS/injection",
    "x-content-type-options": "X-Content-Type-Options missing -- allows MIME-type sniffing",
    "x-frame-options": "X-Frame-Options missing -- page may be vulnerable to clickjacking",
    "referrer-policy": "Referrer-Policy missing -- may leak full URLs to third parties",
    "permissions-policy": "Permissions-Policy missing -- no control over browser features",
}

# headers that, if present, disclose implementation details
INFO_LEAK_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-runtime", "x-request-id",
]

# Headers used to fingerprint technology
TECH_HEADERS = {
    "server": "server",
    "x-powered-by": "framework",
    "x-aspnet-version": "aspnet",
    "x-aspnetmvc-version": "aspnet-mvc",
    "x-generator": "generator",
    "x-trip-app-name": "trip-app",
    "x-trip-app-version": "trip-version",
    "x-trip-app-idc": "trip-datacenter",
    "cf-ray": "cloudflare",
    "x-cdn-cache": "cdn",
    "c-via": "cdn-provider",
    "x-cdn-pop": "cdn-pop",
    "x-backend-latency": "backend-latency",
    "via": "proxy",
    "x-varnish": "varnish",
    "x-cache": "cache",
    "x-drupal-cache": "drupal",
    "x-shopify-stage": "shopify",
    "x-amz-cf-id": "cloudfront",
    "x-akamai-transformed": "akamai",
}

UA_BOTS = [
    ("akamai", "Akamai CDN"),
    ("cloudfront", "AWS CloudFront"),
    ("cloudflare", "Cloudflare"),
    ("varnish", "Varnish Cache"),
    ("nginx", "Nginx"),
    ("apache", "Apache"),
    ("iis", "Microsoft IIS"),
    ("litespeed", "LiteSpeed"),
    ("openresty", "OpenResty"),
]


class HeaderAnalysisTool(Tool):
    name = "header_analysis"
    capability = "HEADER_ANALYSIS"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["python-header-analysis", target]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 20, **kwargs) -> ToolResult:
        full_url = kwargs.get("full_url")
        if full_url:
            urls_to_try = [full_url]
        else:
            urls_to_try = [f"https://{target}", f"http://{target}"]

        headers = {}
        url_used = ""
        status = 0

        for url in urls_to_try:
            try:
                r = requests.get(url, timeout=timeout, headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"
                }, allow_redirects=True, verify=True)
                headers = {k.lower(): v for k, v in r.headers.items()}
                url_used = url
                status = r.status_code
                break
            except requests.exceptions.SSLError:
                try:
                    r = requests.get(url, timeout=timeout, headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"
                    }, allow_redirects=True, verify=False)
                    headers = {k.lower(): v for k, v in r.headers.items()}
                    url_used = url
                    status = r.status_code
                    break
                except Exception:
                    continue
            except Exception:
                continue

        if not headers:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error=f"Could not fetch headers from '{target}'")

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results=self._analyze(headers, url_used, status))

    @staticmethod
    def _analyze(headers: dict[str, str], url: str, status: int) -> dict[str, Any]:
        missing: list[str] = []
        findings: list[str] = []

        for header, message in SECURITY_HEADERS.items():
            if header not in headers:
                missing.append(header)
                findings.append(message)

        info_leaks = {h: headers[h] for h in INFO_LEAK_HEADERS if h in headers}
        for h, v in info_leaks.items():
            findings.append(f"'{h}' header discloses: {v}")

        # Detect technologies from headers
        technologies = []
        for hdr, tech_name in TECH_HEADERS.items():
            if hdr in headers:
                val = headers[hdr]
                if tech_name == "cdn-provider":
                    # Parse "c-via: akamai" -> "Akamai CDN"
                    cdn_name = val.strip().title()
                    technologies.append(f"{cdn_name} CDN")
                elif tech_name in ("trip-app", "trip-version", "trip-datacenter"):
                    technologies.append(f"Trip.com ({val})")
                elif tech_name == "proxy":
                    technologies.append(f"Proxy ({val})")
                elif tech_name in ("varnish", "cache"):
                    technologies.append("Varnish Cache")
                else:
                    technologies.append(f"{tech_name}: {val}")

        # Detect server from server header
        server = headers.get("server", "")
        if server:
            for pattern, name in UA_BOTS:
                if pattern in server.lower():
                    if name not in technologies:
                        technologies.append(name)
                    break
            else:
                technologies.append(f"Server: {server}")

        return {
            "header_analysis_url": url,
            "http_status": status,
            "response_headers": headers,
            "missing_security_headers": missing,
            "info_disclosure_headers": info_leaks,
            "header_findings": findings,
            "technologies": technologies,
        }
