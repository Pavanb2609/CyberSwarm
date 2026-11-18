import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from tools.base import Tool, ToolResult

# Each CMS: extra paths worth probing beyond the homepage, and lowercase
# substrings (checked against body + headers) that count as a signal if seen
# on the homepage OR on one of the extra paths (with a non-404 status).
SIGNATURE_SOURCES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-json/", "/wp-content/", "/wp-includes/"],
        "markers": ("wp-content", "wp-includes", "wp-json", "wordpress"),
    },
    "Drupal": {
        "paths": ["/CHANGELOG.txt", "/core/CHANGELOG.txt", "/sites/default/files/"],
        "markers": ("drupal.settings", "drupal", "/sites/default/", "/sites/all/"),
    },
    "Joomla": {
        "paths": ["/administrator/", "/media/system/js/core.js"],
        "markers": ("joomla", "/media/jui/", "/media/system/"),
    },
    "Magento": {
        "paths": ["/skin/frontend/", "/js/mage/"],
        "markers": ("magento", "mage.cookies", "/skin/frontend/"),
    },
    "Shopify": {
        "paths": [],
        "markers": ("cdn.shopify.com", "shopify.theme", "x-shopify"),
    },
}

GENERATOR_META_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3})")


class CMSIdentifyTool(Tool):
    """
    Fingerprints common CMS platforms (WordPress, Drupal, Joomla, Magento,
    Shopify) from the homepage plus a handful of CMS-specific paths. Pure
    Python via `requests` -- no external binary, zero extra installs,
    same rationale as dns_resolve.py / api_discover.py.
    """

    name = "cms_identify"
    capability = "CMS_IDENTIFICATION"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self) -> Optional[str]:
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []  # unused; run() is overridden below

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}  # unused; run() is overridden below

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        try:
            import requests
        except ImportError as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                               error=f"'requests' package not available: {e}")

        base_url = kwargs.get("base_url")
        if not base_url:
            base_url = target if target.startswith("http") else f"https://{target}"
        base_url = base_url.rstrip("/")
        per_request_timeout = kwargs.get("per_request_timeout", 6)

        session = requests.Session()
        session.headers.update({"User-Agent": "CyberSwarm-Recon/1.0"})

        scores: Dict[str, int] = {name: 0 for name in SIGNATURE_SOURCES}
        signals: List[str] = []
        generator_content = None

        def check_page(url: str, label: str) -> None:
            nonlocal generator_content
            try:
                resp = session.get(url, timeout=per_request_timeout, allow_redirects=True, verify=True)
            except requests.exceptions.RequestException:
                return
            if resp.status_code >= 400:
                return

            body = (resp.text or "")[:5000].lower()
            header_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
            haystack = body + " " + header_blob

            if generator_content is None:
                m = GENERATOR_META_RE.search(resp.text or "")
                if m:
                    generator_content = m.group(1)

            for cms_name, spec in SIGNATURE_SOURCES.items():
                for marker in spec["markers"]:
                    if marker in haystack:
                        scores[cms_name] += 1
                        signals.append(f"{cms_name}: '{marker}' found on {label}")
                        break  # one signal per page per CMS is enough

        check_page(base_url + "/", "homepage")
        # only probe extra paths for CMS candidates that already got a
        # homepage hint, or if nothing matched yet -- keeps requests low
        candidates = [c for c, s in scores.items() if s > 0] or list(SIGNATURE_SOURCES.keys())
        for cms_name in candidates:
            for path in SIGNATURE_SOURCES[cms_name]["paths"]:
                check_page(urljoin(base_url + "/", path.lstrip("/")), path)

        cms_detected = max(scores, key=scores.get) if any(scores.values()) else None
        cms_version = None
        if generator_content:
            vm = VERSION_RE.search(generator_content)
            if vm:
                cms_version = vm.group(1)

        result = {
            "cms_detected": cms_detected,
            "cms_signals": signals[:20],
            "cms_scores": {k: v for k, v in scores.items() if v > 0},
        }
        if cms_version:
            result["cms_version"] = cms_version
        if generator_content:
            result["generator_meta"] = generator_content

        return ToolResult(tool=self.name, status="success", capability=self.capability, results=result)
