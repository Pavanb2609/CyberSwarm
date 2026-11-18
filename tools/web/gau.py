from typing import Any, Dict, List

from tools.base import Tool


class GauTool(Tool):
    """
    gau (Get All URLs) pulls known URLs for a domain from Wayback Machine,
    Common Crawl, AlienVault OTX, and urlscan.io -- surfaces old/forgotten
    endpoints that current crawling wouldn't find.
    """

    name = "gau"
    capability = "HISTORICAL_URL_DISCOVERY"
    binary = "gau"
    allow_nonzero_exit = True

    def build_command(self, target: str, **kwargs) -> List[str]:
        return [self.binary, target]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        urls = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                if line not in urls:
                    urls.append(line)
        return {"historical_urls": urls, "count": len(urls)}
