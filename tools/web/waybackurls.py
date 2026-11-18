from typing import Any, Dict, List

from tools.base import Tool


class WaybackURLsTool(Tool):
    """Fallback for HISTORICAL_URL_DISCOVERY if gau isn't installed -- same idea, Wayback Machine only."""

    name = "waybackurls"
    capability = "HISTORICAL_URL_DISCOVERY"
    binary = "waybackurls"
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
