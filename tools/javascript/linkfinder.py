from typing import Any, Dict, List

from tools.base import Tool


class LinkFinderTool(Tool):
    """
    LinkFinder crawls a page's JS files and extracts endpoints/paths
    referenced in the code -- often surfaces API routes or admin paths
    that aren't linked anywhere in the visible HTML.
    """

    name = "linkfinder"
    capability = "JAVASCRIPT_ANALYSIS"
    binary = "linkfinder"
    allow_nonzero_exit = True

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"http://{target}"
        # -d makes it crawl the domain for JS files instead of requiring a single file
        return [self.binary, "-i", url, "-d", "-o", "cli"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        endpoints = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # LinkFinder's cli output prints discovered endpoints as bare
            # paths/URLs -- keep only lines that actually look like one
            if line.startswith("/") or line.startswith("http://") or line.startswith("https://"):
                if line not in endpoints:
                    endpoints.append(line)
        return {"js_endpoints": endpoints, "count": len(endpoints)}
