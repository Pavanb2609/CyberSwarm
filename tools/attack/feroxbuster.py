"""
Feroxbuster wrapper — recursive content discovery (faster than ffuf for dirs).
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool
from tools.wordlists import default_wordlist_or


class FeroxbusterTool(Tool):
    name = "feroxbuster"
    capability = "CONTENT_DISCOVERY"
    binary = "feroxbuster"
    allow_nonzero_exit = True

    def build_command(self, target: str, **kwargs) -> List[str]:
        out = tempfile.mktemp(suffix=".json")
        self._out = out
        wordlist = default_wordlist_or(kwargs.get("wordlist", ""))
        if not wordlist:
            raise FileNotFoundError(
                "No wordlist found in common locations or $FFUF_WORDLIST. "
                "Install SecLists or pass wordlist=<path> explicitly."
            )
        return [self.binary, "-u", target, "-w", wordlist, "--json", "-o", out,
                "--silent", "--dont-scan", "402", "-t", "8",
                "--status-codes", "200,204,301,302,307,401,403"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        urls = []
        path = getattr(self, "_out", None)
        data = ""
        if path and Path(path).exists():
            data = Path(path).read_text(encoding="utf-8", errors="replace")
            Path(path).unlink(missing_ok=True)
        for line in data.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if obj.get("status", 0) in (200, 204, 301, 302, 307, 401, 403):
                    urls.append(obj.get("url", ""))
            except json.JSONDecodeError:
                continue
        return {"discovered_urls": sorted(set(urls)), "count": len(set(urls))}
