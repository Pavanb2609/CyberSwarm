import json
from typing import Any, Dict, List

from tools.base import Tool


class SubfinderTool(Tool):
    name = "subfinder"
    capability = "SUBDOMAIN_DISCOVERY"
    binary = "subfinder"

    def build_command(self, target: str, **kwargs) -> List[str]:
        # -silent keeps stdout clean, -oJ gives JSONL (one JSON object per line)
        return [self.binary, "-d", target, "-silent", "-oJ"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        subdomains = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                host = obj.get("host")
            except json.JSONDecodeError:
                # fall back to plain-text mode (one subdomain per line)
                host = line
            if host and host not in subdomains:
                subdomains.append(host)
        return {"subdomains": subdomains, "count": len(subdomains)}
