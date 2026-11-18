import json
from typing import Any, Dict, List

from tools.base import Tool


class HttpxTool(Tool):
    name = "httpx"
    capability = "WEB_PROBING"
    # Binary NAME, not an absolute path — Tool.is_available() resolves it via
    # PATH plus ~/go/bin etc. (a hardcoded /home/ubuntu/go/bin/httpx broke
    # resolution on every other machine/user).
    binary = "httpx"

    def build_command(self, target: str, **kwargs) -> List[str]:
        # Use full_url if provided (user passed a URL instead of hostname)
        url = kwargs.get("full_url") or target
        # httpx reads targets from stdin normally; -u works for a single target too
        return [self.binary, "-u", url, "-silent", "-json", "-title", "-status-code", "-tech-detect"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        probes = []
        technologies = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            probes.append({
                "url": obj.get("url"),
                "status_code": obj.get("status_code"),
                "title": obj.get("title"),
                "webserver": obj.get("webserver"),
            })
            for tech in obj.get("tech", []) or []:
                if tech not in technologies:
                    technologies.append(tech)

        return {"probes": probes, "technologies": technologies, "reachable": len(probes) > 0}
