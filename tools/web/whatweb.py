import json
from typing import Any, Dict, List

from tools.base import Tool


class WhatWebTool(Tool):
    name = "whatweb"
    capability = "WEB_TECHNOLOGY_DISCOVERY"
    binary = "whatweb"
    allow_nonzero_exit = True

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = kwargs.get("full_url") or (target if target.startswith("http") else f"http://{target}")
        return [self.binary, "--log-json=-", "--no-errors", url]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        technologies = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            plugins = obj.get("plugins", {})
            for plugin_name, details in plugins.items():
                # skip generic/noisy plugins that aren't real technology signals
                if plugin_name in ("HTTPServer", "Title", "IP", "Country"):
                    continue
                if plugin_name not in technologies:
                    technologies.append(plugin_name)

        return {"technologies": technologies}
