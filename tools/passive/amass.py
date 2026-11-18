import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class AmassTool(Tool):
    name = "amass"
    capability = "PASSIVE_ASSET_DISCOVERY"
    binary = "amass"
    allow_nonzero_exit = True  # amass can exit non-zero on rate limits etc while still producing partial results

    def __init__(self):
        self._json_path = Path(tempfile.mktemp(suffix=".json"))

    def build_command(self, target: str, **kwargs) -> List[str]:
        return [self.binary, "enum", "-passive", "-d", target, "-json", str(self._json_path)]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        if not self._json_path.exists():
            return {"subdomains": [], "count": 0}

        subdomains = []
        for line in self._json_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = obj.get("name")
            if name and name not in subdomains:
                subdomains.append(name)

        self._json_path.unlink(missing_ok=True)
        return {"subdomains": subdomains, "count": len(subdomains)}
