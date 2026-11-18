import json
from typing import Any, Dict, List

from tools.base import Tool


class NaabuTool(Tool):
    name = "naabu"
    capability = "PORT_DISCOVERY"
    binary = "naabu"

    def build_command(self, target: str, **kwargs) -> List[str]:
        top_ports = kwargs.get("top_ports", "100")
        return [self.binary, "-host", target, "-top-ports", str(top_ports), "-silent", "-json"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        open_ports = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                port = obj.get("port")
                if port is not None and port not in open_ports:
                    open_ports.append(port)
            except json.JSONDecodeError:
                continue
        return {"open_ports": sorted(open_ports), "count": len(open_ports)}
