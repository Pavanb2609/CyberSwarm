import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class HostDiscoveryTool(Tool):
    """Answers the single question: is this host up? (nmap -sn, a ping scan, no ports touched)"""

    name = "nmap_host_discovery"
    capability = "HOST_DISCOVERY"
    binary = "nmap"
    allow_nonzero_exit = True

    def __init__(self):
        self._xml_path = Path(tempfile.mktemp(suffix=".xml"))

    def build_command(self, target: str, **kwargs) -> List[str]:
        return [self.binary, "-sn", "-oX", str(self._xml_path), target]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        if not self._xml_path.exists():
            raise RuntimeError(f"nmap produced no XML output. stderr: {stderr[:300]}")

        tree = ET.parse(self._xml_path)
        root = tree.getroot()
        host = root.find("host")
        self._xml_path.unlink(missing_ok=True)

        if host is None:
            return {"reachable": False}

        status = host.find("status")
        reachable = status is not None and status.get("state") == "up"
        return {"reachable": reachable}
