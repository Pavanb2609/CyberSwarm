import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class NmapTool(Tool):
    name = "nmap"
    capability = "SERVICE_DETECTION"
    binary = "nmap"
    allow_nonzero_exit = True  # nmap can exit non-zero on partial scans, output is still useful

    def __init__(self):
        self._xml_path = Path(tempfile.mktemp(suffix=".xml"))

    def build_command(self, target: str, **kwargs) -> List[str]:
        ports = kwargs.get("ports")  # e.g. "22,80,443" from a prior PORT_DISCOVERY step
        cmd = [self.binary, "-sV", "-oX", str(self._xml_path)]
        if ports:
            cmd += ["-p", ports]
        cmd.append(target)
        return cmd

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        if not self._xml_path.exists():
            raise RuntimeError("nmap did not produce XML output")

        tree = ET.parse(self._xml_path)
        root = tree.getroot()
        host = root.find("host")
        self._xml_path.unlink(missing_ok=True)

        if host is None:
            return {"reachable": False, "open_ports": [], "services": [], "technologies": []}

        status = host.find("status")
        reachable = status is not None and status.get("state") == "up"

        open_ports, services, technologies, port_details = [], [], [], []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port.get("portid"))
                open_ports.append(portid)
                svc = port.find("service")
                svc_name, product, version = None, None, None
                if svc is not None:
                    svc_name = svc.get("name")
                    if svc_name and svc_name not in services:
                        services.append(svc_name)
                    product = svc.get("product")
                    version = svc.get("version")
                    if product:
                        tech = f"{product} {version}".strip() if version else product
                        if tech not in technologies:
                            technologies.append(tech)
                port_details.append({
                    "port": portid, "service": svc_name, "product": product, "version": version,
                })

        return {
            "reachable": reachable,
            "open_ports": sorted(open_ports),
            "services": services,
            "technologies": technologies,
            "port_details": port_details,
        }
