import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool

SMB_PORTS = {139, 445}


class WindowsServiceEnumerationTool(Tool):
    """
    Runs nmap's smb-os-discovery, smb-enum-shares, and smb-enum-users NSE
    scripts -- standard low-impact SMB/Windows recon (OS/build version,
    share names, and usernames where the target allows guest/anonymous
    enumeration). Reuses the project's existing nmap dependency rather than
    adding a new one. Gated: only runs if PORT_DISCOVERY already found
    139/445 open -- matches the planner prompt's rule that this capability
    needs SMB evidence, not plausibility.
    """

    name = "smb_enum"
    capability = "WINDOWS_SERVICE_ENUMERATION"
    binary = "nmap"
    allow_nonzero_exit = True

    def __init__(self):
        self._xml_path = Path(tempfile.mktemp(suffix=".xml"))

    def build_command(self, target: str, **kwargs) -> List[str]:
        ports_str = kwargs.get("ports") or ""
        open_ports = {int(p) for p in ports_str.split(",") if p.strip().isdigit()}
        self._relevant = open_ports & SMB_PORTS  # noqa: attribute set for run()'s pre-check via base flow
        port_list = ",".join(str(p) for p in sorted(self._relevant)) or "445"
        return [
            self.binary, "-p", port_list,
            "--script", "smb-os-discovery,smb-enum-shares,smb-enum-users",
            "-oX", str(self._xml_path), target,
        ]

    def run(self, target: str, timeout: int = 180, **kwargs):
        ports_str = kwargs.get("ports") or ""
        open_ports = {int(p) for p in ports_str.split(",") if p.strip().isdigit()}
        if not (open_ports & SMB_PORTS):
            from tools.base import ToolResult
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"windows_enum_skipped": True,
                         "reason": "Neither SMB port (139, 445) is in open_ports -- "
                                   "skipping rather than scanning blind."},
            )
        return super().run(target, timeout=timeout, **kwargs)

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        if not self._xml_path.exists():
            return {"windows_enum": {}, "note": "nmap produced no XML output"}

        tree = ET.parse(self._xml_path)
        root = tree.getroot()
        host = root.find("host")
        self._xml_path.unlink(missing_ok=True)
        if host is None:
            return {"windows_enum": {}}

        scripts: Dict[str, str] = {}
        for port in host.findall(".//port"):
            for script in port.findall("script"):
                scripts[script.get("id")] = script.get("output", "")
        for script in host.findall(".//hostscript/script"):
            scripts[script.get("id")] = script.get("output", "")

        shares = [line.strip() for line in scripts.get("smb-enum-shares", "").splitlines()
                  if line.strip().startswith("\\\\")]
        users = [line.strip() for line in scripts.get("smb-enum-users", "").splitlines()
                 if line.strip() and not line.strip().lower().startswith(("smb-enum-users", "host script"))]

        return {
            "windows_enum": {
                "os_discovery": scripts.get("smb-os-discovery", "").strip() or None,
                "shares": shares,
                "users": users[:30],
            }
        }
