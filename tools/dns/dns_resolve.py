import socket
from typing import Any, Dict, List

from tools.base import Tool, ToolResult


class DNSResolutionTool(Tool):
    """
    Resolves a hostname to an IP address. Uses Python's built-in socket
    module rather than shelling out to a binary, since basic DNS resolution
    doesn't need an external tool and this way it always works with zero
    extra installs.
    """

    name = "dns_resolve"
    capability = "DNS_RESOLUTION"
    binary = ""  # no external binary required

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None  # always ready, nothing to check

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []  # unused; run() is overridden below

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}  # unused; run() is overridden below

    def run(self, target: str, timeout: int = 10, **kwargs) -> ToolResult:
        try:
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(target)
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"resolved_ip": ip, "reachable": True},
            )
        except socket.gaierror as e:
            return ToolResult(
                tool=self.name, status="error", capability=self.capability,
                error=f"DNS resolution failed: {e}",
            )
        except socket.timeout:
            return ToolResult(
                tool=self.name, status="timeout", capability=self.capability,
                error=f"DNS resolution timed out after {timeout}s",
            )
