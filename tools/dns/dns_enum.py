import dns.resolver
import dns.name
from typing import Any, Dict, List

from tools.base import Tool, ToolResult

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]


class DNSEnumTool(Tool):
    name = "dns_enum"
    capability = "DNS_ENUMERATION"
    binary = ""  # uses dnspython library

    def is_available(self) -> bool:
        try:
            import dns.resolver  # noqa: F401
            return True
        except ImportError:
            return False

    def validate(self):
        try:
            import dns.resolver  # noqa: F401
        except ImportError:
            return "dnspython is not installed (pip install dnspython)"
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 30, **kwargs) -> ToolResult:
        records: Dict[str, List[str]] = {}
        errors: List[str] = []

        for rtype in RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(target, rtype, lifetime=timeout)
                records[rtype] = sorted({str(r) for r in answers})
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                errors.append(f"{rtype}: NXDOMAIN")
                records[rtype] = []
            except dns.resolver.LifetimeTimeout:
                errors.append(f"{rtype}: timeout")
                records[rtype] = []
            except Exception as e:
                errors.append(f"{rtype}: {e}")
                records[rtype] = []

        has_any = any(v for v in records.values())
        if has_any:
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"dns_records": records, "record_count": sum(len(v) for v in records.values())},
            )

        return ToolResult(
            tool=self.name, status="error", capability=self.capability,
            error=f"No DNS records found. Errors: {'; '.join(errors)}" if errors else "No DNS records found for target.",
            results={"dns_records": records, "record_count": 0},
        )
