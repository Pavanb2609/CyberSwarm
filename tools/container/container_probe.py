from typing import Any, Dict, List, Optional

from tools.base import Tool, ToolResult

# port -> (endpoint to hit, what a real API response looks like)
CONTAINER_PORTS = {
    2375: ("http://{host}:2375/version", "docker"),   # Docker API, unencrypted -- a real finding if open
    2376: ("https://{host}:2376/version", "docker"),  # Docker API, TLS
    6443: ("https://{host}:6443/version", "kubernetes"),  # Kubernetes API server
    10250: ("https://{host}:10250/pods", "kubelet"),      # Kubelet API
    8080: ("http://{host}:8080/version", "docker_or_k8s"),  # sometimes proxied Docker/K8s API
}


class ContainerDiscoveryTool(Tool):
    """
    Checks whether any already-discovered open ports look like an exposed
    Docker or Kubernetes API, and if so, queries the version endpoint (a
    read-only, unauthenticated call on a misconfigured target). Pure Python
    via `requests`, no external binary. Gated: only runs against ports that
    PORT_DISCOVERY already found open -- matches the planner prompt's rule
    that this capability needs container-platform evidence, not plausibility.
    """

    name = "container_probe"
    capability = "CONTAINER_DISCOVERY"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self) -> Optional[str]:
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        ports_str = kwargs.get("ports") or ""
        open_ports = {int(p) for p in ports_str.split(",") if p.strip().isdigit()}
        relevant = open_ports & CONTAINER_PORTS.keys()
        if not relevant:
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"container_discovery_skipped": True,
                         "reason": "None of the known Docker/Kubernetes API ports "
                                   "(2375, 2376, 6443, 8080, 10250) are in open_ports -- skipping."},
            )

        try:
            import requests
        except ImportError as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                               error=f"'requests' package not available: {e}")

        host = target.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        session = requests.Session()
        per_request_timeout = kwargs.get("per_request_timeout", 6)

        found: List[Dict[str, Any]] = []
        for port in relevant:
            url_tpl, platform = CONTAINER_PORTS[port]
            url = url_tpl.format(host=host)
            try:
                resp = session.get(url, timeout=per_request_timeout, verify=False)
            except requests.exceptions.RequestException:
                continue
            if resp.status_code < 500:  # even a 401/403 confirms a real API is listening
                found.append({
                    "port": port, "platform": platform, "url": url,
                    "status": resp.status_code,
                    "unauthenticated_access": resp.status_code == 200,
                    "response_sample": (resp.text or "")[:300],
                })

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"container_apis_found": found, "count": len(found)},
        )
