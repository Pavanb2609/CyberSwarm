"""
Attack Engine — the Phase-2 analogue of recon_engine.py.

Executes every registered attack action (or a chosen subset) against a target
and aggregates the tool results. Used by --run-all mode so the attack sweep
does not depend on the LLM planner.

Each action maps to one-or-more tools via attack_registry; the first available
tool runs (WAF/CDN-aware skipping is left to the calling agents).
"""

from typing import Any, Dict, List, Optional

from tools import attack_registry
from tools.base import ToolResult

ATTACK_TIMEOUTS: Dict[str, int] = {
    "TLS_VULN_SCAN": 600,
    "VULN_SCAN": 300,
    "WEB_VULN_SCAN": 300,
    "SERVICE_VULN_SCAN": 300,
    "SQLI_SCAN": 300,
    "XSS_SCAN": 300,
    "SUBDOMAIN_TAKEOVER_SCAN": 240,
    "CONTENT_DISCOVERY": 240,
    "CMD_INJECTION_SCAN": 240,
    "SECRETS_SCAN": 240,
}


def execute_action(action: str, target: str, timeout: int = 180, **kwargs) -> ToolResult:
    """Run the first available tool registered for an attack action."""
    tools = attack_registry.get_tools_for_action(action)
    if not tools:
        return ToolResult(tool="none", status="unsupported", capability=action,
                          error=f"No tool registered for action '{action}'. "
                                f"Supported: {attack_registry.supported_actions()}")
    for tool in tools:
        problem = tool.validate()
        if problem:
            continue
        result = tool.run(target, timeout=ATTACK_TIMEOUTS.get(action, timeout), **kwargs)
        result.capability = action
        return result
    tried = [f"{t.name}: {t.validate()}" for t in tools]
    return ToolResult(tool="none", status="not_installed", capability=action,
                      error=f"No available tool for '{action}'. Tried: {tried}")


def run_all(target: str, actions: Optional[List[str]] = None,
            timeout: int = 180, max_actions: Optional[int] = None, **kwargs) -> Dict[str, Any]:
    """Run every registered attack action (or the given subset) and aggregate."""
    chosen = actions or attack_registry.supported_actions()
    if max_actions:
        chosen = chosen[:max_actions]

    results: Dict[str, Any] = {}
    for action in chosen:
        tr = execute_action(action, target, timeout=timeout, **kwargs)
        results[action] = {
            "tool": tr.tool,
            "status": tr.status,
            "error": tr.error,
            "results": tr.results,
        }
        print(f"[run-all] {action:28s} -> {tr.tool:14s} {tr.status}"
              + (f" ({tr.error})" if tr.error else ""))
    return results
