"""
The Recon Engine is the only thing that knows how to turn a capability
into an actual tool execution. The planner never talks to this directly --
it only emits a capability name, and the executor layer (recon_loop.py)
calls execute_capability() after a human has approved that capability.

Every execution is also recorded against the tool's reliability history
(results/tool_memory.json), which feeds the RAG memory, the dashboard and
action scoring. Recording happens here because this is the single place all
capability executions pass through -- doing it in the callers would mean
every new caller silently loses tracking.
"""

import time
from typing import Any, Dict, Optional

from tools import registry
from tools.base import ToolResult

# Per-capability timeout overrides (seconds).  Tools not listed here use the
# global default passed via ``timeout``.
CAPABILITY_TIMEOUTS: Dict[str, int] = {
    "TLS_ANALYSIS": 600,
}

# Statuses that say nothing about how reliable a tool is. A binary that is not
# installed has not failed -- counting it as a failure would drive its
# reliability to zero and teach the RAG index a lesson that is simply untrue.
_NOT_A_RELIABILITY_SIGNAL = frozenset({"not_installed", "unsupported"})

_manager = None


def _default_manager():
    """Lazily build the shared ToolManager. None if it cannot be constructed."""
    global _manager
    if _manager is None:
        try:
            from tool_manager import ToolManager
            _manager = ToolManager()
        except Exception:  # noqa: BLE001 - tracking is never worth a crash
            _manager = False
    return _manager or None


def record_execution(tool_name: str, status: str, duration_s: float,
                     quality: float = 0.0, tool_manager: Optional[Any] = None) -> None:
    """Fold one execution into the tool's reliability history.

    Best effort throughout: a tracking failure must not take down a run that
    otherwise succeeded.
    """
    if status in _NOT_A_RELIABILITY_SIGNAL:
        return
    manager = tool_manager if tool_manager is not None else _default_manager()
    if manager is None:
        return
    try:
        manager.record_result(tool_name, status, duration_s, quality)
        # Timeouts are failures, but the distinction is what tells you to raise
        # a limit rather than swap the tool, so keep it separately.
        if status == "timeout":
            entry = manager._entry(tool_name)          # noqa: SLF001
            entry["timeout_failures"] = entry.get("timeout_failures", 0.0) + 1
        manager.save()
    except Exception:  # noqa: BLE001
        pass


def _quality(result: ToolResult) -> float:
    """Rough 0-1 usefulness of a result, for the quality average.

    A tool that runs cleanly but finds nothing is working correctly; it just
    had nothing to report. It scores lower than a tool that produced findings,
    but well above one that errored.
    """
    if result.status != "success":
        return 0.0
    payload = getattr(result, "results", None)
    if not isinstance(payload, dict) or not payload:
        return 0.4
    non_empty = sum(1 for v in payload.values() if v not in (None, "", [], {}))
    return 1.0 if non_empty else 0.4


def execute_capability(capability: str, target: str, timeout: int = 180,
                       tool_manager: Optional[Any] = None, **kwargs) -> ToolResult:
    tools = registry.get_tools_for_capability(capability)

    if not tools:
        return ToolResult(
            tool="none", status="unsupported", capability=capability,
            error=f"No tool registered for capability '{capability}'. "
                  f"Supported: {registry.supported_capabilities()}",
        )

    tried = []
    for tool in tools:
        problem = tool.validate()
        if problem:
            tried.append(f"{tool.name}: {problem}")
            continue

        started = time.monotonic()
        try:
            result = tool.run(target, timeout=CAPABILITY_TIMEOUTS.get(capability, timeout),
                              **kwargs)
        except Exception as exc:  # noqa: BLE001
            # An exception is a failure of that tool, and the history should say
            # so rather than losing the attempt entirely.
            record_execution(tool.name, "error", time.monotonic() - started,
                             tool_manager=tool_manager)
            raise
        duration = time.monotonic() - started

        result.capability = capability  # tag with the requested capability, not the tool's own default
        record_execution(tool.name, result.status, duration, _quality(result),
                         tool_manager=tool_manager)
        return result

    return ToolResult(
        tool="none", status="not_installed", capability=capability,
        error=f"No available tool for '{capability}'. Tried: {tried}",
    )
