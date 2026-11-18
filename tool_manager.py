"""
ToolManager wraps the recon and attack tool registries with a reliability-aware,
capability-driven execution layer.

It adds what the raw registries and the Recon Engine do not:
  - capability/action -> ordered tool chain resolution (recon or attack)
  - reliability-aware chain ordering (tools that historically succeed get
    tried first) without requiring an LLM
  - automatic fallback: if a tool hits a runtime error or times out, the next
    tool in the chain is tried instead of ending the assessment
  - strict retry limits so we never hammer the same failing tool
  - per-tool performance memory persisted to results/tool_memory.json
  - risk classification (PASSIVE / ACTIVE_LOW / ACTIVE_HIGH) so the
    Controller can respect authorization and blast-radius limits
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import tools.registry as _recon_registry
import tools.attack_registry as _attack_registry
from tools.base import Tool, ToolResult

RISK_PASSIVE = "PASSIVE"
RISK_ACTIVE_LOW = "ACTIVE_LOW"
RISK_ACTIVE_HIGH = "ACTIVE_HIGH"
RISK_LEVELS = (RISK_PASSIVE, RISK_ACTIVE_LOW, RISK_ACTIVE_HIGH)

DEFAULT_MEMORY_PATH = Path("results") / "tool_memory.json"
DEFAULT_MAX_ATTEMPTS = 3

_PASSIVE_TOOL_NAMES = {
    "subfinder", "amass", "gau", "waybackurls", "dns_resolve", "dns_enum",
    "cert_info", "searchsploit",
}

_PASSIVE_HINTS = ("subfinder", "amass", "waybackurls", "dns_resolv", "dns_enum", "cert_info", "searchsploit")

_HIGH_RISK_HINTS = (
    "exploit", "bypass", "payloads", "fixation", "hijack",
    "brute", "hydra", "medusa", "default_creds", "default_creds",
    "sqlmap", "commix", "dalfox", "sqli", "xss", "xxe", "crlf",
    "ssti", "lfi", "ssrf", "cmdi", "deserialization", "file_upload",
)


def tool_risk_level(tool_name: str) -> str:
    """Classify a tool by blast radius: PASSIVE, ACTIVE_LOW, or ACTIVE_HIGH."""
    name = (tool_name or "").lower()
    if name in _PASSIVE_TOOL_NAMES:
        return RISK_PASSIVE
    if any(hint in name for hint in _HIGH_RISK_HINTS):
        return RISK_ACTIVE_HIGH
    return RISK_ACTIVE_LOW


def output_quality(result: ToolResult) -> float:
    """Estimate how much structured signal a ToolResult produced (0..1)."""
    if result.status != "success":
        return 0.0
    results = result.results or {}
    nonempty = [v for v in results.values() if v not in (None, "", [], {})]
    if not results:
        return 0.3
    if not nonempty:
        return 0.3
    return min(1.0, 0.5 + 0.1 * len(nonempty))


@dataclass
class ToolAttempt:
    tool: str
    status: str
    duration_s: float
    quality: float
    error: Optional[str] = None


@dataclass
class ExecutionRecord:
    capability: str
    target: str
    attempts: List[ToolAttempt] = field(default_factory=list)
    final_status: str = ""
    chosen_tool: Optional[str] = None
    fell_back: bool = False
    total_duration_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability,
            "target": self.target,
            "attempts": [
                {"tool": a.tool, "status": a.status, "duration_s": round(a.duration_s, 3),
                 "quality": round(a.quality, 3), "error": a.error}
                for a in self.attempts
            ],
            "final_status": self.final_status,
            "chosen_tool": self.chosen_tool,
            "fell_back": self.fell_back,
            "total_duration_s": round(self.total_duration_s, 3),
        }


class ToolManager:
    """Reliability-aware capability execution with fallback and memory."""

    def __init__(
        self,
        recon_loader: Optional[Callable[[str], Tool]] = None,
        attack_loader: Optional[Callable[[str], Tool]] = None,
        memory_path: Optional[Path] = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        self._recon_loader = recon_loader or _recon_registry.load_tool
        self._attack_loader = attack_loader or _attack_registry.load_attack_tool
        self.memory_path = Path(memory_path) if memory_path else DEFAULT_MEMORY_PATH
        self.max_attempts = max(1, int(max_attempts))
        self.last_attempts: List[ToolAttempt] = []
        self.last_execution: Optional[ExecutionRecord] = None
        self._stats: Dict[str, Dict[str, float]] = {}
        self.load()

    # ------------------------------------------------------------------ memory
    def load(self) -> None:
        if self.memory_path.exists():
            try:
                data = json.loads(self.memory_path.read_text())
                self._stats = data.get("tools", {}) if isinstance(data, dict) else {}
            except (json.JSONDecodeError, OSError):
                self._stats = {}
        else:
            self._stats = {}

    def save(self) -> None:
        payload = {"version": 1, "tools": self._stats}
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        self.memory_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    def _entry(self, tool_name: str) -> Dict[str, float]:
        return self._stats.setdefault(
            tool_name, {"attempts": 0.0, "successes": 0.0, "failures": 0.0,
                        "total_duration": 0.0, "quality_sum": 0.0})

    def record_result(self, tool_name: str, status: str, duration_s: float,
                      quality: float = 0.0) -> None:
        e = self._entry(tool_name)
        e["attempts"] += 1
        e["total_duration"] += max(0.0, duration_s)
        if status == "success":
            e["successes"] += 1
            e["quality_sum"] += max(0.0, min(1.0, quality))
        else:
            e["failures"] += 1

    def reliability(self, tool_name: str) -> float:
        e = self._entry(tool_name)
        attempts = e["attempts"]
        if attempts <= 0:
            return 0.5
        return (e["successes"] + 1.0) / (attempts + 2.0)

    def mean_duration(self, tool_name: str) -> float:
        e = self._entry(tool_name)
        if e["attempts"] <= 0:
            return 0.0
        return e["total_duration"] / e["attempts"]

    def success_rate(self, tool_name: str) -> float:
        e = self._entry(tool_name)
        if e["attempts"] <= 0:
            return 0.0
        return e["successes"] / e["attempts"]

    def tool_stats(self, tool_name: str) -> Dict[str, Any]:
        return dict(self._entry(tool_name))

    def all_tool_stats(self) -> Dict[str, Dict[str, Any]]:
        return {name: dict(e) for name, e in sorted(self._stats.items())}

    def reset_stats(self, tool_name: Optional[str] = None) -> None:
        if tool_name is None:
            self._stats.clear()
        else:
            self._stats.pop(tool_name, None)

    # ------------------------------------------------------------- resolution
    def tool_names_for(self, capability: str, use_attack: bool = False) -> List[str]:
        if use_attack:
            return list(_attack_registry.ATTACK_TOOL_MAP.get(capability, []))
        return list(_recon_registry.CAPABILITY_TOOL_MAP.get(capability, []))

    def preferred_tool(self, capability: str, use_attack: bool = False) -> Optional[str]:
        names = self.tool_names_for(capability, use_attack=use_attack)
        return names[0] if names else None

    def get_tool_chain(self, capability: str, use_attack: bool = False) -> List[Tool]:
        loader = self._attack_loader if use_attack else self._recon_loader
        chain: List[Tool] = []
        for name in self.tool_names_for(capability, use_attack=use_attack):
            try:
                chain.append(loader(name))
            except Exception:  # noqa: BLE001 - bad wrapper must not kill the chain
                continue
        return chain

    def order_tool_chain(self, tools: List[Tool]) -> List[Tool]:
        """Sort by reliability descending; stable so equal reliability keeps
        the registry's preference order."""
        return sorted(tools, key=lambda t: -self.reliability(t.name))

    def risk_level_for_capability(self, capability: str, use_attack: bool = False) -> str:
        levels = [tool_risk_level(name) for name in self.tool_names_for(capability, use_attack=use_attack)]
        if not levels:
            return RISK_ACTIVE_LOW
        if RISK_ACTIVE_HIGH in levels:
            return RISK_ACTIVE_HIGH
        if RISK_PASSIVE in levels:
            return RISK_PASSIVE
        return RISK_ACTIVE_LOW

    # ------------------------------------------------------------ execution
    def _execute_chain(self, capability: str, target: str, tools: List[Tool],
                       timeout: int, max_attempts: Optional[int],
                       **kwargs: Any) -> ToolResult:
        record = ExecutionRecord(capability=capability, target=target)
        attempt_budget = min(len(tools), max_attempts or self.max_attempts)
        candidate_chains = self.order_tool_chain(tools)
        last: Optional[ToolResult] = None
        total_start = time.monotonic()

        for idx, tool in enumerate(candidate_chains[:attempt_budget]):
            t0 = time.monotonic()
            try:
                result = tool.run(target, timeout=timeout, **kwargs)
            except Exception as exc:  # noqa: BLE001
                result = ToolResult(tool=tool.name, status="error",
                                    capability=capability, error=f"runtime exception: {exc}")
            duration = time.monotonic() - t0
            quality = output_quality(result)
            self.record_result(tool.name, result.status, duration, quality)
            record.attempts.append(
                ToolAttempt(tool=tool.name, status=result.status, duration_s=duration,
                            quality=quality, error=result.error))
            last = result
            if result.status == "success":
                break

        record.total_duration_s = time.monotonic() - total_start
        self.last_execution = record
        self.last_attempts = record.attempts

        if last is None:
            empty = ToolResult(tool="", status="unsupported", capability=capability,
                               error=f"No tools registered for capability '{capability}'")
            self.record_result("__unsupported__", "error", 0.0)
            return empty

        self.last_execution.fell_back = len(record.attempts) > 1 or last.status != "success"
        self.last_execution.final_status = last.status
        self.last_execution.chosen_tool = last.tool if last.status == "success" else None
        return last

    def execute_capability(self, capability: str, target: str, timeout: int = 120,
                           max_attempts: Optional[int] = None,
                           force_tool: Optional[str] = None, **kwargs: Any) -> ToolResult:
        tools = self.get_tool_chain(capability, use_attack=False)
        if force_tool:
            tools = self._promote(tools, force_tool)
        return self._execute_chain(capability, target, tools, timeout, max_attempts,
                                   **kwargs)

    def execute_action(self, action: str, target: str, timeout: int = 120,
                       max_attempts: Optional[int] = None,
                       force_tool: Optional[str] = None, **kwargs: Any) -> ToolResult:
        tools = self.get_tool_chain(action, use_attack=True)
        if force_tool:
            tools = self._promote(tools, force_tool)
        return self._execute_chain(action, target, tools, timeout, max_attempts,
                                   **kwargs)

    def _promote(self, tools: List[Tool], tool_name: str) -> List[Tool]:
        order = []
        for t in tools:
            if t.name == tool_name:
                order.insert(0, t)
            else:
                order.append(t)
        if not any(t.name == tool_name for t in order):
            try:
                order.insert(0, self._recon_loader(tool_name))
            except Exception:  # noqa: BLE001
                pass
        return order