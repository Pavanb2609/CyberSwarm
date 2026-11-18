import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class ArjunTool(Tool):
    name = "arjun"
    capability = "PARAMETER_DISCOVERY"
    binary = "arjun"

    def __init__(self):
        self._json_path = Path(tempfile.mktemp(suffix=".json"))

    def run(self, target: str, timeout: int = 180, **kwargs):
        """Probe the primary URL plus discovered paths for hidden params.

        arjun only tests the exact URL it is given, so a single root probe
        (the previous behaviour) misses the actual parameter-bearing endpoints
        found by content discovery. Iterate over them within the same budget.
        """
        import urllib.parse as _up

        from tools.base import ToolResult

        base = (kwargs.get("full_url") or
                (target if target.startswith("http") else f"http://{target}"))
        base = base.rstrip("/")
        urls = [base]
        candidates = list(kwargs.get("discovered_paths") or []) \
            + list(kwargs.get("endpoints") or [])
        for p in candidates[:12]:
            if isinstance(p, dict):
                p = str(p.get("url") or p.get("path") or "")
            if not isinstance(p, str) or not p:
                continue
            u = p if p.startswith("http") else _up.urljoin(base + "/", p.lstrip("/"))
            if u not in urls:
                urls.append(u)
        urls = urls[:6]

        merged: List[str] = []
        per_url = max(int(timeout) // max(len(urls), 1), 30)
        for u in urls:
            self._json_path = Path(tempfile.mktemp(suffix=".json"))
            result = self._run_single(u, timeout=per_url)
            for entry in result:
                if entry not in merged:
                    merged.append(entry)

        keep = [p for p in merged if p.startswith("http") and "?" in p]
        names = [p for p in merged if "/" not in p and "?" not in p]
        params = keep + names
        return ToolResult(tool=self.name, status="success",
                          capability=self.capability,
                          results={"discovered_parameters": params,
                                   "count": len(params)})

    def _run_single(self, url: str, timeout: int) -> List[str]:
        try:
            result = super().run(url, timeout=timeout)
        except Exception:  # noqa: BLE001
            return []
        parsed = (result.results or {}).get("discovered_parameters", []) \
            if result and result.status == "success" else []
        return parsed

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = (kwargs.get("full_url") or
               (target if target.startswith("http") else f"http://{target}"))
        return [self.binary, "-u", url, "-o", str(self._json_path), "-q"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        if not self._json_path.exists():
            return {"discovered_parameters": [], "count": 0}

        data = json.loads(self._json_path.read_text(encoding="utf-8"))
        self._json_path.unlink(missing_ok=True)

        params = []
        # arjun's JSON output is keyed by URL, each with a "params" list.
        # Emit full injectable URLs ("url?param=1") so downstream consumers
        # (system map -> injection targets) keep the URL association without
        # needing dict-shaped evidence entries.
        for url, details in data.items():
            base = url if url.startswith("http") else f"http://{url}"
            for p in details.get("params", []):
                entry = f"{base}?{p}=1"
                if entry not in params:
                    params.append(entry)
                if p not in params and "/" not in p:  # keep bare name for LLM context
                    params.append(p)

        return {"discovered_parameters": params, "count": len(params)}
