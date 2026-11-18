"""
burp_scan.py — Burp Suite Professional Active Scanner adapter (optional).

Drives Burp's REST API (loopback port 1337, Professional edition) to run an
active scan against a web target and folds the results back as CyberSwarm
findings. Burp is an OPTIONAL enhancement:

  * If the REST API is unreachable (Community edition / misconfigured), the
    tool reports ``status="not_installed"`` and the planner skips the ``burp``
    agent -- it never crashes the pipeline.
  * If Burp is reachable but returns no issues, the tool reports
    ``status="success"`` with an empty issue list.

This is a REST tool, not a subprocess tool, so it overrides ``Tool.is_available``
and ``Tool.run`` directly.

REST flow
---------
    POST /v0.1/scan            {"urls": [...], "scope": {"include": [...]}}
        -> 201, task id in the Location header (or "task_id" in the body)
    GET  /v0.1/scan/<task_id>  -> {"scan_status", "scan_metrics", "issue_events"}

Findings come from ``issue_events``, which are the issues Burp actually found
on the target. They must not be confused with
``/v0.1/knowledge_base/issue_definitions``, which is Burp's static catalogue
of every issue type it knows about, unrelated to any scan.
"""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any, Dict, List, Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except Exception:  # noqa: BLE001
    _requests = None  # type: ignore[assignment]
    _HAS_REQUESTS = False

from burp_service import BurpService, get_burp_service
from tools.base import Tool, ToolResult

_SEV_MAP = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "information": "INFO",
}

# Burp scan_status values that mean "this task will not progress further".
_TERMINAL_STATUSES = {"succeeded", "succeeded_with_errors", "failed",
                      "aborted", "cancelled", "canceled"}

DEFAULT_TIMEOUT_S = 3600
POLL_INTERVAL_S = 5


class BurpScanTool(Tool):
    name = "burp_scan"
    capability = "burp-scanner"
    binary = ""  # not a subprocess tool

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config if isinstance(config, dict) else {}
        injected = cfg.get("service")
        self._svc: BurpService = injected if injected else get_burp_service(cfg or None)
        self._config: Dict[str, Any] = cfg

    # ── Availability ─────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Burp is 'installed' only if the REST API healthcheck succeeds."""
        return self._svc.healthcheck()

    def validate(self) -> Optional[str]:
        if not self.is_available():
            return ("Burp REST API not reachable (host=%s, port=%s). Requires Burp "
                    "Suite Professional with the REST API enabled; check "
                    "burp_service / burp.api config. Skipping burp agent."
                    % (self._svc.api_host, self._svc.api_port))
        return None

    def ensure_running(self, target: str = "cyberswarm") -> bool:
        """Ensure Burp is up and ready, launching it if needed.

        Launching is what makes the agent usable on a machine where Burp is
        installed but not running -- which is the normal state.
        """
        if self._svc.healthcheck():
            return True
        if not self._svc.start(target):
            return False
        return self._svc.wait_until_ready()

    def build_command(self, target: str, **kwargs) -> List[str]:
        """Not a subprocess tool; the REST flow in run() applies instead."""
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    # ── Scan payload ─────────────────────────────────────────────────────────

    def _scan_config(self, url: str, project_options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Build the POST /scan body for a single URL.

        Only keys Burp's REST schema actually accepts are sent; unknown keys
        make Burp reject the whole request with a 400.
        """
        payload: Dict[str, Any] = {
            "urls": [url],
            "scope": {"include": [{"rule": url}]},
        }
        for key in ("scan_configurations", "application_logins",
                    "resource_pool", "scan_callback", "protocol_option", "name"):
            value = (project_options or {}).get(key)
            if value:
                payload[key] = value
        return payload

    # ── Entry point ──────────────────────────────────────────────────────────

    def run(self, target: str, timeout: Optional[int] = DEFAULT_TIMEOUT_S,
            **kwargs) -> ToolResult:
        if not self.ensure_running(str(kwargs.get("project_target") or target)):
            return ToolResult(tool=self.name, status="not_installed",
                              capability=self.capability,
                              error="Burp REST API unavailable; cannot run scan.")

        urls = kwargs.get("urls") or [target]
        project_options = kwargs.get("project_options") or {}
        config = kwargs.get("config") or {}
        # Callers legitimately pass timeout=None to mean "use the default";
        # int(None) would raise, so coalesce before converting.
        raw_timeout = kwargs.get("timeout", timeout)
        if raw_timeout is None:
            raw_timeout = timeout if timeout is not None else DEFAULT_TIMEOUT_S
        try:
            _timeout = int(raw_timeout)
        except (TypeError, ValueError):
            _timeout = DEFAULT_TIMEOUT_S

        base = self._svc._rest_url("")

        try:
            scan_ids = self._start_scan(base, config, project_options, urls)
            if not scan_ids:
                return ToolResult(tool=self.name, status="success", capability=self.capability,
                                  results={"burp_issues": [], "total_issues": 0,
                                           "message": "Scan not accepted by Burp REST API."})
            issues = self._collect_issues(base, scan_ids, _timeout)
        except Exception as e:  # noqa: BLE001
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error=f"burp_scan failed: {e}")

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"burp_issues": issues, "total_issues": len(issues),
                                   "scan_ids": scan_ids})

    # ── REST plumbing ────────────────────────────────────────────────────────

    def _request(self, method: str, url: str, payload: Any = None, timeout: int = 30):
        if _HAS_REQUESTS and _requests is not None:
            fn = getattr(_requests, method.lower())
            kw = {"json": payload} if payload is not None else {}
            return fn(url, timeout=timeout, **kw)
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method.upper(),
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            obj = json.loads(body) if body.strip() else None
            return _SimpleResp(resp.status, resp.headers, obj)

    @staticmethod
    def _json(resp: Any) -> Any:
        """Decode a response body from either a requests.Response or _SimpleResp.

        requests.Response has .json() and no .obj; reading .obj unconditionally
        raises AttributeError whenever requests is installed.
        """
        if resp is None:
            return None
        if hasattr(resp, "obj"):
            return resp.obj
        try:
            return resp.json()
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _header(resp: Any, name: str) -> str:
        try:
            headers = resp.headers
        except AttributeError:
            return ""
        for key in (name, name.lower(), name.title()):
            try:
                value = headers.get(key)
            except Exception:  # noqa: BLE001
                value = None
            if value:
                return str(value)
        return ""

    def _start_scan(self, base: str, config: Dict[str, Any],
                    project_options: Optional[Dict[str, Any]], urls: List[str]) -> List[str]:
        """POST /scan once per URL; return the resulting task ids.

        Each request carries only its own URL. Sending the full URL list on
        every request would start N identical whole-surface scans.
        """
        ids: List[str] = []
        for url in urls:
            payload = self._scan_config(url, project_options)
            payload.update(config.get("scan", {}) or {})
            try:
                resp = self._request("POST", f"{base}/scan", payload)
            except Exception:  # noqa: BLE001
                continue
            scan_id = ""
            location = self._header(resp, "Location")
            if location:
                scan_id = location.rstrip("/").split("/")[-1]
            if not scan_id:
                body = self._json(resp)
                if isinstance(body, dict) and body.get("task_id") is not None:
                    scan_id = str(body["task_id"])
            if scan_id:
                ids.append(scan_id)
        return ids

    def _collect_issues(self, base: str, scan_ids: List[str], timeout_s: int) -> List[Dict[str, Any]]:
        """Poll each scan to completion, then harvest its issue_events.

        On timeout the issues found so far are still returned -- a partial
        result beats discarding a scan that ran for an hour.
        """
        deadline = time.time() + max(float(timeout_s), 0.0)
        issues: Dict[str, Dict[str, Any]] = {}

        for scan_id in scan_ids:
            latest: Dict[str, Any] = {}
            while time.time() < deadline:
                body = self._json(self._safe_get(f"{base}/scan/{scan_id}"))
                if isinstance(body, dict):
                    latest = body
                    status = str(body.get("scan_status", "")).lower()
                    if status in _TERMINAL_STATUSES:
                        break
                time.sleep(POLL_INTERVAL_S)
            else:
                # Deadline hit: take one last reading so a slow scan still reports.
                body = self._json(self._safe_get(f"{base}/scan/{scan_id}"))
                if isinstance(body, dict):
                    latest = body

            for event in latest.get("issue_events") or []:
                issue = event.get("issue") if isinstance(event, dict) else None
                if not isinstance(issue, dict):
                    continue
                parsed = self._parse_issue(issue)
                key = f"{parsed['name']}|{parsed['path']}"
                if key not in issues:
                    issues[key] = parsed
        return list(issues.values())

    def _safe_get(self, url: str):
        try:
            return self._request("GET", url)
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _parse_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
        """Map one Burp issue object onto CyberSwarm's finding shape."""
        origin = str(issue.get("origin", "") or "")
        path = str(issue.get("path", "") or "")
        return {
            "name": issue.get("name", "Burp issue"),
            "severity": _SEV_MAP.get(str(issue.get("severity", "")).lower(), "MEDIUM"),
            "confidence": issue.get("confidence", "Certain"),
            "url": f"{origin}{path}" if origin or path else "",
            "path": path,
            "description": (issue.get("issue_detail") or issue.get("description")
                            or issue.get("issue_background") or "")[:800],
            "remediation": (issue.get("remediation_detail")
                            or issue.get("remediation_background") or "")[:800],
            "evidence": [
                str(e.get("type", ""))
                for e in (issue.get("evidence") or [])
                if isinstance(e, dict)
            ][:5],
        }


class _SimpleResp:
    """Minimal stand-in for a requests.Response when requests is unavailable."""

    def __init__(self, status: int, headers: Any, obj: Any):
        self.status_code = status
        self.headers = self._headers_dict(headers)
        self.obj = obj

    @staticmethod
    def _headers_dict(headers: Any) -> Dict[str, str]:
        out: Dict[str, str] = {}
        try:
            for k, v in headers.items():
                out[k.lower()] = v
        except Exception:  # noqa: BLE001
            pass
        return out
