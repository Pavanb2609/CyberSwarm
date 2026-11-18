"""
zap_scan.py — OWASP ZAP active scanner adapter (the free-tier fallback).

CyberSwarm's active-scan slot is filled by whichever engine is available:

    Burp Professional  -> burp_scan.py   (Burp's own REST scanner)
    Burp Community     -> nothing         (Community has no scanner engine)
    neither            -> THIS            (ZAP, the standard free active scanner)

ZAP is the right fallback because, unlike Burp Community, it ships a complete
scanner reachable over a documented HTTP API. This tool drives that API:
spider the target, run the active scanner, harvest the alerts, map them to
CyberSwarm findings.

Availability, matching the rest of the tooling:

  * ZAP API unreachable AND no ZAP binary to launch -> status "not_installed",
    the planner skips the active-scan agent, the pipeline carries on.
  * ZAP reachable, clean scan                        -> success, no findings.
  * ZAP reachable, alerts                            -> HIGH/MEDIUM/LOW findings.

ZAP's daemon exposes its API on 127.0.0.1:8080 by default. An API key is
recommended and supported; without one, ZAP still answers on loopback. This is
a REST tool, not a subprocess tool, so it overrides Tool.run directly and only
shells out when it needs to LAUNCH a stopped-but-installed ZAP.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except Exception:  # noqa: BLE001
    _requests = None  # type: ignore[assignment]
    _HAS_REQUESTS = False

from tools.base import Tool, ToolResult

# ZAP risk names -> CyberSwarm severities.
_RISK_MAP = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
}

DEFAULT_TIMEOUT_S = 1800
POLL_INTERVAL_S = 5
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
START_TIMEOUT_S = 90


class ZAPService:
    """Locates, launches and health-checks a ZAP daemon."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config if isinstance(config, dict) else {}
        self.host = str(cfg.get("host", DEFAULT_HOST) or DEFAULT_HOST)
        self.port = int(cfg.get("port", DEFAULT_PORT) or DEFAULT_PORT)
        self.api_key = str(cfg.get("api_key", "") or "")
        # Explicit path to zap.sh / zap.bat, else auto-detected on PATH.
        self.zap_path = str(cfg.get("path", "") or "")
        self.timeout = int(cfg.get("timeout", DEFAULT_TIMEOUT_S) or DEFAULT_TIMEOUT_S)
        self.auto_start = bool(cfg.get("auto_start", True))
        self._proc: Optional[subprocess.Popen] = None

    @property
    def base(self) -> str:
        return f"http://{self.host}:{self.port}"

    def _binary(self) -> Optional[str]:
        if self.zap_path and os.path.exists(self.zap_path):
            return self.zap_path
        for name in ("zap.sh", "zap", "zaproxy", "owasp-zap", "zap.bat"):
            found = shutil.which(name)
            if found:
                return found
        return None

    def is_installed(self) -> bool:
        return self._binary() is not None

    def healthcheck(self) -> bool:
        """True if the ZAP API answers. Uses the always-present version call."""
        try:
            self._api_get("core/view/version")
            return True
        except Exception:  # noqa: BLE001
            return False

    def start(self) -> bool:
        """Launch ZAP in daemon mode. True if the process started."""
        if self.healthcheck():
            return True
        if not self.auto_start:
            return False
        binary = self._binary()
        if not binary:
            return False
        cmd = [binary, "-daemon", "-host", self.host, "-port", str(self.port),
               "-config", "api.addrs.addr.name=.*",
               "-config", "api.addrs.addr.regex=true"]
        if self.api_key:
            cmd += ["-config", f"api.key={self.api_key}"]
        else:
            cmd += ["-config", "api.disablekey=true"]
        try:
            devnull = open(os.devnull, "w")
            self._proc = subprocess.Popen(cmd, stdout=devnull, stderr=devnull)
        except OSError:
            self._proc = None
            return False
        return True

    def wait_until_ready(self, timeout_s: Optional[float] = None) -> bool:
        deadline = time.time() + (timeout_s or START_TIMEOUT_S)
        while time.time() < deadline:
            if self.healthcheck():
                return True
            if self._proc is not None and self._proc.poll() is not None:
                return False
            time.sleep(2)
        return False

    def stop(self) -> None:
        """Shut down a ZAP we launched. Leaves an externally-started one alone."""
        if self._proc is None:
            return
        try:
            self._api_get("core/action/shutdown")
        except Exception:  # noqa: BLE001
            try:
                self._proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        self._proc = None

    # ── REST plumbing ────────────────────────────────────────────────────────

    def _url(self, component_view_action: str, params: Dict[str, Any]) -> str:
        query = dict(params or {})
        if self.api_key:
            query["apikey"] = self.api_key
        return (f"{self.base}/JSON/{component_view_action}/"
                f"?{urllib.parse.urlencode(query)}")

    def _api_get(self, component_view_action: str,
                 params: Optional[Dict[str, Any]] = None,
                 timeout: int = 30) -> Dict[str, Any]:
        url = self._url(component_view_action, params or {})
        if _HAS_REQUESTS and _requests is not None:
            resp = _requests.get(url, timeout=timeout)
            if resp.status_code >= 400:
                raise RuntimeError(f"ZAP API {resp.status_code}: {resp.text[:200]}")
            return resp.json()
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            return json.loads(body) if body.strip() else {}


class ZAPScanTool(Tool):
    name = "zap_scan"
    capability = "ACTIVE_SCAN"
    binary = ""  # REST tool

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config if isinstance(config, dict) else {}
        injected = cfg.get("service")
        self._svc: ZAPService = injected if injected else ZAPService(cfg or None)
        self._config = cfg

    # ── availability ─────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Reachable now, or installed and launchable."""
        return self._svc.healthcheck() or self._svc.is_installed()

    def validate(self) -> Optional[str]:
        if not self.is_available():
            return ("OWASP ZAP is not reachable and no ZAP binary was found. "
                    "Install ZAP (https://www.zaproxy.org/download/) or point "
                    "zap.path at zap.sh. This is the free active-scan fallback "
                    "for when Burp Professional is unavailable.")
        return None

    def ensure_running(self) -> bool:
        if self._svc.healthcheck():
            return True
        if not self._svc.start():
            return False
        return self._svc.wait_until_ready()

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    # ── entry point ──────────────────────────────────────────────────────────

    def run(self, target: str, timeout: Optional[int] = DEFAULT_TIMEOUT_S,
            **kwargs: Any) -> ToolResult:
        if not self.ensure_running():
            return ToolResult(tool=self.name, status="not_installed",
                              capability=self.capability,
                              error="ZAP API unavailable and could not be launched.")

        raw_timeout = kwargs.get("timeout", timeout)
        try:
            deadline_budget = int(raw_timeout) if raw_timeout is not None else DEFAULT_TIMEOUT_S
        except (TypeError, ValueError):
            deadline_budget = DEFAULT_TIMEOUT_S
        deadline = time.time() + max(deadline_budget, 30)

        url = kwargs.get("url") or target
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            self._spider(url, deadline)
            self._active_scan(url, deadline)
            alerts = self._alerts(url)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(tool=self.name, status="error",
                              capability=self.capability,
                              error=f"zap_scan failed: {exc}")

        findings = self._to_findings(alerts)
        return ToolResult(tool=self.name, status="success",
                          capability=self.capability,
                          results={"zap_alerts": findings,
                                   "total_alerts": len(findings), "url": url})

    # ── scan phases ──────────────────────────────────────────────────────────

    def _spider(self, url: str, deadline: float) -> None:
        """Crawl to build the site tree the active scanner needs."""
        try:
            resp = self._svc._api_get("spider/action/scan", {"url": url})
        except Exception:  # noqa: BLE001 - spider is best effort
            return
        scan_id = resp.get("scan")
        if scan_id is None:
            return
        while time.time() < deadline:
            status = self._svc._api_get("spider/view/status", {"scanId": scan_id})
            if int(status.get("status", 100) or 0) >= 100:
                break
            time.sleep(POLL_INTERVAL_S)

    def _active_scan(self, url: str, deadline: float) -> None:
        resp = self._svc._api_get("ascan/action/scan", {"url": url})
        scan_id = resp.get("scan")
        if scan_id is None:
            return
        while time.time() < deadline:
            status = self._svc._api_get("ascan/view/status", {"scanId": scan_id})
            if int(status.get("status", 0) or 0) >= 100:
                return
            time.sleep(POLL_INTERVAL_S)
        # Timed out: stop the scan so alerts collected so far are still usable.
        try:
            self._svc._api_get("ascan/action/stop", {"scanId": scan_id})
        except Exception:  # noqa: BLE001
            pass

    def _alerts(self, url: str) -> List[Dict[str, Any]]:
        resp = self._svc._api_get("alert/view/alerts", {"baseurl": url})
        alerts = resp.get("alerts")
        return alerts if isinstance(alerts, list) else []

    @staticmethod
    def _to_findings(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate ZAP alerts by (name, url) and map to CyberSwarm shape."""
        seen: Dict[str, Dict[str, Any]] = {}
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            name = alert.get("alert") or alert.get("name") or "ZAP alert"
            target_url = alert.get("url", "")
            key = f"{name}|{target_url}"
            if key in seen:
                continue
            seen[key] = {
                "name": name,
                "severity": _RISK_MAP.get(str(alert.get("risk", "")).lower(), "LOW"),
                "confidence": alert.get("confidence", "Medium"),
                "url": target_url,
                "param": alert.get("param", ""),
                "description": str(alert.get("description", ""))[:800],
                "solution": str(alert.get("solution", ""))[:600],
                "cwe": alert.get("cweid", ""),
                "reference": str(alert.get("reference", ""))[:300],
            }
        return list(seen.values())
