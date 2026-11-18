"""
burp_service.py — Burp Suite daemon lifecycle manager (optional enhancement).

CyberSwarm drives Burp Suite Professional's ACTIVE SCANNER through the
official REST API (default loopback port 1337). This module manages the
headless Burp process:

    BurpService.start()            -> launch headless Burp
    BurpService.wait_until_ready() -> poll the REST API until it answers
    BurpService.healthcheck()      -> confirm the REST API (and Professional edition)
    BurpService.stop()             -> process cleanup

Burp is treated as an OPTIONAL enhancement: if Burp is Community edition
(no REST API), or the REST API is unreachable, the planner simply skips the
``burp`` agent. This module never raises into the caller for a mere
missing/unreachable Burp -- it reports availability via booleans so the rest
of the pipeline degrades cleanly.

Enabling the REST API
---------------------
Burp's REST API is switched on inside Burp itself (Settings -> Suite -> REST
API), where you also generate the API key. That setting lives in Burp's user
configuration, so to run headless you export that user config from Burp once
and point ``burp.user_config`` at the exported file. CyberSwarm does not
fabricate a user-config file: the schema is Burp's own and writing a guessed
one silently produces a Burp that starts without the API enabled.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except Exception:  # noqa: BLE001
    _requests = None  # type: ignore[assignment]
    _HAS_REQUESTS = False


class BurpService:
    """Manages a single headless Burp Suite process for CyberSwarm."""

    DEFAULT_PORT = 1337
    DEFAULT_HOST = "127.0.0.1"
    START_TIMEOUT_S = 120
    REQUEST_TIMEOUT_S = 30

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.home: str = cfg.get("home", "/home/ubuntu/BurpSuite")
        self.jar: str = cfg.get("jar", "") or ""
        self.api_host: str = cfg.get("api_host", self.DEFAULT_HOST)
        self.api_port: int = int(cfg.get("api_port", self.DEFAULT_PORT))
        self.api_key: str = str(cfg.get("api_key", "") or "")
        # Burp's REST API listens on plain HTTP by default. Overridable only
        # for the unusual case of a TLS-terminating proxy in front of it.
        self.scheme: str = str(cfg.get("scheme", "http") or "http")
        self.headless: bool = bool(cfg.get("headless", True))
        self.user_config: str = cfg.get("user_config", "") or ""
        self._edition_override: str = cfg.get("edition", "") or ""
        self.project_dir: str = cfg.get("project_dir", "") or ""
        self.project_config: str = cfg.get("project_config", "") or ""
        self.timeout: int = int(cfg.get("timeout", 3600))
        self._proc: Optional[subprocess.Popen] = None

    # ── Locations ────────────────────────────────────────────────────────────

    def _java(self) -> Optional[str]:
        """Path to a java executable (prefer Burp's bundled JRE, else PATH)."""
        bundled = Path(self.home) / "jre" / "bin" / "java"
        if bundled.exists() and os.access(bundled, os.X_OK):
            return str(bundled)
        return shutil.which("java")

    def _jar(self) -> Optional[Path]:
        """Locate the Burp jar: explicit config, then the conventional name,
        then any burpsuite*.jar in the install directory."""
        if self.jar:
            candidate = Path(self.jar)
            return candidate if candidate.exists() else None
        home = Path(self.home)
        conventional = home / "burpsuite.jar"
        if conventional.exists():
            return conventional
        try:
            matches = sorted(home.glob("burpsuite*.jar"))
        except OSError:
            return None
        return matches[0] if matches else None

    # ── REST addressing ──────────────────────────────────────────────────────

    @property
    def api_base(self) -> str:
        return f"{self.scheme}://{self.api_host}:{self.api_port}"

    def _rest_url(self, path: str = "") -> str:
        """Build a REST URL.

        Burp's key-authenticated form is ``/<api_key>/v0.1/<path>``; with no
        key configured the key segment is simply omitted.
        """
        if self.api_key:
            return f"{self.api_base}/{self.api_key}/v0.1{path}"
        return f"{self.api_base}/v0.1{path}"

    # ── Edition ──────────────────────────────────────────────────────────────

    def edition(self) -> str:
        """"pro", "community" or "unknown".

        Project files and the REST API are Professional features; Community
        rejects ``--project-file`` outright. Detection is by jar name, which is
        how PortSwigger ships them (burpsuite_pro_v*.jar /
        burpsuite_community_v*.jar), with a config override for odd layouts.
        """
        override = str(self._edition_override or "").strip().lower()
        if override in ("pro", "professional"):
            return "pro"
        if override in ("community", "free"):
            return "community"

        jar = self._jar()
        if jar is None:
            return "unknown"
        name = jar.name.lower()
        if "community" in name:
            return "community"
        if "pro" in name:
            return "pro"
        return "unknown"

    def supports_projects(self) -> bool:
        """Only Professional can open a project file."""
        return self.edition() == "pro"

    def is_installed(self) -> bool:
        """True when a jar and a JVM exist, whether or not Burp is running."""
        return self._jar() is not None and self._java() is not None

    def project_file_for(self, target: str) -> Path:
        """Per-target project file.

        A single shared project file means two targets' scan data land in one
        place and a second run reopens the first run's state. Names are
        sanitised because a target can contain anything.
        """
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in str(target))[:80]
        return Path(self.project_dir or self.home) / f"cyberswarm_{safe or 'target'}.burp"

    def ensure_executable(self) -> List[str]:
        """Make the bundled JRE runnable if it is not already.

        Burp archives unpacked without preserving the executable bit are a
        common cause of "Burp is installed but will not start". Returns the
        paths that were changed, for logging.
        """
        fixed: List[str] = []
        bundled = Path(self.home) / "jre" / "bin" / "java"
        for candidate in (bundled,):
            try:
                if candidate.exists() and not os.access(candidate, os.X_OK):
                    candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR
                                    | stat.S_IXGRP | stat.S_IXOTH)
                    fixed.append(str(candidate))
            except OSError:
                pass    # not fatal; _java() falls back to PATH
        return fixed

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self, target: str = "cyberswarm") -> bool:
        """Launch headless Burp for a target. True if the process started.

        Ready is a separate question -- call wait_until_ready() after this.
        """
        if self.is_running():
            return True

        # An unpacked archive that lost the executable bit is a common reason
        # Burp is present but will not launch, and the error it produces says
        # nothing useful. Repair it before giving up.
        fixed = self.ensure_executable()
        if fixed:
            log.info("Made Burp's bundled JRE executable: %s", ", ".join(fixed))

        java = self._java()
        if not java:
            log.warning("No JVM found. Install a JRE or set burp.home to an "
                        "install containing jre/bin/java.")
            return False
        jar = self._jar()
        if jar is None:
            log.warning("No Burp jar found under %s. Set burp.jar explicitly.",
                        self.home)
            return False

        cmd: List[str] = [java]
        if self.headless:
            cmd.append("-Djava.awt.headless=true")
        # Burp's launcher takes --flag=value; space-separated values are not parsed.
        cmd += ["-jar", str(jar)]

        # Project files are Professional-only. Passing --project-file to
        # Community makes it refuse to start, which looks like a crash.
        if self.supports_projects():
            project_file = self.project_file_for(target)
            try:
                project_file.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            cmd.append(f"--project-file={project_file}")
            log.info("Burp Professional: using project file %s", project_file)
        else:
            log.info("Burp edition is %s; starting without a project file "
                     "(projects are a Professional feature).", self.edition())

        cmd.append("--unpause-spider-and-scanner")
        if self.user_config:
            cmd.append(f"--user-config-file={self.user_config}")
        if self.project_config:
            cmd.append(f"--config-file={self.project_config}")
        else:
            cmd.append("--use-defaults")

        try:
            devnull = open(os.devnull, "w")
        except OSError:
            return False
        try:
            self._proc = subprocess.Popen(cmd, stdout=devnull, stderr=devnull,
                                          cwd=self.home)
        except OSError:
            devnull.close()
            self._proc = None
            return False
        return True

    def is_running(self) -> bool:
        if self._proc is None:
            return False
        return self._proc.poll() is None

    def wait_until_ready(self, timeout_s: Optional[float] = None) -> bool:
        deadline = time.time() + (timeout_s or self.START_TIMEOUT_S)
        while time.time() < deadline:
            if self.healthcheck():
                return True
            if self._proc is not None and self._proc.poll() is not None:
                return False  # process died before becoming ready
            time.sleep(2)
        return False

    def healthcheck(self) -> bool:
        """True if the Burp REST API responds (i.e. Professional + enabled).

        Hits the API root, which serves the self-documenting index. The
        api-key segment is included when configured, so a wrong key fails
        here rather than at scan time.
        """
        try:
            req = urllib.request.Request(self._rest_url(""), method="GET")
            with urllib.request.urlopen(req, timeout=self.REQUEST_TIMEOUT_S) as resp:
                return 200 <= getattr(resp, "status", 0) < 300
        except Exception:  # noqa: BLE001
            return False

    def stop(self) -> None:
        """Shut Burp down. The REST API exposes no shutdown verb, so this is a
        process-level terminate with a kill fallback."""
        if self._proc is not None:
            try:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            except Exception:  # noqa: BLE001
                pass
            self._proc = None


# Convenience singleton accessor so tools/agents share one daemon instance.
_service: Optional[BurpService] = None
_service_config: Optional[Dict[str, Any]] = None


def get_burp_service(config: Optional[Dict[str, Any]] = None) -> BurpService:
    """Shared BurpService.

    If a caller supplies a config that differs from the one the current
    singleton was built with, the singleton is rebuilt -- otherwise the first
    (often config-less) caller would pin everyone to default host/port/key.
    """
    global _service, _service_config
    if _service is None:
        _service = BurpService(config)
        _service_config = dict(config) if config else None
    elif config and config != _service_config:
        _service = BurpService(config)
        _service_config = dict(config)
    return _service


def reset_burp_service() -> None:
    """Drop the singleton (used by tests)."""
    global _service, _service_config
    _service = None
    _service_config = None
