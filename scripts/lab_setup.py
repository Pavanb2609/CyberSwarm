#!/usr/bin/env python3
"""
lab_setup.py — spin up deliberately vulnerable lab targets for CyberSwarm.

    python scripts/lab_setup.py up         # start all labs
    python scripts/lab_setup.py up dvwa    # start just DVWA
    python scripts/lab_setup.py status     # check which are running
    python scripts/lab_setup.py down       # stop everything
    python scripts/lab_setup.py authorize  # add lab targets to scope

Every target started here is automatically authorized in
config/authorized_targets.json — you do not need to authorize them manually.

Labs available
--------------
  dvwa        Damn Vulnerable Web Application   http://localhost:8001
  juiceshop   OWASP Juice Shop                  http://localhost:8002
  webgoat     OWASP WebGoat                     http://localhost:8003
  vulnapi     Vulnerable API (VulnAPI)          http://localhost:8004

None of these need docker-compose — a single `docker run` per lab. The
containers are named cyberswarm_<lab> so they do not conflict with anything
else you are running.

Requirements: Docker. That is all.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent

LABS: Dict[str, Dict] = {
    "dvwa": {
        "name":        "DVWA (Damn Vulnerable Web Application)",
        "image":       "ghcr.io/digininja/dvwa:latest",
        "port":        8001,
        "container":   "cyberswarm_dvwa",
        "url":         "http://localhost:8001",
        "default_creds": ("admin", "password"),
        "ready_path":  "/",
        "notes": (
            "After startup visit http://localhost:8001/setup.php "
            "and click 'Create / Reset Database'. "
            "Default login: admin / password"
        ),
    },
    "juiceshop": {
        "name":        "OWASP Juice Shop",
        "image":       "bkimminich/juice-shop",
        "port":        8002,
        "container":   "cyberswarm_juiceshop",
        "url":         "http://localhost:8002",
        "default_creds": ("admin@juice-sh.op", "admin123"),
        "ready_path":  "/",
        "notes": "Full-stack JS app. Great for XSS, SQLi, broken auth.",
    },
    "webgoat": {
        "name":        "OWASP WebGoat",
        "image":       "webgoat/webgoat",
        "port":        8003,
        "container":   "cyberswarm_webgoat",
        "url":         "http://localhost:8003/WebGoat",
        "default_creds": ("guest", "guest"),
        "ready_path":  "/WebGoat",
        "notes": (
            "Java app covering OWASP Top 10 with lessons. "
            "Register a user on first visit."
        ),
    },
    "vulnapi": {
        "name":        "VulnAPI (deliberately vulnerable REST API)",
        "image":       "roottusk/vulnapi",
        "port":        8004,
        "container":   "cyberswarm_vulnapi",
        "url":         "http://localhost:8004",
        "default_creds": None,
        "ready_path":  "/",
        "notes": "REST API with OWASP API Top 10 vulnerabilities.",
    },
}


def docker_available() -> bool:
    return shutil.which("docker") is not None


def _run(cmd: List[str], capture: bool = True) -> Tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=capture, text=True, timeout=120)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        return 1, "timed out"
    except OSError as exc:
        return 1, str(exc)


def container_running(name: str) -> bool:
    rc, out = _run(["docker", "inspect", "--format", "{{.State.Running}}", name])
    return rc == 0 and out.strip() == "true"


def container_exists(name: str) -> bool:
    rc, _ = _run(["docker", "inspect", name])
    return rc == 0


def start_lab(key: str) -> bool:
    lab = LABS[key]
    name = lab["container"]
    port = lab["port"]

    if container_running(name):
        print(f"  {key}: already running on port {port}")
        return True

    if container_exists(name):
        print(f"  {key}: restarting existing container...")
        rc, out = _run(["docker", "start", name])
        if rc != 0:
            print(f"  {key}: failed to restart: {out}")
            return False
    else:
        print(f"  {key}: pulling {lab['image']} ...")
        _run(["docker", "pull", lab["image"]])
        print(f"  {key}: starting on port {port} ...")
        rc, out = _run([
            "docker", "run", "-d",
            "--name", name,
            "-p", f"{port}:{port if key != 'webgoat' else 8080}",
            "--restart", "unless-stopped",
            lab["image"],
        ])
        if rc != 0:
            print(f"  {key}: failed to start: {out}")
            return False

    # Wait for the app to be ready (up to 60 s)
    print(f"  {key}: waiting for {lab['url']} ...", end="", flush=True)
    deadline = time.time() + 60
    while time.time() < deadline:
        rc, _ = _run(["docker", "exec", name, "sh", "-c",
                       f"curl -sf http://localhost:{port if key != 'webgoat' else 8080}"
                       f"{lab['ready_path']} > /dev/null 2>&1 && echo ok"])
        if rc == 0 or _ == "ok":
            print(" ready")
            break
        print(".", end="", flush=True)
        time.sleep(3)
    else:
        print(" (timeout — may still be starting)")

    _authorize(lab["url"])
    print(f"  {key}: {lab['url']}")
    if lab.get("notes"):
        print(f"         {lab['notes']}")
    if lab.get("default_creds"):
        u, pw = lab["default_creds"]
        print(f"         Default credentials: {u} / {pw}")
    return True


def stop_lab(key: str) -> None:
    name = LABS[key]["container"]
    if container_exists(name):
        _run(["docker", "stop", name])
        _run(["docker", "rm", name])
        print(f"  {key}: stopped and removed")
    else:
        print(f"  {key}: not running")


def status() -> None:
    print("Lab status:")
    for key, lab in LABS.items():
        running = container_running(lab["container"])
        state = f"RUNNING  {lab['url']}" if running else "stopped"
        print(f"  {key:12} {state}")


def _authorize(url: str) -> None:
    """Add the lab URL's host to the authorized scope."""
    sys.path.insert(0, str(ROOT))
    try:
        import authorization
        authorization.authorize_target(url)
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] could not authorize {url}: {exc}")


def authorize_all() -> None:
    """Ensure every lab target is in the scope file."""
    sys.path.insert(0, str(ROOT))
    import authorization
    for lab in LABS.values():
        authorization.authorize_target(lab["url"])
    print(f"Authorized {len(LABS)} lab targets.")
    print(f"Scope: {', '.join(authorization.scope())}")


def print_quickstart() -> None:
    print("""
Quick-start for CyberSwarm red-team testing
============================================

1. Start a lab:
     python scripts/lab_setup.py up dvwa

2. Run a full assessment:
     python cli.py full http://localhost:8001

3. Or run phases separately:
     python cli.py recon http://localhost:8001
     python cli.py attack http://localhost:8001

4. Check the results:
     python cli.py report http://localhost:8001
     python cli.py dashboard

All lab targets are pre-authorized. Never run CyberSwarm against
targets you do not own or have explicit written permission to test.
""")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage deliberately vulnerable lab targets for CyberSwarm.")
    parser.add_argument("command", choices=["up", "down", "status", "authorize"],
                        help="up=start, down=stop, status=check, authorize=add to scope")
    parser.add_argument("labs", nargs="*", choices=list(LABS) + ["all"],
                        help="which labs (default: all)")
    args = parser.parse_args()

    if not docker_available():
        print("Docker is not installed. Install it from https://docs.docker.com/get-docker/")
        return 1

    targets = args.labs if args.labs and "all" not in args.labs else list(LABS)

    if args.command == "status":
        status()
        return 0

    if args.command == "authorize":
        authorize_all()
        return 0

    if args.command == "up":
        print(f"Starting {len(targets)} lab(s)...")
        for key in targets:
            if key not in LABS:
                print(f"  unknown lab: {key!r}. Choose from: {list(LABS)}")
                continue
            start_lab(key)
        print()
        print_quickstart()
        return 0

    if args.command == "down":
        print(f"Stopping {len(targets)} lab(s)...")
        for key in targets:
            if key in LABS:
                stop_lab(key)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
