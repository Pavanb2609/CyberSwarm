#!/usr/bin/env python3
"""
lab_bench.py -- measure detection on the local lab.

Two targets, both loopback-only:

  vulnerable   scripts/lab_app.py -- known ground truth: xss, sqli, ssti, lfi
  control      a static page with nothing to find -- every finding reported
               here is a false positive

Reporting both is the point: recall says what it finds, the control says how
much it makes up. Results land in results/benchmarks/lab_<timestamp>.{json,md}.

Two modes:

  --mode detection   (default) DETERMINISTIC. Seeds the known lab endpoints
                     into a SystemMap and runs the PayloadAgent directly.
                     Needs no model backend and no external security tools --
                     payload generation + probing are pure Python -- so the
                     number is reproducible on any machine. Measures the
                     DETECTION capability "given the injection surface".

  --mode e2e         Runs the full `cli.py recon` + `attack` pipeline. Adds
                     discovery (does recon find the endpoints?) and needs the
                     model backend from config.yaml plus whatever tools are
                     installed. Measures DISCOVERY + DETECTION end to end.

The detection mode is the default because a benchmark must be reproducible and
must isolate the capability from the environment: a 0% in e2e can mean "no
model", "no tools", or "crawler found no links", none of which is a detection
failure. Run e2e once the backend and tools are set up to measure discovery.

    python benchmarks/lab_bench.py                      # deterministic detection
    python benchmarks/lab_bench.py --only vulnerable
    python benchmarks/lab_bench.py --mode e2e           # full pipeline

Both servers bind 127.0.0.1 only; the authorization gate always allows
localhost, so no scope changes are needed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks import scoring  # noqa: E402

LAB_TRUTH = ["xss", "sqli", "ssti", "lfi"]
# Classes that legitimately accompany a truth class (the /page LFI is also a
# path traversal and an information disclosure). Detecting these is correct,
# not a false positive, so they are not counted as "extra" on the vuln target.
LAB_COMPANIONS = {"path_traversal", "information_disclosure"}
# Endpoint -> (param, truth class). The surface a real recon would discover
# from the lab's linked index page.
LAB_ENDPOINTS = [("/greet", "name"), ("/search", "q"), ("/calc", "expr"), ("/page", "path")]
# v2 lab (scripts/lab_app_v2.py): three instances per class, varied sink
# contexts, plus a hardened control that HAS parameters. Addresses the
# reviewer-level weaknesses of v1 (one positive/class, parameterless control).
V2_ENDPOINTS = [
    ("/greet", "name"), ("/comment", "author"), ("/welcome", "user"),
    ("/search", "q"), ("/lookup", "id"), ("/filter", "category"),
    ("/calc", "expr"), ("/render", "tpl"), ("/preview", "body"),
    ("/page", "path"), ("/download", "file"), ("/include", "tpl"),
]
V2_CONTROL_ENDPOINTS = [("/search2", "q"), ("/greet2", "name"),
                        ("/calc2", "expr"), ("/page2", "file")]
TARGET = "localhost"   # evidence files are keyed by host
PER_TARGET_FILES = ("results/evidence/{t}.json", "results/attack_evidence/{t}.json",
                    "results/system_map/{t}.json", "results/state/{t}.json",
                    "results/phase_state/{t}.json", "results/traces/{t}.json")


class _NoModel:
    """A model client that answers nothing. The PayloadAgent's detection is
    deterministic (payload_gen + payload_probe); the model is only consulted
    for optional narrative, so a no-op keeps the benchmark offline."""

    def chat(self, *a, **k) -> str:
        return "{}"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(port: int, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


class _ControlHandler(BaseHTTPRequestHandler):
    """A boring, correctly-configured static site that reflects nothing."""

    BODY = (b"<!doctype html><html><head><title>Control</title></head>"
            b"<body><h1>Nothing to see here</h1><p>Static page.</p></body></html>")

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, *a):
        pass


def start_control(port: int) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), _ControlHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def start_lab(port: int) -> subprocess.Popen:
    code = ("import sys; sys.path.insert(0, 'scripts'); import lab_app; "
            f"lab_app.app.run(host='127.0.0.1', port={port})")
    return subprocess.Popen([sys.executable, "-c", code], cwd=str(ROOT),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_lab_v2(port: int) -> subprocess.Popen:
    """Vulnerable v2 lab (scripts/lab_app_v2.py: 3 instances per class)."""
    code = ("import sys; sys.path.insert(0, 'scripts'); import lab_app_v2; "
            f"lab_app_v2.app.run(host='127.0.0.1', port={port})")
    return subprocess.Popen([sys.executable, "-c", code], cwd=str(ROOT),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_control_v2(port: int) -> subprocess.Popen:
    """Hardened v2 control: real parameters, safely handled (Flask)."""
    code = ("import sys; sys.path.insert(0, 'scripts'); import lab_app_v2; "
            f"lab_app_v2.control_app.run(host='127.0.0.1', port={port})")
    return subprocess.Popen([sys.executable, "-c", code], cwd=str(ROOT),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_lab_v3(port: int) -> subprocess.Popen:
    """Vulnerable v3 lab: v1 surface with a REAL SQLite backend (sqli
    row-conditional responses exist, so sqli is confirmable end-to-end)."""
    code = ("import sys; sys.path.insert(0, 'scripts'); import lab_app_v3; "
            f"lab_app_v3.app.run(host='127.0.0.1', port={port})")
    return subprocess.Popen([sys.executable, "-c", code], cwd=str(ROOT),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_control_v3(port: int) -> subprocess.Popen:
    """Hardened v3 control: same surface/database, bound parameters."""
    code = ("import sys; sys.path.insert(0, 'scripts'); import lab_app_v3; "
            f"lab_app_v3.control_app.run(host='127.0.0.1', port={port})")
    return subprocess.Popen([sys.executable, "-c", code], cwd=str(ROOT),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _system_map_v2(base: str, endpoints) -> dict[str, Any]:
    """Injection surface for the v2 lab (parameterised endpoint list)."""
    return {
        "target": TARGET, "base_url": base,
        "endpoints": [f"{base}{path}?{param}=x" for path, param in endpoints],
        "parameters": [{"url": f"{base}{path}", "name": param}
                       for path, param in endpoints],
        "technologies": [{"name": "Flask"}, {"name": "Jinja2"}, {"name": "Python"}],
        "waf": False,
    }


def _system_map(base: str) -> dict[str, Any]:
    """The injection surface a successful recon would hand the attack phase."""
    return {
        "target": TARGET, "base_url": base,
        "endpoints": [f"{base}{path}?{param}=x" for path, param in LAB_ENDPOINTS],
        "parameters": [{"url": f"{base}{path}", "name": param}
                       for path, param in LAB_ENDPOINTS],
        "technologies": [{"name": "Flask"}, {"name": "Jinja2"}, {"name": "Python"}],
        "waf": False,
    }


# ── detection mode (deterministic) ───────────────────────────────────────────

def _finding_dicts(result) -> list[dict[str, Any]]:
    out = []
    for f in (getattr(result, "findings", None) or []):
        out.append(f if isinstance(f, dict) else getattr(f, "__dict__", {}))
    return out


def run_detection(label: str, app_version: str = "v1") -> scoring.BenchmarkResult:
    from agents.payload_agent import PayloadAgent

    port = _free_port()
    started = time.time()
    if app_version == "v2":
        handle: Any = (start_lab_v2(port) if label == "vulnerable"
                       else start_control_v2(port))
        endpoints = V2_ENDPOINTS if label == "vulnerable" else V2_CONTROL_ENDPOINTS
    else:
        handle = start_lab(port) if label == "vulnerable" else start_control(port)
        endpoints = LAB_ENDPOINTS
    try:
        if not _wait_for(port):
            return scoring.score_benchmark(
                label, LAB_TRUTH if label == "vulnerable" else [], [],
                error="server did not start (is Flask installed?)")
        base = f"http://{TARGET}:{port}"
        smap = (_system_map(base) if app_version == "v1"
                else _system_map_v2(base, endpoints))
        result = PayloadAgent(_NoModel()).run(TARGET, smap, {})
        findings = _finding_dicts(result)
    finally:
        if isinstance(handle, subprocess.Popen):
            handle.terminate()
        else:
            handle.shutdown()
    tags = LAB_TRUTH if label == "vulnerable" else []
    from benchmarks import taxonomy, scoring  # noqa: E402 (scoring imported at module top)
    out = scoring.score_benchmark(label, tags, findings,
                                  duration_s=time.time() - started)
    # v2: per-endpoint (instance-level) breakdown in addition to classes
    if app_version == "v2":
        fam = {"greet": "xss", "comment": "xss", "welcome": "xss",
               "search": "sqli", "lookup": "sqli", "filter": "sqli",
               "calc": "ssti", "render": "ssti", "preview": "ssti",
               "page": "lfi", "download": "lfi", "include": "lfi",
               "search2": None, "greet2": None, "calc2": None, "page2": None}
        per_ep = []
        for path, param in endpoints:
            name = path.strip("/").lstrip("/")
            key = name if not name.endswith("2") else name[:-2]
            expected = fam.get(name) or fam.get(key)
            ep_findings = [f for f in findings
                           if str(f.get("url", "")).startswith(f"{base}{path}")]
            classes: set[str] = set()
            for f in ep_findings:
                classes |= taxonomy.classify_finding(
                    f.get("name", ""), f.get("description", ""),
                    f.get("tool", ""), f.get("source_agent", ""))
            per_ep.append({
                "endpoint": f"{path}?{param}", "expected": expected,
                "findings": len(ep_findings),
                "classes": sorted(classes),
                "hit": bool(expected) and bool(expected in classes),
            })
        out.per_endpoint = per_ep          # instance-level detail (v2)
        out.instance_recall = (round(sum(e["hit"] for e in per_ep)
                                     / sum(1 for e in per_ep if e["expected"]), 3)
                               if any(e["expected"] for e in per_ep) else None)
    return out


# ── e2e mode (full pipeline) ─────────────────────────────────────────────────

def _archive_target_state(stamp: str, label: str) -> None:
    dest = ROOT / "results" / "benchmarks" / "archive" / f"{stamp}_{label}"
    for pattern in PER_TARGET_FILES:
        src = ROOT / pattern.format(t=TARGET)
        if src.exists():
            dest.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dest / f"{Path(pattern).parent.name}.json"))


def _read_confirmed() -> list[dict[str, Any]]:
    path = ROOT / "results" / "attack_evidence" / f"{TARGET}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return list(data.get("vulnerabilities") or [])


def run_e2e(label: str, timeout: int, stamp: str, app_version: str = "v1") -> scoring.BenchmarkResult:
    port = _free_port()
    started = time.time()
    _archive_target_state(stamp, f"before_{label}")
    if app_version == "v3":
        handle: Any = (start_lab_v3(port) if label == "vulnerable"
                       else start_control_v3(port))
    else:
        handle = start_lab(port) if label == "vulnerable" else start_control(port)
    try:
        if not _wait_for(port):
            return scoring.score_benchmark(
                label, LAB_TRUTH if label == "vulnerable" else [], [],
                error="server did not start (is Flask installed?)")
        url = f"http://{TARGET}:{port}"
        err = None
        for stage in (["recon", url, "--auto-approve", "--run-all"],
                      ["attack", url, "--auto-approve", "--force", "--reset-memory"]):
            try:
                proc = subprocess.run([sys.executable, "cli.py", *stage], cwd=str(ROOT),
                                      capture_output=True, text=True, timeout=timeout,
                                      errors="replace")
            except subprocess.TimeoutExpired:
                err = f"{stage[0]} timed out after {timeout}s"
                break
            if proc.returncode != 0:
                err = f"{stage[0]} failed: {(proc.stderr or proc.stdout)[-300:]}"
                break
        findings = _read_confirmed()
    finally:
        if isinstance(handle, subprocess.Popen):
            handle.terminate()
        else:
            handle.shutdown()
    _archive_target_state(stamp, f"after_{label}")
    tags = LAB_TRUTH if label == "vulnerable" else []
    return scoring.score_benchmark(label, tags, findings, duration_s=time.time() - started,
                                   error=err or "")


# ── summary / render ─────────────────────────────────────────────────────────

def summarize(results: list[scoring.BenchmarkResult]) -> dict[str, Any]:
    vuln = next((r for r in results if r.benchmark == "vulnerable"), None)
    ctrl = next((r for r in results if r.benchmark == "control"), None)
    out: dict[str, Any] = {}
    if vuln:
        out["vulnerable"] = {
            "expected": sorted(vuln.expected), "detected": sorted(vuln.detected),
            "missed": sorted(vuln.expected - vuln.detected),
            "extra": sorted(vuln.detected - vuln.expected - LAB_COMPANIONS),
            "recall": round(len(vuln.expected & vuln.detected) / max(len(vuln.expected), 1), 3),
            "findings": vuln.findings, "error": vuln.error}
    if ctrl:
        out["control"] = {"false_positive_classes": sorted(ctrl.detected),
                          "false_positives": ctrl.findings, "error": ctrl.error}
    return out


def to_markdown(summary: dict[str, Any], mode: str) -> str:
    L = [f"# Lab detection benchmark ({mode})", ""]
    if mode == "detection":
        L += ["_Deterministic: known endpoints seeded into the SystemMap, "
              "PayloadAgent run directly (no model, no external tools). "
              "Measures detection given the injection surface._", ""]
    else:
        L += ["_End to end: full `recon` + `attack` pipeline. Also exercises "
              "discovery and needs the model backend + installed tools._", ""]
    v = summary.get("vulnerable")
    if v:
        L += [f"**Recall on lab_app: {v['recall']:.0%}** "
              f"({len(v['expected']) - len(v['missed'])}/{len(v['expected'])} classes)", "",
              f"- detected: {', '.join(v['detected']) or 'none'}",
              f"- missed: {', '.join(v['missed']) or 'none'}",
              f"- reported but not in ground truth: {', '.join(v['extra']) or 'none'}"]
        if v["error"]:
            L.append(f"- run error: {v['error']}")
    c = summary.get("control")
    if c:
        L += ["", f"**False positives on the clean control: {c['false_positives']}**",
              f"- classes: {', '.join(c['false_positive_classes']) or 'none'}"]
        if c["error"]:
            L.append(f"- run error: {c['error']}")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Local lab detection benchmark")
    p.add_argument("--mode", choices=["detection", "e2e"], default="detection")
    p.add_argument("--app", choices=["v1", "v2"], default="v1",
                   help="v2: 3 instances/class + parameterised control")
    p.add_argument("--only", choices=["vulnerable", "control"])
    p.add_argument("--timeout", type=int, default=3600, help="(e2e) per pipeline stage")
    a = p.parse_args(argv)

    stamp = time.strftime("%Y%m%d_%H%M%S")
    labels = [a.only] if a.only else ["vulnerable", "control"]
    if a.mode == "detection" and a.app == "v2":
        # v2 needs more than the first 4 URLs probed and instance-level
        # findings; set before payload_agent is imported (defaults untouched
        # for every other consumer, so frozen-run behaviour is preserved)
        os.environ["CYBERSWARM_PAYLOAD_MAX_TARGETS"] = "16"
        os.environ["CYBERSWARM_PAYLOAD_PER_ENDPOINT"] = "1"
    if a.mode == "detection":
        results = [run_detection(lbl, a.app) for lbl in labels]
    else:
        results = [run_e2e(lbl, a.timeout, stamp) for lbl in labels]
    summary = summarize(results)
    md = to_markdown(summary, a.mode)
    # v2: append the instance-level breakdown
    if a.app == "v2":
        for r in results:
            per = getattr(r, "per_endpoint", None)
            if per:
                md += f"\n## Per-endpoint breakdown ({r.benchmark}, app v2)\n\n"
                md += "| endpoint | expected | findings | classes | hit |\n|---|---|---|---|---|\n"
                for e in per:
                    md += (f"| {e['endpoint']} | {e['expected'] or '-'} | "
                           f"{e['findings']} | {', '.join(e['classes']) or '-'} | "
                           f"{'yes' if e['hit'] else ('-' if not e['expected'] else 'NO')} |\n")
                ir = getattr(r, "instance_recall", None)
                if ir is not None:
                    md += f"\n**Instance recall: {ir:.0%}**\n"
    out_dir = ROOT / "results" / "benchmarks"
    out_dir.mkdir(parents=True, exist_ok=True)
    extra = {r.benchmark: {"per_endpoint": getattr(r, "per_endpoint", []),
                           "instance_recall": getattr(r, "instance_recall", None)}
             for r in results if a.app == "v2"}
    (out_dir / f"lab_{stamp}.json").write_text(
        json.dumps({"mode": a.mode, "app": a.app, **summary, "detail": extra},
                   indent=2), encoding="utf-8")
    (out_dir / f"lab_{stamp}.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"saved -> {out_dir / f'lab_{stamp}.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
