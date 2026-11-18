#!/usr/bin/env python3
"""
scanner_bench.py — traditional-scanner comparison benchmark.

Runs four tools (sqlmap, nuclei, OWASP ZAP, CyberSwarm) against the same three
applications with the same ground rules, and scores them against a 34-instance
ground truth plus 12 hardened control endpoints:

  lab v2      12 instances   scripts/lab_app_v2.py   (xss x3, sqli x3, ssti x3, lfi x3)
  DVWA low    12 instances   docker (ghcr.io/digininja/dvwa + mariadb)
  Juice Shop  10 instances   docker (bkimminich/juice-shop)
  lab v2c     12 controls    scripts/lab_app_v2c.py  (hardened mirror of lab v2)

All tools talk to the applications THROUGH a logging reverse proxy, so request
counts come from one uniform source (the proxy access log). Scoring is
endpoint+class: a detection counts for an instance when the tool reported a
finding at the instance's path with the instance's class; parameter-level
matches are recorded separately. ZAP alerts with High risk at paths that are
not ground truth count as "false high-severity reports".

Each instance's exploitability is re-verified (exploit-response check) before
every run; the verification results are written into the run record.

Usage:
  ./venv/bin/python benchmarks/scanner_bench.py --tools sqlmap nuclei-serial zap
  ./venv/bin/python benchmarks/scanner_bench.py --tools cyberswarm
"""

from __future__ import annotations

import argparse
import datetime
import http.client
import http.server
import json
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks import taxonomy  # noqa: E402  (class derivation, same as e2e)

ZAP_PORT = 8091
TIME_BUDGET_S = 25 * 60          # per tool per application

# ---------------------------------------------------------------------------
# Applications and ports
# ---------------------------------------------------------------------------

DVWA_PORT, JUICE_PORT = 8001, 8002
LAB_PORT, CONTROL_PORT = 5010, 5012
PROXY_PORTS = {DVWA_PORT: 8101, JUICE_PORT: 8102,
               LAB_PORT: 8110, CONTROL_PORT: 8112}

# ---------------------------------------------------------------------------
# Ground truth: 34 instances (endpoint = path, param = primary parameter,
# cls = class in CyberSwarm's taxonomy; verify = an exploit-response check)
# ---------------------------------------------------------------------------

GROUND_TRUTH = [
    # ---- lab v2 (12) — verification basis: scripts/lab_app_v2.py source ----
    {"app": "lab",    "endpoint": "/greet",   "param": "name",     "cls": "xss",
     "verify": ("get", "/greet?name=%3Cscript%3Ealert(1)%3C/script%3E", "<script>alert(1)</script>")},
    {"app": "lab",    "endpoint": "/comment", "param": "author",   "cls": "xss",
     "verify": ("get", "/comment?author=%3Cscript%3Ealert(1)%3C/script%3E", "<script>alert(1)</script>")},
    {"app": "lab",    "endpoint": "/welcome", "param": "user",     "cls": "xss",
     "verify": ("get", "/welcome?user=%3Cscript%3Ealert(1)%3C/script%3E", "<script>alert(1)</script>")},
    {"app": "lab",    "endpoint": "/search",  "param": "q",        "cls": "sqli",
     "verify": ("get", "/search?q='", "syntax error")},
    {"app": "lab",    "endpoint": "/lookup",  "param": "id",       "cls": "sqli",
     "verify": ("get", "/lookup?id=1%20or%201=1", "error in your SQL")},
    {"app": "lab",    "endpoint": "/filter",  "param": "category", "cls": "sqli",
     "verify": ("get", "/filter?category='", "syntax error")},
    {"app": "lab",    "endpoint": "/calc",    "param": "expr",     "cls": "ssti",
     "verify": ("get", "/calc?expr=%7B%7B7*7%7D%7D", "Result: 49")},
    {"app": "lab",    "endpoint": "/render",  "param": "tpl",      "cls": "ssti",
     "verify": ("get", "/render?tpl=%7B%7B7*7%7D%7D", "49")},
    {"app": "lab",    "endpoint": "/preview", "param": "body",     "cls": "ssti",
     "verify": ("get", "/preview?body=%7B%7B7*7%7D%7D", "49")},
    {"app": "lab",    "endpoint": "/page",    "param": "path",     "cls": "lfi",
     "verify": ("get", "/page?path=/etc/passwd", "root:x:")},
    {"app": "lab",    "endpoint": "/download", "param": "file",    "cls": "lfi",
     "verify": ("get", "/download?file=/etc/passwd", "root:x:")},
    {"app": "lab",    "endpoint": "/include", "param": "tpl",      "cls": "lfi",
     "verify": ("get", "/include?tpl=/etc/passwd", "root:x:")},

    # ---- DVWA (12) — basis: DVWA source, security=low, admin session ----
    {"app": "dvwa",   "endpoint": "/vulnerabilities/sqli/",        "param": "id",       "cls": "sqli",
     "verify": ("get", "/vulnerabilities/sqli/?id=1%27&Submit=Submit", "You have an error in your SQL syntax")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/sqli_blind/",  "param": "id",       "cls": "sqli",
     "verify": ("diff", "/vulnerabilities/sqli_blind/?id=1%27%20and%201=1%20--%20&Submit=Submit",
               "/vulnerabilities/sqli_blind/?id=1%27%20and%201=2%20--%20&Submit=Submit",
               "User ID exists")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/xss_r/",       "param": "name",     "cls": "xss",
     "verify": ("get", "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E&Submit=Submit", "<script>alert(1)</script>")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/xss_d/",       "param": "default",  "cls": "xss",
     "verify": ("contains", "/vulnerabilities/xss_d/?default=English", "document.write(\"<option value='")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/xss_s/",       "param": "txtMessage", "cls": "xss",
     "verify": ("contains", "/vulnerabilities/xss_s/", "mtxMessage")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/fi/",          "param": "page",     "cls": "lfi",
     "verify": ("get", "/vulnerabilities/fi/?page=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "root:x:")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/exec/",        "param": "ip",       "cls": "command_injection",
     "verify": ("post", "/vulnerabilities/exec/", "ip=127.0.0.1;cat /etc/passwd&Submit=Submit", "daemon:")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/brute/",       "param": "password", "cls": "brute_force",
     "verify": ("get", "/vulnerabilities/brute/?username=admin&password=wrong&Login=Login", "incorrect")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/csrf/",        "param": "password_new", "cls": "csrf",
     "verify": ("contains", "/vulnerabilities/csrf/", "New password")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/upload/",      "param": "uploaded", "cls": "file_upload",
     "verify": ("contains", "/vulnerabilities/upload/", 'type="file"')},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/weak_id/",     "param": None,       "cls": "session_fixation",
     "verify": ("contains", "/vulnerabilities/weak_id/", "Session ID")},
    {"app": "dvwa",   "endpoint": "/vulnerabilities/captcha/",     "param": "step",     "cls": "business_logic",
     "verify": ("contains", "/vulnerabilities/captcha/", "captcha")},

    # ---- Juice Shop (10) — basis: public challenge design (BodgeIt Store /
    #      Juice Shop hacking guide); two instances verified with the admin
    #      token obtained through instance js-login (dependency disclosed) ----
    {"app": "juice",  "endpoint": "/rest/user/login",                     "param": "email",  "cls": "sqli",
     "verify": ("json_login_sqli", "/rest/user/login", None)},
    {"app": "juice",  "endpoint": "/rest/products/search",                "param": "q",      "cls": "sqli",
     "verify": ("get", "/rest/products/search?q=%27%29%29", "SQLITE_ERROR")},
    {"app": "juice",  "endpoint": "/rest/product/search",                 "param": "q",      "cls": "xss",
     "verify": ("get", "/rest/product/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "alert(1)")},
    {"app": "juice",  "endpoint": "/#/search",                            "param": "query",  "cls": "xss",
     "verify": ("contains", "/#/search?query=%3Ciframe%20src%3Djavascript:alert(1)%3E", "<title>OWASP Juice Shop")},
    {"app": "juice",  "endpoint": "/ftp",                                 "param": None,     "cls": "information_disclosure",
     "verify": ("get", "/ftp", "coupons")},
    {"app": "juice",  "endpoint": "/rest/admin/application-version",      "param": None,     "cls": "information_disclosure",
     "verify": ("get", "/rest/admin/application-version", "version")},
    {"app": "juice",  "endpoint": "/rest/user/security-question",         "param": "email",  "cls": "information_disclosure",
     "verify": ("get", "/rest/user/security-question?email=admin@juice-sh.op", "question")},
    {"app": "juice",  "endpoint": "/rest/products/1/reviews",             "param": None,     "cls": "information_disclosure",
     "verify": ("get", "/rest/products/1/reviews", "author")},
    {"app": "juice",  "endpoint": "/api/Users",                           "param": None,     "cls": "information_disclosure",
     "verify": ("token_get", "/api/Users", "admin@juice-sh.op")},
    {"app": "juice",  "endpoint": "/rest/basket/2",                       "param": None,     "cls": "idor",
     "verify": ("token_get", "/rest/basket/2", "\"UserId\":2")},
]

CONTROLS = [f"/{p}" for p in
            ("greet2", "comment2", "welcome2", "search2", "lookup2", "filter2",
             "calc2", "render2", "preview2", "page2", "download2", "include2")]

APP_PORTS = {"lab": LAB_PORT, "dvwa": DVWA_PORT, "juice": JUICE_PORT}

# ---------------------------------------------------------------------------
# Logging reverse proxy (request counting)
# ---------------------------------------------------------------------------


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    backend_port = None
    log_file = None
    lock = threading.Lock()

    def _relay(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None
        conn = http.client.HTTPConnection("127.0.0.1", self.backend_port, timeout=90)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "connection", "transfer-encoding")}
        if getattr(self, "inject_headers", None):
            for k, v in self.inject_headers.items():
                headers[k] = v
        headers["Host"] = self.headers.get("Host", "localhost")
        conn.request(self.command, self.path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        with self.lock:
            if self.log_file:
                self.log_file.write(f"{self.command} {self.path} -> {resp.status}\n")
        return resp, data

    def _send(self, resp, data):
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            lk = k.lower()
            # content-length is re-emitted below; forwarding the backend's copy
            # as well produces a duplicate header that strict clients (ZAP's
            # Apache HttpClient5) reject outright with ProtocolException.
            if lk in ("server", "date", "transfer-encoding", "content-length"):
                continue
            if lk == "location":
                v = v.replace(f":{self.backend_port}", f":{self.server.server_port}")
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):    self._one()
    def do_POST(self):   self._one()
    def do_PUT(self):    self._one()
    def do_DELETE(self): self._one()
    def do_HEAD(self):   self._one()
    def do_OPTIONS(self): self._one()
    def do_PATCH(self):  self._one()

    def _one(self):
        try:
            resp, data = self._relay()
        except Exception as exc:  # noqa: BLE001
            self.send_error(502, str(exc))
            return
        self._send(resp, data)

    def log_message(self, *a):
        pass


class LoggingProxy:
    """Forward requests to one backend and count them in an access log."""

    def __init__(self, backend_port: int, port: int, log_path: Path,
                 inject_headers: dict | None = None):
        cls_attrs = {"backend_port": backend_port}
        if inject_headers:
            # injected on every forwarded request (used to authenticate all
            # tools against DVWA uniformly)
            cls_attrs["inject_headers"] = inject_headers
        handler = type(f"P{port}", (ProxyHandler,), cls_attrs)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
        self.server.log_file = log_path.open("a", encoding="utf-8")
        handler.log_file = self.server.log_file
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def count(self) -> int:
        self.server.log_file.flush()
        with open(self.server.log_file.name, encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())

    def stop(self):
        self.server.log_file.close()
        self.server.shutdown()


# ---------------------------------------------------------------------------
# Verification (item ⑦: re-verified before every run)
# ---------------------------------------------------------------------------


def dvwa_cookie_header() -> str | None:
    """Authenticate to DVWA with curl (works around the image's duplicated
    session cookie) and return a 'Cookie: ...' header string."""
    jar = f"/tmp/opencode/dvwa_auth_{int(time.time())}.jar"
    try:
        r = subprocess.run(["curl", "-s", "--max-time", "15", "-c", jar,
                            "http://localhost:8001/login.php"],
                           capture_output=True, text=True, timeout=30)
        tok_m = re.search(r"user_token' value='([0-9a-f]+)", r.stdout)
        if not tok_m:
            return None
        post = subprocess.run(
            ["curl", "-s", "--max-time", "15", "-b", jar, "-c", jar,
             "-d", f"username=admin&password=password&Login=Login&user_token={tok_m.group(1)}",
             "-o", "/dev/null", "-w", "%{redirect_url}",
             "http://localhost:8001/login.php"], capture_output=True, text=True, timeout=30)
        if not post.stdout.strip().endswith("/index.php"):
            return None
        cookies = [f"{row[5]}={row[6]}" for row in
                   (line.split() for line in open(jar) if "PHPSESSID" in line or "security" in line)]
        # force the target security level: the freshly logged-in session
        # defaults to 'impossible', which would disable every vulnerability
        header = "Cookie: " + "; ".join(
            c if c.startswith("security=") else c for c in cookies)
        header = re.sub(r"security=[a-z]+", "security=low", header)
        return header
    finally:
        try:
            Path(jar).unlink()
        except OSError:
            pass


def juice_token(base: str) -> str | None:
    r = subprocess.run(
        ["curl", "-s", "--max-time", "10", "-X", "POST", f"{base}/rest/user/login",
         "-H", "Content-Type: application/json",
         "-d", json.dumps({"email": "' or 1=1--", "password": "x"})],
        capture_output=True, text=True, timeout=20)
    try:
        return json.loads(r.stdout)["authentication"]["token"]
    except (json.JSONDecodeError, KeyError):
        return None


def verify_ground_truth(base_by_app: dict, dvwa_cookie: str | None) -> dict:
    """Exploit-response checks for all 34 instances; returns {instance_id: bool}."""
    results = {}
    for inst in GROUND_TRUTH:
        iid = f"{inst['app']}:{inst['endpoint']}:{inst['param']}"
        base = base_by_app[inst["app"]]
        kind = inst["verify"][0]
        ok = False
        try:
            if kind == "get":
                url = base + inst["verify"][1]
                cmd = ["curl", "-sg", "--max-time", "15"]
                if inst["app"] == "dvwa" and dvwa_cookie:
                    cmd += ["-H", dvwa_cookie]
                r = subprocess.run(cmd + [url], capture_output=True, text=True, timeout=25)
                ok = inst["verify"][2] in r.stdout
            elif kind == "post":
                url = base + inst["verify"][1]
                cmd = ["curl", "-sg", "--max-time", "20"]
                if inst["app"] == "dvwa" and dvwa_cookie:
                    cmd += ["-H", dvwa_cookie]
                cmd += ["-d", inst["verify"][2], url]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
                ok = inst["verify"][3] in r.stdout
            elif kind == "contains":
                url = base + inst["verify"][1]
                cmd = ["curl", "-sg", "--max-time", "15"]
                if inst["app"] == "dvwa" and dvwa_cookie:
                    cmd += ["-H", dvwa_cookie]
                r = subprocess.run(cmd + [url], capture_output=True, text=True, timeout=25)
                ok = inst["verify"][2] in r.stdout
            elif kind == "diff":
                cmd = ["curl", "-sg", "--max-time", "15", "-H", dvwa_cookie or ""]
                a = subprocess.run(cmd + [base + inst["verify"][1]], capture_output=True, text=True).stdout
                b = subprocess.run(cmd + [base + inst["verify"][2]], capture_output=True, text=True).stdout
                ok = inst["verify"][3] in a and inst["verify"][3] not in b
            elif kind == "json_login_sqli":
                r = subprocess.run(
                    ["curl", "-s", "--max-time", "15", "-X", "POST", base + inst["verify"][1],
                     "-H", "Content-Type: application/json",
                     "-d", json.dumps({"email": "' or 1=1--", "password": "x"})],
                    capture_output=True, text=True, timeout=25)
                ok = "token" in r.stdout
            elif kind == "token_get":
                tok = juice_token(base)
                if tok:
                    r = subprocess.run(
                        ["curl", "-s", "--max-time", "15", base + inst["verify"][1],
                         "-H", f"Authorization: Bearer {tok}"],
                        capture_output=True, text=True, timeout=25)
                    ok = inst["verify"][2] in r.stdout
        except Exception:  # noqa: BLE001
            ok = False
        results[iid] = ok
    return results


# ---------------------------------------------------------------------------
# Tool runners — each returns (detections, raw_log_path)
#   detection = {"endpoint": path, "param": str|None, "cls": str, "high": bool}
# ---------------------------------------------------------------------------


def _run_cmd(cmd, log_path, timeout):
    with log_path.open("w", encoding="utf-8") as fh:
        proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                text=True, errors="replace")
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"\n[time budget exhausted: killed after {timeout}s]\n")
            return "timeout"
    return "ok" if rc == 0 else "error"


def run_sqlmap(run_dir, base_by_app, dvwa_cookie, timeout):
    """sqlmap given the parameterized endpoint list (no class labels) —
    sqlmap cannot operate from a bare URL, so it receives the same endpoints
    the other tools discover by crawling; disclosed in the protocol. Time
    budget: `timeout` seconds per application, split across its targets."""
    log = run_dir / "sqlmap_output.txt"
    detections = []
    status = "ok"
    by_app = {}
    for inst in GROUND_TRUTH:
        if inst["param"] is None:
            continue
        by_app.setdefault(inst["app"], []).append(
            f"{base_by_app[inst['app']]}{inst['endpoint']}?{inst['param']}=1"
            + ("&Submit=Submit" if inst["app"] == "dvwa" else ""))
    for app, targets in by_app.items():
        per_target = max(60, timeout // max(1, len(targets)))
        for t in targets:
            cmd = ["sqlmap", "-u", t, "--batch", "--level=2", "--risk=2",
                   "--output-dir", str(run_dir / "sqlmap"), "--threads=1",
                   "--timeout=15", "--retries=1", "--flush-session",
                   f"--time-sec=3"]
            if app == "dvwa" and dvwa_cookie:
                cmd += ["--cookie", dvwa_cookie.removeprefix("Cookie: ")]
            rc = _run_cmd(cmd, log, per_target)
            if rc == "timeout":
                status = "timeout"
            text = log.read_text(errors="replace") if log.exists() else ""
            if "is injectable" in text or "Parameter:" in text and "injectable" in text:
                m = re.search(r"GET parameter '([^']+)'", text)
                path = urllib.parse.urlparse(t).path
                detections.append({"endpoint": path, "param": m.group(1) if m else None,
                                   "cls": "sqli", "high": True})
    return detections, log, status


NUCLEI_CLASS_MAP = [
    (("sqli", "sql-injection", "blind-sql"), "sqli"),
    (("xss", "dast-xss"), "xss"),
    (("lfi", "file-inclusion", "local-file"), "lfi"),
    (("traversal", "path-traversal"), "path_traversal"),
    (("ssti", "template-injection"), "ssti"),
    (("rce", "command-injection", "code-injection"), "command_injection"),
    (("exposure", "exposed", "disclosure", "config", "tokens",
      "panel", "listing", "tech", "apikey", "debug"), "information_disclosure"),
    (("default-login",), "default_credentials"),
]


def nuclei_class(tags):
    tags = [t.lower() for t in tags]
    for keys, cls in NUCLEI_CLASS_MAP:
        if any(k in tags for k in keys):
            return cls
    return "information_disclosure"


def _parse_nuclei_findings(path):
    """Parse nuclei JSONL finding lines from a file.  Findings go to stdout
    incrementally, while -o output is buffered and flushed only at clean
    exit — so stdout logs are the authoritative evidence source."""
    findings = []
    if not path.exists():
        return findings
    for line in path.read_text(errors="replace").splitlines():
        if not line.startswith('{"template'):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(j)
    return findings


def run_nuclei(run_dir, base_by_app, dvwa_cookie, timeout, name, extra):
    log = run_dir / f"nuclei_{name}_output.jsonl"
    out = run_dir / f"nuclei_{name}_results.jsonl"
    cmd = ["nuclei", "-t", str(Path.home() / "nuclei-templates"),
           "-severity", "low,medium,high,critical", "-silent",
           # nuclei v3: -j is a boolean (JSONL format); findings go to the
           # file given via -o.  Passing the path as -j's argument made
           # nuclei treat it as a target and exit without scanning.
           "-j", "-o", str(out)] + extra
    detections = []
    status = "ok"
    for app, port in APP_PORTS.items():
        base = base_by_app[app]
        r_cmd = cmd + ["-u", base]
        if app == "dvwa" and dvwa_cookie:
            r_cmd += ["-H", dvwa_cookie]
        st = _run_cmd(r_cmd, log.with_suffix(f".{app}.log"), timeout)
        if st == "timeout":
            status = "timeout"
    if out.exists():
        for line in out.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = j.get("info", {})
            matched = j.get("matched-at") or j.get("host") or ""
            path = urllib.parse.urlparse(matched).path or "/"
            detections.append({"endpoint": path,
                               "param": j.get("matched-at", None) and None,
                               "cls": nuclei_class(info.get("tags", [])),
                               "high": str(info.get("severity", "")).lower() in ("high", "critical"),
                               "template": info.get("name", "")})
    # stdout logs capture findings incrementally (the -o file is buffered and
    # lost on an unclean exit); parse them as well and dedupe against `out`.
    seen = {(d["endpoint"], d["template"]) for d in detections}
    for app in APP_PORTS:
        for j in _parse_nuclei_findings(log.with_suffix(f".{app}.log")):
            info = j.get("info", {})
            matched = j.get("matched-at") or j.get("host") or ""
            path = urllib.parse.urlparse(matched).path or "/"
            d = {"endpoint": path,
                 "param": None,
                 "cls": nuclei_class(info.get("tags", [])),
                 "high": str(info.get("severity", "")).lower() in ("high", "critical"),
                 "template": info.get("name", "")}
            if (d["endpoint"], d["template"]) not in seen:
                seen.add((d["endpoint"], d["template"]))
                detections.append(d)
    return detections, log, status


ZAP_CLASS_MAP = [
    (("sql",), "sqli"),
    (("cross-site scripting", "xss", "scripting"), "xss"),
    (("path traversal", "directory traversal", "browsing"), "path_traversal"),
    (("file inclusion", "remote file"), "lfi"),
    (("command injection", "remote code", "shell injection"), "command_injection"),
    (("template injection", "expression language"), "ssti"),
    (("information disclosure", "information leakage", "private ip",
      "cacheable", "debug", "banner", " disclosure", "header"), "information_disclosure"),
    (("session id", "session fixation"), "session_fixation"),
]


def zap_class(name, pluginid):
    low = name.lower()
    for keys, cls in ZAP_CLASS_MAP:
        if any(k in low for k in keys):
            return cls
    return None  # unmapped ZAP alert -> not creditable as a class match


def zap_api(method, path, timeout=60, expect_json=False):
    conn = http.client.HTTPConnection("127.0.0.1", ZAP_PORT, timeout=timeout)
    conn.request(method, path)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    if expect_json:
        try:
            return json.loads(data.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return {}
    return data.decode("utf-8", "replace")


def start_zap(run_dir):
    log = run_dir / "zap_daemon.log"
    # Fresh ZAP home per run: ZAP persists its site tree, history and alerts
    # in its profile dir — reusing the default ~/.ZAP leaks prior sessions'
    # tree entries and alerts into this run's results (observed: spider
    # 'completing' without fetching and alerts carrying stale entries).
    zap_home = run_dir / "zap_home"
    zap_home.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        ["/home/vboxuser/zap/ZAP_2.17.0/zap.sh", "-daemon", "-port", str(ZAP_PORT),
         "-dir", str(zap_home),
         "-config", "api.disablekey=true", "-config", "database.ping=false"],
        stdout=log.open("w", encoding="utf-8"), stderr=subprocess.STDOUT,
        text=True)
    for _ in range(90):
        try:
            zap_api("GET", "/JSON/core/view/zapVersion/")
            return proc
        except Exception:
            time.sleep(2)
    return None


def _zap_start_scan(path, log, fh, what, base):
    """Start a spider/ascan and return its scanId.  ZAP 2.17 status views
    require scanId ('does_not_exist' without it — probed live), and the
    action response is {'scan': '<id>'}."""
    resp = zap_api("GET", f"{path}?url={urllib.parse.quote(base)}")
    with fh.open("a", encoding="utf-8") as f2:
        f2.write(f"[zap] {what} start {base} -> {resp[:120]}\n")
    try:
        return int(json.loads(resp)["scan"])
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


def _zap_wait(scan_id, view, timeout_s, log, fh, what):
    """Poll a ZAP scan to completion by scanId.  Returns True on completion,
    False if it never started or the API became unreachable."""
    if scan_id is None:
        return False
    saw_running = False
    deadline = time.time() + timeout_s
    n_err = 0
    while time.time() < deadline:
        time.sleep(5)
        try:
            j = zap_api("GET", f"/JSON/{view}/view/status/?scanId={scan_id}",
                        expect_json=True)
            st = int(float(j["status"]))
            n_err = 0
        except Exception:
            n_err += 1
            if n_err >= 6:
                with fh.open("a", encoding="utf-8") as f2:
                    f2.write(f"[zap] {what} status unreachable for scanId={scan_id}\n")
                return False
            continue
        if st < 100:
            saw_running = True
        elif saw_running or time.time() - deadline + timeout_s > 60:
            return True
    with fh.open("a", encoding="utf-8") as f2:
        f2.write(f"[zap] {what} scanId={scan_id} hit its time budget\n")
    return True


def run_zap(run_dir, base_by_app, timeout):
    """ZAP daemon: spider + active scan per application, then one report export.

    Authentication is handled at the LoggingProxy level (bench Cookie header
    injected on every forwarded request), so no per-tool session setup is
    needed — ZAP 2.17's httpSessions API proved unusable for this (probed:
    createSession -> bad_action, setSessionTokenValue -> missing_parameter)."""
    log = run_dir / "zap_run.log"
    detections = []
    status = "ok"
    crashed = False
    for app, port in APP_PORTS.items():
        base = base_by_app[app]
        started = time.time()
        with log.open("a", encoding="utf-8") as fh:
            fh.write(f"[zap] spider {base} at {datetime.datetime.now()}\n")
            spider_id = _zap_start_scan("/JSON/spider/action/scan/", log,
                                        log, "spider", base)
            # spider up to half the total budget; completion by scanId
            spider_ok = _zap_wait(spider_id, "spider", timeout // 2, log, log,
                                  "spider")
            fh.write(f"[zap] spider {base} done={spider_ok} "
                     f"({time.time() - started:.0f}s)\n")
            ascan_id = _zap_start_scan("/JSON/ascan/action/scan/", log,
                                       log, "ascan", base)
            ascan_ok = _zap_wait(ascan_id, "ascan", timeout, log, log, "ascan")
            fh.write(f"[zap] ascan {base} done={ascan_ok} "
                     f"({time.time() - started:.0f}s)\n")
        if not (spider_ok and ascan_ok):
            crashed = True
            # continue to the next app — one bad app must not skip the rest
            status = "crashed"
    # export alerts
    try:
        alerts = zap_api("GET", "/JSON/core/view/alerts/?baseurl=&start=&count=99999",
                         expect_json=True).get("alerts", [])
    except Exception:
        alerts = []
    (run_dir / "zap_alerts.json").write_text(json.dumps(alerts, indent=1))
    report = zap_api("GET", "/OTHER/core/other/htmlreport/?zaphtmlformat=html")
    (run_dir / "zap_report.html").write_text(report)
    for a in alerts:
        cls = zap_class(a.get("name", ""), a.get("pluginId", ""))
        if not cls:
            continue
        url = a.get("url", "")
        path = urllib.parse.urlparse(url).path or "/"
        risk = str(a.get("risk", "0"))
        if not risk.isdigit():  # some alert sources report risk by name
            risk = {"informational": "0", "low": "1", "medium": "2",
                    "high": "3"}.get(risk.lower(), "0")
        detections.append({"endpoint": path, "param": a.get("param") or None,
                           "cls": cls, "high": int(risk) >= 3,
                           "plugin": a.get("pluginId"), "name": a.get("name")})
    return detections, log, ("crashed" if crashed else status)


def run_cyberswarm(run_dir, base_by_app, dvwa_cookie, timeout):
    """CyberSwarm recon+attack per application (needs the model backend).

    Per-app state isolation (2026-11-16): cli.py normalizes every target to
    the bare hostname (`localhost`), so all three apps share one engagement
    state; without cleanup the juice stages reused the lab's remembered map
    and never reached juice (superseded stamp 20261114_174628: juice proxy
    0 requests, all detections lab paths). Mirrors lab_bench's
    _archive_target_state: after each app's evidence is read, the per-target
    state files are moved into the stamp dir so the next app starts fresh.
    """
    log = run_dir / "cyberswarm_run.log"
    detections = []
    status = "ok"
    for app, port in APP_PORTS.items():
        base = base_by_app[app]
        args = ["./venv/bin/python", "cli.py", "attack", base,
                "--auto-approve", "--force", "--reset-memory"]
        if app == "dvwa" and dvwa_cookie:
            cf = run_dir / f"dvwa_cookies_{app}.txt"
            cf.write_text(dvwa_cookie.removeprefix("Cookie: "))
            args += ["--cookies-file", str(cf)]
        stage = "ok"
        if app == "juice":
            # Juice Shop is fragile under sustained load (Exited 139 observed
            # 2026-11-16 during the 050408 run; the three queue11 runs then
            # started with it already dead). Health-check and restart before
            # its stages so the arm never scans a dead target.
            def _juice_up() -> bool:
                try:
                    conn = http.client.HTTPConnection("localhost", 8002,
                                                      timeout=5)
                    conn.request("GET", "/")
                    ok = conn.getresponse().status in (200, 302)
                    conn.close()
                    return ok
                except Exception:
                    return False
            if not _juice_up():
                print("[cyberswarm] juice down — restarting", flush=True)
                subprocess.run(["docker", "start", "cyberswarm_juiceshop"],
                               capture_output=True)
                for _ in range(12):
                    if _juice_up():
                        break
                    time.sleep(5)
        for kind in (("recon", ["recon", base, "--auto-approve", "--run-all"]),
                     ("attack", args[2:])):
            st = _run_cmd(["./venv/bin/python", "cli.py", *kind[1]],
                          log.with_suffix(f".{app}.{kind[0]}.log"),
                          timeout // 2 if kind[0] == "recon" else timeout)
            if st == "timeout":
                stage = "timeout"
            elif st == "error" and stage == "ok":
                stage = "error"
        if stage != "ok":
            status = stage
        ev = ROOT / "results/attack_evidence/localhost.json"
        if ev.exists():
            data = json.loads(ev.read_text())
            for f in data.get("vulnerabilities", []):
                f_url = f.get("url", "") or f.get("target", "")
                pu = urllib.parse.urlparse(f_url)
                path = pu.path or "/"
                qparam = pu.query.split("=", 1)[0] if pu.query else None
                # Class derivation identical to the e2e pipeline: the paper's
                # standard taxonomy over (name, description, tool, agent).
                # The flat evidence findings carry no category/param fields.
                for cls in sorted(taxonomy.classify_finding(
                        f.get("name", ""), f.get("description", ""),
                        f.get("tool", ""), f.get("source_agent", ""))):
                    detections.append({"endpoint": path, "param": qparam,
                                       "cls": cls,
                                       "high": str(f.get("verdict", "")).upper() == "CONFIRM"})
        else:
            subprocess.run(["docker", "exec", f"cyberswarm_{app}",
                            "true"], capture_output=True)  # noop, keep parity
        # Per-app state isolation: move the per-target state files aside so
        # the next app's recon does not inherit this app's engagement.
        state_dir = run_dir / f"state_{app}"
        state_dir.mkdir(exist_ok=True)
        for pattern in ("results/evidence/localhost.json",
                        "results/attack_evidence/localhost.json",
                        "results/system_map/localhost.json",
                        "results/state/localhost.json",
                        "results/phase_state/localhost.json",
                        "results/traces/localhost.json"):
            src = ROOT / pattern
            if src.exists():
                shutil.move(str(src), str(state_dir / Path(pattern).name))
        eng = ROOT / "results/engagements/localhost"
        if eng.exists():
            shutil.move(str(eng), str(state_dir / "engagement"))
    return detections, log, status


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def norm_path(p):
    p = (p or "").split("?")[0].rstrip("/") or "/"
    if p.startswith("/#/"):
        p = "/" + p[2:].split("?")[0] or "/"
    return p


_CLASS_EQUIV = {"lfi": {"lfi", "path_traversal"}}


def score(tool, detections, run_dir):
    per_inst = {f"{i['app']}:{i['endpoint']}" for i in GROUND_TRUTH}
    truth_by_key = {f"{i['app']}:{i['endpoint']}": i for i in GROUND_TRUTH}
    app_of_port = {v: k for k, v in APP_PORTS.items()}
    hits, param_hits, control_hits, false_high = [], [], [], []
    app_boundaries = {}
    for det in detections:
        path = norm_path(det["endpoint"])
        app = None
        for i in GROUND_TRUTH:
            ep = i["endpoint"]
            if ep.startswith("/#"):
                ep_norm = "/" + ep[2:].split("?")[0]
            else:
                ep_norm = ep.rstrip("/")
            if path == ep_norm or path.startswith(ep_norm + "/"):
                app = i["app"]
                key = f"{i['app']}:{i['endpoint']}"
                gt_cls = truth_by_key[key]["cls"]
                # Equivalence rule (2026-11-16, applied uniformly to every
                # arm): lfi and path_traversal are the same underlying flaw
                # — a path-traversal detection at an lfi ground-truth
                # endpoint is a hit. This matches the paper taxonomy, which
                # classifies such findings under both classes; before this
                # rule ZAP's high path_traversal alerts at the three lab lfi
                # endpoints went uncredited while CyberSwarm's same-class
                # taxonomy labels were credited (asymmetric, flagged in
                # review).
                if det["cls"] == gt_cls or det["cls"] in _CLASS_EQUIV.get(gt_cls, set()):
                    hits.append(key)
                    if det.get("param") and det["param"] == truth_by_key[key]["param"]:
                        param_hits.append(key)
        # app boundary by port-prefix heuristics: control hits only exist on lab
        if app is None:
            for i in CONTROLS:
                if path == i:
                    control_hits.append(path)
        if det.get("high") and app is None and path not in CONTROLS:
            # uniform across tools: a high-severity alert at a non-ground-truth
            # path is false high-severity noise regardless of which tool
            # emitted it (previously gated to ZAP only).
            false_high.append({"endpoint": path,
                               "alert": det.get("name") or det.get("template")})
    return {
        "hits": sorted(set(hits)), "param_hits": sorted(set(param_hits)),
        "control_hits": sorted(set(control_hits)),
        "false_high_severity": false_high,
        "instances": len(GROUND_TRUTH),
        "tp": len(set(hits)),
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def start_lab_apps(run_dir):
    procs = []
    for mod, which, port in (("lab_app_v2", "vuln", LAB_PORT),
                             ("lab_app_v2c", "control", CONTROL_PORT)):
        code = (f"import sys; sys.path.insert(0,'scripts'); import {mod}; "
                f"(lab_app_v2.app if '{mod}'=='lab_app_v2' else {mod}.control_app)"
                f".run(host='127.0.0.1', port={port})")
        log = run_dir / f"lab_{which}_{port}.log"
        procs.append(subprocess.Popen(
            [sys.executable, "-c", code.replace("lab_app_v2.app if", f"{mod}.app if")]
            if mod == "lab_app_v2" else [sys.executable, "-c", code],
            cwd=str(ROOT), stdout=log.open("w"), stderr=subprocess.STDOUT))
    time.sleep(2)
    return procs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", nargs="+",
                    default=["sqlmap", "nuclei-serial", "nuclei-concurrent", "zap"],
                    choices=["sqlmap", "nuclei-serial", "nuclei-concurrent", "zap",
                             "cyberswarm"])
    ap.add_argument("--timeout", type=int, default=TIME_BUDGET_S)
    ap.add_argument("--out", default="results/scanner_benchmark")
    args = ap.parse_args()

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = ROOT / args.out / stamp
    run_dir.mkdir(parents=True, exist_ok=True)

    # logging proxies: every tool talks to the proxy ports
    lab_procs = start_lab_apps(run_dir)
    dvwa_cookie = dvwa_cookie_header()
    print(f"[auth] dvwa cookie: {'ok' if dvwa_cookie else 'FAILED'}")
    # Authentication is injected at the proxy level so every tool's DVWA
    # traffic is uniformly authenticated (disclosed in the protocol; the
    # per-tool cookie flags become redundant but are kept so the exact
    # command lines stay reproducible).
    inject = {"Cookie": dvwa_cookie[len("Cookie: "):]} if dvwa_cookie else None
    proxies = {}
    for backend, prox in PROXY_PORTS.items():
        proxies[backend] = LoggingProxy(
            backend, prox, run_dir / f"proxy_{prox}.log",
            inject_headers=inject if backend == DVWA_PORT else None)
    base_by_app = {
        "dvwa": f"http://localhost:{PROXY_PORTS[DVWA_PORT]}",
        "juice": f"http://localhost:{PROXY_PORTS[JUICE_PORT]}",
        "lab": f"http://localhost:{PROXY_PORTS[LAB_PORT]}",
    }
    print(f"[auth] dvwa cookie: {'ok' if dvwa_cookie else 'FAILED'}")

    _nuc_ver = subprocess.run(["nuclei", "--version"], capture_output=True,
                              text=True)
    _nuc_m = re.search(r"v\d+\.\d+\.\d+", _nuc_ver.stdout + _nuc_ver.stderr)
    ver = {"sqlmap": subprocess.run(["sqlmap", "--version"], capture_output=True,
                                    text=True).stdout.strip(),
           "nuclei": _nuc_m.group(0) if _nuc_m else "unknown",
           "templates": subprocess.run(
               ["ls", str(Path.home() / "nuclei-templates")],
               capture_output=True, text=True).stdout.count("\n"),
           "zap": "2.17.0", "cyberswarm": "freeze-2 code (FROZEN_MANIFEST_2.json)"}

    verified = verify_ground_truth(
        {k: f"http://localhost:{v}" for k, v in
         {"dvwa": DVWA_PORT, "juice": JUICE_PORT, "lab": LAB_PORT}.items()},
        dvwa_cookie)
    n_ok = sum(verified.values())
    print(f"[truth] {n_ok}/{len(GROUND_TRUTH)} instances verified")

    # Ground truth must be fully verified before any arm runs (protocol §2).
    # If not, restart the target containers once and re-verify; abort the
    # run rather than score against a partially-verified environment
    # (the queue11 runs recorded 24/34 with juice's container dead and
    # proceeded — a protocol violation this check now prevents).
    if n_ok < len(GROUND_TRUTH):
        print("[truth] incomplete — restarting containers and re-verifying",
              flush=True)
        for c in ("cyberswarm_dvwa_db", "cyberswarm_dvwa",
                  "cyberswarm_juiceshop"):
            subprocess.run(["docker", "start", c], capture_output=True)
        time.sleep(10)
        try:
            dvwa_cookie = dvwa_cookie_header()
            inject = {"Cookie": dvwa_cookie[len("Cookie: "):]} if dvwa_cookie \
                else None
            for backend, prox in PROXY_PORTS.items():
                proxies[backend].inject_headers = \
                    inject if backend == DVWA_PORT else None
        except Exception:
            pass
        verified = verify_ground_truth(
            {k: f"http://localhost:{v}" for k, v in
             {"dvwa": DVWA_PORT, "juice": JUICE_PORT,
              "lab": LAB_PORT}.items()},
            dvwa_cookie)
        n_ok = sum(verified.values())
        print(f"[truth] after restart: {n_ok}/{len(GROUND_TRUTH)}", flush=True)
        if n_ok < len(GROUND_TRUTH):
            (run_dir / "run.json").write_text(json.dumps(
                {"stamp": stamp,
                 "date": datetime.datetime.now().isoformat(),
                 "verified_count": f"{n_ok}/{len(GROUND_TRUTH)}",
                 "status": "env-fail: ground truth incomplete after restart"},
                indent=1))
            print("[truth] aborting — 34/34 required (protocol §2)", flush=True)
            return 1

    record = {"stamp": stamp, "date": datetime.datetime.now().isoformat(),
              "tool_versions": ver, "verified": verified,
              "verified_count": f"{n_ok}/{len(GROUND_TRUTH)}",
              "time_budget_s": args.timeout, "tools": {}}
    (run_dir / "run.json").write_text(json.dumps(record, indent=1))

    tool_ports = {}
    for tool in args.tools:
        print(f"[{tool}] starting at {datetime.datetime.now():%H:%M:%S}", flush=True)
        t0 = time.time()
        pre_counts = {b: p.count() for b, p in proxies.items()}
        if tool == "sqlmap":
            det, log, st = run_sqlmap(run_dir, base_by_app, dvwa_cookie, args.timeout)
        elif tool.startswith("nuclei"):
            extra = ["-c", "1"] if tool.endswith("serial") else []
            det, log, st = run_nuclei(run_dir, base_by_app, dvwa_cookie,
                                      args.timeout, tool[7:], extra)
        elif tool == "zap":
            zap_proc = start_zap(run_dir)
            if not zap_proc:
                print("[zap] daemon failed to start", flush=True)
                continue
            try:
                det, log, st = run_zap(run_dir, base_by_app, args.timeout)
            finally:
                zap_proc.kill()
        else:
            det, log, st = run_cyberswarm(run_dir, base_by_app, dvwa_cookie,
                                          args.timeout)
        mins = (time.time() - t0) / 60
        sc = score(tool, det, run_dir)
        requests_by_proxy = {str(b): p.count() - pre_counts[b] for b, p in proxies.items()}
        tool_ports[tool] = {"detections": det, "score": sc, "status": st,
                            "runtime_min": round(mins, 1),
                            "requests": requests_by_proxy}
        record["tools"][tool] = tool_ports[tool]
        (run_dir / "run.json").write_text(json.dumps(record, indent=1))
        print(f"[{tool}] done in {mins:.1f} min | TP {sc['tp']}/{sc['instances']} "
              f"| controls {len(sc['control_hits'])} | ZAP-high-FP "
              f"{len(sc['false_high_severity'])} | {st}", flush=True)

    for p in proxies.values():
        p.stop()
    for pr in lab_procs:
        pr.terminate()
    print("run dir:", run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
