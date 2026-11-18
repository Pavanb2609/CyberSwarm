"""
benchmark_payload_agent.py — ground-truth benchmark for CyberSwarm's PayloadAgent.

Every scenario is a local loopback HTTP mock server with a KNOWN ground truth
(genuinely vulnerable, or genuinely clean-but-noisy). The agent is run
end-to-end against each one exactly as it would run in a real engagement.
No live network, no third-party targets.

Metrics reported:
  - True-positive rate per category (does it detect a REAL vuln in that class)
  - False-positive rate per category (does a benign-but-noisy page fool it)
"""
import sys, threading, time, json
sys.path.insert(0, ".")
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from agents.registry import load_agent


class _MC:
    model = "qwen3:8b"
    def complete(self, *a, **k):
        return {"content": "{}"}


def serve(handler_cls):
    httpd = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{port}"


def run_agent(base, endpoint_path, param, tech):
    smap = {"target": "127.0.0.1", "full_url": base,
            "web_surfaces": [{"url": base}],
            "endpoints": [f"{base}{endpoint_path}"],
            "technologies": [{"name": t} for t in tech],
            "parameters": [param]}
    return load_agent("payload", _MC()).run("127.0.0.1", smap, {})


class Quiet(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, status=200, extra_headers=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


# ── TRUE-POSITIVE (genuinely vulnerable) handlers ───────────────────────────

class XssVuln(Quiet):
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        self._send(f"<html><body>Hi {v}</body></html>")  # unescaped, real reflection

class SqliVuln(Quiet):
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        if "'" in v:
            self._send("You have an error in your SQL syntax near line 1")
        else:
            self._send("<html>no results</html>")

class SstiVuln(Quiet):
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        if "{{7*7}}" in v or "${7*7}" in v:
            self._send("Result: 49")
        else:
            self._send(f"Result: {v}")

class LfiVuln(Quiet):
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("path", [""])[0]
        if "etc/passwd" in v:
            self._send("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin")
        else:
            self._send("<html>ok</html>")

class CmdiVuln(Quiet):
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        if ";id" in v or "`id`" in v:
            self._send("uid=0(root) gid=0(root) groups=0(root)")
        else:
            self._send("<html>ok</html>")

class CmdiBlindVuln(Quiet):
    """No output reflected at all — the only signal is that a sleep-style
    payload makes the response take genuinely longer."""
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        if "sleep 5" in v:
            time.sleep(4.5)
        self._send("<html>ok</html>")

class CrlfVuln(Quiet):
    """Genuinely reflects the raw decoded param into a response header —
    a real CRLF header-injection bug."""
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("redirect", [""])[0]
        self._send("<html>ok</html>", extra_headers={"X-Echo": v})

class OpenRedirectVuln(Quiet):
    """Genuinely vulnerable: redirects to whatever off-host value is supplied."""
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("redirect", [""])[0]
        if v.startswith("//") or v.startswith("http"):
            self.send_response(302)
            self.send_header("Location", v)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send("<html>ok</html>")


# ── FALSE-POSITIVE bait (clean, but textually noisy) handlers ──────────────

class XssClean(Quiet):
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        import html as _h
        self._send(f"<html><body>Hi {_h.escape(v)}</body></html>")

class SqliBoilerplate(Quiet):
    """Clean: identical response regardless of payload, but the boilerplate
    text contains an SQL-error-looking phrase."""
    def do_GET(self):
        self._send("<html>Search results.<footer>If you see 'SQL syntax' "
                    "issues, contact support.</footer></html>")

class SstiPriceTag(Quiet):
    """Clean: static receipt page, no templating at all — but the number 49
    appears as an ordinary price."""
    def do_GET(self):
        self._send("<html>Your cart total: $49.00 (order #49)</html>")

class CmdiSampleDoc(Quiet):
    """Clean: a help page showing example CLI output as documentation text."""
    def do_GET(self):
        self._send("<html>Example output: uid=1000(testuser) gid=1000(testuser)"
                    "</html>")

class CmdiEchoTrap(Quiet):
    """Clean: reflects whatever was submitted verbatim, like a plain search
    page — never executes anything. Must NOT be flagged just because the
    payload text itself happens to contain the word 'whoami'."""
    def do_GET(self):
        v = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        self._send(f"<html>You searched for: {v}</html>")


# ── JSON-API and XXE handlers (need POST) ───────────────────────────────────

class JsonApiVuln(Quiet):
    """A POST-JSON-only endpoint (no query string at all) — genuinely
    vulnerable reflected XSS in the JSON field."""
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            v = str(json.loads(raw).get("q", ""))
        except Exception:
            v = ""
        self._send(f"<html><body>Hi {v}</body></html>")
    def do_GET(self):
        self._send("<html>not found</html>", 404)

class XxeVuln(Quiet):
    """Genuinely vulnerable to XXE: an external entity pointing at
    /etc/passwd gets resolved and its content leaked back."""
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        if "SYSTEM" in raw and "file://" in raw:
            self._send("<x>root:x:0:0:root:/root:/bin/bash</x>")
        else:
            self._send("<x>ok</x>")
    def do_GET(self):
        self._send("<html>not found</html>", 404)


SCENARIOS = [
    # (label, handler, endpoint, param, tech, expected_category, ground_truth)
    ("TP xss",            XssVuln,          "/greet?q=w", "q", ["PHP"],    "xss",  True),
    ("TP sqli",           SqliVuln,         "/search?q=a", "q", ["PHP"],   "sqli", True),
    ("TP ssti",           SstiVuln,         "/calc?q=1", "q", ["Jinja2"],  "ssti", True),
    ("TP lfi",            LfiVuln,          "/page?path=x", "path", ["PHP"],     "lfi",  True),
    ("TP cmdi",           CmdiVuln,         "/run?q=x", "q", ["PHP"],      "cmdi", True),
    ("TP crlf (header)",  CrlfVuln,         "/echo?redirect=x", "redirect", ["PHP"], "crlf", True),
    ("TP open_redirect",  OpenRedirectVuln, "/go?redirect=x", "redirect", ["PHP"], "open_redirect", True),
    ("TP cmdi (blind/timing)", CmdiBlindVuln, "/run?q=x", "q", ["PHP"],    "cmdi", True),
    ("FP xss (escaped)",  XssClean,         "/greet?q=w", "q", ["PHP"],    "xss",  False),
    ("FP sqli (boilerplate)", SqliBoilerplate, "/search?q=a", "q", ["PHP"], "sqli", False),
    ("FP ssti (price tag)", SstiPriceTag,   "/calc?q=1", "q", ["Jinja2"],  "ssti", False),
    ("FP cmdi (sample doc)", CmdiSampleDoc, "/run?q=x", "q", ["PHP"],      "cmdi", False),
    ("FP cmdi (echo trap)", CmdiEchoTrap,   "/search?q=x", "q", ["PHP"],   "cmdi", False),
]

EXTRA_SCENARIOS = [
    # (label, handler, endpoint, param, tech, expected_category, ground_truth)
    ("TP json-api xss (POST body)", JsonApiVuln, "/api/search?q=1", "q", ["json api"], "xss", True),
    ("TP xxe (POST XML body)",      XxeVuln,     "/soap?wsdl=1", "q", ["SOAP API"],    "xxe", True),
]

print(f"{'scenario':<26}{'ground truth':<14}{'agent found it?':<18}{'severity':<10}{'time(s)':<8}")
print("-" * 78)
results = []
for label, handler, ep, param, tech, cat, is_vuln in SCENARIOS + EXTRA_SCENARIOS:
    httpd, base = serve(handler)
    t0 = time.time()
    try:
        res = run_agent(base, ep, param, tech)
    finally:
        httpd.shutdown()
    dt = time.time() - t0
    hit = next((f for f in res.findings if cat.replace("_", " ").split()[0] in f.name.lower()
                or cat in f.raw_output_excerpt), None)
    # more precise: check category via evidence chain / raw_output_excerpt
    hit = None
    for f in res.findings:
        if f"'{cat}'" in f.description or f'"category": "{cat}"' in f.raw_output_excerpt:
            hit = f
            break
    found = hit is not None
    sev = hit.severity if hit else "-"
    correct = (found == is_vuln)
    results.append((label, is_vuln, found, sev, correct))
    print(f"{label:<26}{str(is_vuln):<14}{str(found):<18}{sev:<10}{dt:<8.2f}")

print("-" * 78)
tp_cases = [r for r in results if r[1]]
fp_cases = [r for r in results if not r[1]]
tp_rate = sum(1 for r in tp_cases if r[2]) / len(tp_cases) * 100
fp_rate = sum(1 for r in fp_cases if r[2]) / len(fp_cases) * 100 if fp_cases else 0
print(f"\nTrue-positive detection rate: {tp_rate:.0f}% ({sum(1 for r in tp_cases if r[2])}/{len(tp_cases)})")
print(f"False-positive rate on clean/noisy targets: {fp_rate:.0f}% ({sum(1 for r in fp_cases if r[2])}/{len(fp_cases)})")
