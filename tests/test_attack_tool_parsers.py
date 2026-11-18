"""Golden parser tests for the attack-phase tool wrappers in tools/attack/.

Same rationale as test_tool_parsers.py: feed each parse() realistic canned
output (or, for run()-override tools, mock the network/subprocess layer)
and assert the normalized shape.
"""

import json
import re

import pytest

from tools.attack import nuclei_tags
from tools.attack.api_probe import ApiProbeTool
from tools.attack.auth_probe import AuthProbeTool
from tools.attack.clickjacking import ClickjackingTool
from tools.attack.commix import CommixTool
from tools.attack.corsy import CorsyTool
from tools.attack.dalfox import DalfoxTool
from tools.attack.feroxbuster import FeroxbusterTool
from tools.attack.host_header import HostHeaderAttackTool
from tools.attack.http_methods import HttpMethodTestTool
from tools.attack.jwt_tool import JwtTool
from tools.attack.nikto import NiktoTool
from tools.attack.nmap_nse import NmapNSETool
from tools.attack.nuclei import NucleiTool
from tools.attack.searchsploit import SearchsploitTool
from tools.attack.sqlmap import SqlmapTool
from tools.attack.sslyze import SSLyzeTool
from tools.attack.subjack import SubjackTool
from tools.attack.wafw00f import Wafw00fTool

# ── nuclei ────────────────────────────────────────────────────────────────

NUCLEI_LINE = json.dumps({
    "template-id": "exposed-panel", "type": "http",
    "info": {"name": "Exposed Admin Panel", "severity": "medium",
             "description": "Admin panel is exposed", "tags": ["panel", "exposure"],
             "reference": ["https://example.org/ref1", "https://example.org/ref2"],
             "classification": {"cve-id": ["CVE-2021-1234"], "cwe-id": ["CWE-200"],
                                "cvss-score": 5.3}},
    "matched-at": "https://example.com/admin",
})


def test_nuclei_parses_findings_from_output_file(tmp_path):
    tool = NucleiTool()
    tool._out_file = tmp_path / "nuclei.jsonl"
    tool._out_file.write_text(NUCLEI_LINE + "\n[INF] progress noise\n")
    out = tool.parse("", "")
    assert out["count"] == 1
    f = out["nuclei_findings"][0]
    assert f["template_id"] == "exposed-panel"
    assert f["severity"] == "MEDIUM"
    assert f["cve_id"] == ["CVE-2021-1234"]
    assert f["cvss_score"] == 5.3


def test_nuclei_dedupes_by_template_and_url(tmp_path):
    tool = NucleiTool()
    tool._out_file = tmp_path / "nuclei.jsonl"
    tool._out_file.write_text(NUCLEI_LINE + "\n" + NUCLEI_LINE + "\n")
    out = tool.parse("", "")
    assert out["count"] == 1


def test_nuclei_falls_back_to_stdout_when_no_output_file():
    tool = NucleiTool()
    tool._out_file = None
    out = tool.parse(NUCLEI_LINE, "")
    assert out["count"] == 1


def test_nuclei_json_array_format():
    tool = NucleiTool()
    tool._out_file = None
    array_line = json.dumps([json.loads(NUCLEI_LINE)])
    out = tool.parse(array_line, "")
    assert out["count"] == 1


def test_nuclei_handles_empty_output():
    tool = NucleiTool()
    tool._out_file = None
    out = tool.parse("", "")
    assert out == {"nuclei_findings": [], "count": 0}


# ── nuclei_tags subclasses (all 15) ──────────────────────────────────────────

_TAG_CLASSES = [
    (nuclei_tags.SSRFScanTool, "SSRF_SCAN", "ssrf"),
    (nuclei_tags.LFIScanTool, "LFI_SCAN", "lfi"),
    (nuclei_tags.SSTIScanTool, "SSTI_SCAN", "ssti"),
    (nuclei_tags.OpenRedirectScanTool, "OPEN_REDIRECT_SCAN", "redirect"),
    (nuclei_tags.CmdInjectionScanTool, "CMD_INJECTION_SCAN", "command-injection"),
    (nuclei_tags.XSSScanTool, "XSS_SCAN", "xss"),
    (nuclei_tags.SQLiScanTool, "SQLI_SCAN", "sqli"),
    (nuclei_tags.ExposedPanelsScanTool, "EXPOSED_PANELS_SCAN", "exposed-panels"),
    (nuclei_tags.DefaultCredScanTool, "DEFAULT_CRED_SCAN", "default-login"),
    (nuclei_tags.MisconfigScanTool, "MISCONFIG_SCAN", "misconfig"),
    (nuclei_tags.SubdomainTakeoverScanTool, "SUBDOMAIN_TAKEOVER_SCAN", "takeover"),
    (nuclei_tags.HostHeaderScanTool, "HOST_HEADER_ATTACK", "host-header"),
    (nuclei_tags.ClickjackingScanTool, "CLICKJACKING_TEST", "clickjacking"),
    (nuclei_tags.SecretsScanTool, "SECRETS_SCAN", "exposure,secrets"),
    (nuclei_tags.WafDetectScanTool, "WAF_DETECT", "waf-detect"),
]


@pytest.mark.parametrize("cls,capability,default_tags", _TAG_CLASSES)
def test_nuclei_tag_subclass_pins_capability_and_default_tags(cls, capability, default_tags):
    tool = cls()
    assert tool.capability == capability
    cmd = tool.build_command("https://example.com")
    assert "-tags" in cmd
    assert cmd[cmd.index("-tags") + 1] == default_tags


@pytest.mark.parametrize("cls,capability,default_tags", _TAG_CLASSES)
def test_nuclei_tag_subclass_caller_can_override_tags(cls, capability, default_tags):
    tool = cls()
    cmd = tool.build_command("https://example.com", tags="custom-tag")
    assert cmd[cmd.index("-tags") + 1] == "custom-tag"


@pytest.mark.parametrize("cls,capability,default_tags", _TAG_CLASSES)
def test_nuclei_tag_subclass_parse_tags_capability_onto_result(cls, capability, default_tags):
    tool = cls()
    tool._out_file = None
    out = tool.parse(NUCLEI_LINE, "")
    assert out["capability"] == capability


# ── nikto ─────────────────────────────────────────────────────────────────

def test_nikto_parses_json_vulnerabilities(tmp_path):
    tool = NiktoTool()
    tool._json_path = tmp_path / "nikto.json"
    tool._json_path.write_text(json.dumps({
        "vulnerabilities": [{"id": "OSVDB-3092", "OSVDB": "3092", "method": "GET",
                             "url": "/admin/", "msg": "Admin dir found"}]}))
    out = tool.parse("", "")
    assert out["count"] == 1
    assert out["nikto_findings"][0]["url"] == "/admin/"


def test_nikto_falls_back_to_plaintext_plus_lines(tmp_path):
    tool = NiktoTool()
    tool._json_path = tmp_path / "does-not-exist-nikto.json"
    stdout = "+ Server leaks inodes via ETags\n+ /admin/: Admin login page found\n"
    out = tool.parse(stdout, "")
    assert out["count"] == 2


# ── feroxbuster ───────────────────────────────────────────────────────────

def test_feroxbuster_filters_to_interesting_status_codes(tmp_path):
    tool = FeroxbusterTool()
    tool._out = tmp_path / "ferox.json"
    lines = [
        json.dumps({"url": "https://example.com/admin", "status": 200}),
        json.dumps({"url": "https://example.com/secret", "status": 403}),
        json.dumps({"url": "https://example.com/gone", "status": 404}),  # excluded
    ]
    tool._out.write_text("\n".join(lines) + "\n")
    out = tool.parse("", "")
    assert out["count"] == 2
    assert "https://example.com/gone" not in out["discovered_urls"]


# ── corsy ─────────────────────────────────────────────────────────────────

def test_corsy_parses_vulnerable_json(tmp_path):
    tool = CorsyTool()
    tool._out = tmp_path / "corsy.json"
    tool._out.write_text(json.dumps([
        {"url": "https://example.com/api", "reason": "Origin reflected"}]))
    out = tool.parse("", "")
    assert out["count"] == 1
    assert out["cors_findings"][0]["cors_vulnerable"] is True


def test_corsy_no_findings_empty_file(tmp_path):
    tool = CorsyTool()
    tool._out = tmp_path / "corsy.json"
    tool._out.write_text("")
    out = tool.parse("", "")
    assert out["count"] == 0


# ── sslyze ────────────────────────────────────────────────────────────────

def test_sslyze_detects_heartbleed_and_robot(tmp_path):
    tool = SSLyzeTool()
    tool._out = tmp_path / "sslyze.json"
    tool._out.write_text(json.dumps({
        "server_scan_results": {
            "example.com:443": {
                "scan_commands_results": {
                    "heartbleed": {"is_vulnerable_to_heartbleed": True},
                    "robot": {"robot_result": "VULNERABLE"},
                    "compression": {"supports_compression": False},
                },
            },
        },
    }))
    out = tool.parse("", "")
    issues = {f["issue"] for f in out["tls_findings"]}
    assert "Heartbleed" in issues
    assert any("ROBOT" in i for i in issues)
    assert out["count"] == 2


# ── subjack ───────────────────────────────────────────────────────────────

def test_subjack_parses_csv_style_output(tmp_path):
    tool = SubjackTool()
    tool._out = tmp_path / "subjack.txt"
    tool._out.write_text("old.example.com,Vulnerable,Shopify\nother.example.com,Not Vulnerable\n")
    out = tool.parse("", "")
    assert out["count"] == 2
    assert out["takeover_candidates"][0]["domain"] == "old.example.com"


# ── commix ────────────────────────────────────────────────────────────────

def test_commix_detects_injectable_keyword():
    tool = CommixTool()
    out = tool.parse("target url is injectable, identified injection point", "")
    assert out["count"] == 1


def test_commix_no_finding_on_clean_output():
    tool = CommixTool()
    out = tool.parse("no injection points found", "")
    assert out["count"] == 0


# ── jwt_tool ──────────────────────────────────────────────────────────────

def test_jwt_tool_without_token_returns_note():
    tool = JwtTool()
    tool.build_command("example.com")  # sets self._token = ""
    out = tool.parse("", "")
    assert out["count"] == 0
    assert "note" in out


def test_jwt_tool_detects_alg_none():
    tool = JwtTool()
    tool.build_command("example.com", token="eyJhbGciOiJub25lIn0.e30.")
    out = tool.parse("Token accepts alg=none algorithm attack", "")
    assert out["count"] == 1
    assert out["jwt_findings"][0]["severity"] == "HIGH"


# ── http_methods ──────────────────────────────────────────────────────────

def test_http_methods_flags_trace_enabled():
    tool = HttpMethodTestTool()
    stdout = "OPTIONS|200|GET,POST,OPTIONS\nTRACE|200|\nPUT|403|\nDELETE|403|\nPATCH|403|\n"
    out = tool.parse(stdout, "")
    assert any(f["method"] == "TRACE" for f in out["method_findings"])


def test_http_methods_flags_dangerous_verbs_in_allow_header():
    tool = HttpMethodTestTool()
    stdout = "OPTIONS|200|GET,PUT,DELETE\nTRACE|404|\nPUT|200|\nDELETE|403|\nPATCH|403|\n"
    out = tool.parse(stdout, "")
    issues = " ".join(f["issue"] for f in out["method_findings"])
    assert "PUT" in issues


def test_http_methods_clean_server_no_findings():
    tool = HttpMethodTestTool()
    stdout = "OPTIONS|200|GET,POST\nTRACE|404|\nPUT|403|\nDELETE|403|\nPATCH|403|\n"
    out = tool.parse(stdout, "")
    assert out["method_findings"] == []


# ── clickjacking ──────────────────────────────────────────────────────────

def test_clickjacking_flags_missing_protections():
    tool = ClickjackingTool()
    out = tool.parse("HTTP/1.1 200 OK\nContent-Type: text/html\n", "")
    assert out["count"] == 1
    assert out["clickjacking"][0]["frameable"] is True


def test_clickjacking_protected_with_xfo():
    tool = ClickjackingTool()
    out = tool.parse("HTTP/1.1 200 OK\nX-Frame-Options: DENY\n", "")
    assert out["count"] == 0


def test_clickjacking_protected_with_csp_frame_ancestors():
    tool = ClickjackingTool()
    out = tool.parse("HTTP/1.1 200 OK\nContent-Security-Policy: frame-ancestors 'self'\n", "")
    assert out["count"] == 0


# ── host_header ───────────────────────────────────────────────────────────

def test_host_header_detects_reflection_in_location():
    tool = HostHeaderAttackTool()
    stdout = (
        "===BASELINE-HEADERS===\nHTTP/1.1 301\nLocation: https://real.example.com/\n"
        "===EVIL-HEADERS===\nHTTP/1.1 301\nLocation: https://evil.example/\n"
        "===BASELINE-BODY===\nhello\n===EVIL-BODY===\nhello\n===BODYLEN===\n5\n5\n"
    )
    out = tool.parse(stdout, "")
    assert any("Location" in f["issue"] for f in out["host_header_findings"])


def test_host_header_no_reflection_no_findings():
    tool = HostHeaderAttackTool()
    stdout = (
        "===BASELINE-HEADERS===\nHTTP/1.1 200\n"
        "===EVIL-HEADERS===\nHTTP/1.1 200\n"
        "===BASELINE-BODY===\nhello\n===EVIL-BODY===\nhello\n===BODYLEN===\n5\n5\n"
    )
    out = tool.parse(stdout, "")
    assert out["host_header_findings"] == []


# ── wafw00f ───────────────────────────────────────────────────────────────

def test_wafw00f_detects_waf_from_list_format(tmp_path):
    tool = Wafw00fTool()
    tool._out = tmp_path / "waf.json"
    tool._out.write_text(json.dumps([
        {"url": "https://example.com", "detected": True, "firewall": "Cloudflare",
         "manufacturer": "Cloudflare Inc."}]))
    out = tool.parse("", "")
    assert out["count"] == 1
    assert out["wafs_detected"][0]["waf_name"] == "Cloudflare"


def test_wafw00f_no_waf_detected(tmp_path):
    tool = Wafw00fTool()
    tool._out = tmp_path / "waf.json"
    tool._out.write_text(json.dumps([
        {"url": "https://example.com", "detected": False, "firewall": "None"}]))
    out = tool.parse("", "")
    assert out["count"] == 0


def test_wafw00f_plaintext_fallback():
    tool = Wafw00fTool()
    tool._out = "/tmp/does-not-exist-waf.json"
    out = tool.parse("The site https://example.com is behind Cloudflare (Cloudflare Inc.)", "")
    assert out["count"] == 1


# ── nmap_nse ──────────────────────────────────────────────────────────────

NMAP_NSE_OUTPUT = """80/tcp open  http
| http-vuln-cve2021-41773:
|   VULNERABLE:
|   Apache path traversal
|     CVE-2021-41773
|_    State: VULNERABLE

443/tcp open  https
| ssl-cert:
|_  NOT VULNERABLE
"""


def test_nmap_nse_extracts_vulnerable_findings_with_cve():
    tool = NmapNSETool()
    out = tool.parse(NMAP_NSE_OUTPUT, "")
    assert out["count"] == 1  # NOT VULNERABLE block filtered out
    f = out["nmap_vuln_findings"][0]
    assert f["port"] == "80/tcp"
    assert "CVE-2021-41773" in f["cve"]
    assert f["severity"] == "HIGH"


def test_nmap_nse_long_vulners_output_truncates_at_a_word_boundary_not_mid_url():
    # Real bug from a live run: nmap's vulners NSE script lists several
    # "CVE\tscore\turl" entries on one line; a plain [:400] slice cut the
    # 5th entry's URL down to "https://vulners.com/c" -- indistinguishable
    # from corrupted data. The fix must never leave a dangling partial URL,
    # and must mark that a cut happened.
    entries = " ".join(
        f"CVE-2026-{10000 + i}\t{9.0 - i * 0.1:.1f}\thttps://vulners.com/cve/CVE-2026-{10000 + i}"
        for i in range(20)
    )
    raw = f"80/tcp open  http\n| vulners:\n|   cpe:/a:openbsd:openssh:9.9:\n|_    {entries}\n"
    tool = NmapNSETool()
    out = tool.parse(raw, "")
    finding = out["nmap_vuln_findings"][0]
    output = finding["output"]
    assert len(output) <= 400 + len(" …[truncated]")
    assert "…[truncated]" in output
    # every URL that DID make it into the truncated text must be complete
    for url in re.findall(r"https://\S+", output):
        assert not url.rstrip(".").endswith("vulners.com"), f"dangling/incomplete URL: {url!r}"
        assert "CVE-2026-" in url, f"URL got cut before the CVE id: {url!r}"


def test_nmap_nse_short_output_is_not_truncated():
    tool = NmapNSETool()
    out = tool.parse(NMAP_NSE_OUTPUT, "")
    finding = out["nmap_vuln_findings"][0]
    assert "[truncated]" not in finding["output"]


# ── searchsploit ──────────────────────────────────────────────────────────

def test_searchsploit_parses_exploit_and_shellcode_results():
    tool = SearchsploitTool()
    raw = json.dumps({
        "RESULTS_EXPLOIT": [{"Title": "WordPress 5.8 - RCE (CVE-2021-9999)",
                             "EDB-ID": "50000", "Type": "webapps", "Platform": "php",
                             "Path": "/path/to/exploit"}],
        "RESULTS_SHELLCODE": [],
    })
    out = tool.parse(raw, "")
    assert out["count"] == 1
    ex = out["exploit_candidates"][0]
    assert ex["cve"] == ["CVE-2021-9999"]
    assert ex["url"] == "https://www.exploit-db.com/exploits/50000"


def test_searchsploit_invalid_json_returns_empty():
    tool = SearchsploitTool()
    out = tool.parse("not json", "")
    assert out == {"exploit_candidates": [], "count": 0}


# ── sqlmap / dalfox (spot-check; deeper coverage already exists elsewhere) ──

def test_sqlmap_detects_vulnerable_output():
    tool = SqlmapTool()
    out = tool.parse("Parameter 'id' is vulnerable. back-end DBMS: MySQL >= 5.0", "")
    assert out["count"] == 1


def test_sqlmap_no_finding_on_clean_output():
    tool = SqlmapTool()
    out = tool.parse("all tested parameters do not appear to be injectable", "")
    assert out["count"] == 0


def test_sqlmap_parse_json_output(tmp_path):
    """Enhanced sqlmap parses JSON output file with injection details."""
    tool = SqlmapTool()
    json_data = {
        "data": {
            "id": {
                "1": {
                    "title": "AND boolean-based blind - WHERE or HAVING clause",
                    "payload": "id=1 AND 1=1",
                    "dbms": "MySQL >= 5.0",
                    "vector": "AND [RANDNUM]=[RANDNUM]",
                    "place": "id",
                }
            }
        }
    }
    tool._out_file = tmp_path / "sqlmap.json"
    tool._out_file.write_text(json.dumps(json_data))
    out = tool.parse("", "")
    assert out["count"] == 1
    f = out["sqlmap_findings"][0]
    assert f["injection_type"] == "boolean_based"
    assert f["parameter"] == "id"
    assert f["dbms"] == "MySQL >= 5.0"
    assert f["vulnerable"] is True


def test_sqlmap_parse_json_time_based(tmp_path):
    """Enhanced sqlmap parses time-based injection from JSON."""
    tool = SqlmapTool()
    json_data = {
        "data": {
            "search": {
                "1": {
                    "title": "MySQL >= 5.0.12 AND time-based blind",
                    "payload": "search=test AND SLEEP(5)",
                    "dbms": "MySQL",
                    "place": "search",
                }
            }
        }
    }
    tool._out_file = tmp_path / "sqlmap.json"
    tool._out_file.write_text(json.dumps(json_data))
    out = tool.parse("", "")
    f = out["sqlmap_findings"][0]
    assert f["injection_type"] == "time_based"
    assert f["parameter"] == "search"


def test_sqlmap_level5_builds_correct_command():
    """Enhanced sqlmap respects level/risk kwargs."""
    tool = SqlmapTool()
    cmd = tool.build_command("http://example.com/?id=1", level=5, risk=3,
                             cookie="session=abc123", forms=False)
    assert "--level" in cmd
    assert cmd[cmd.index("--level") + 1] == "5"
    assert "--risk" in cmd
    assert cmd[cmd.index("--risk") + 1] == "3"
    assert "--cookie" in cmd
    assert "session=abc123" in cmd
    assert "--forms" not in cmd


def test_sqlmap_parse_text_extracts_parameter():
    """Enhanced sqlmap extracts parameter name from text output."""
    tool = SqlmapTool()
    out = tool.parse("Parameter: 'username' is vulnerable.\nback-end DBMS: PostgreSQL", "")
    assert out["count"] == 1
    f = out["sqlmap_findings"][0]
    assert f["parameter"] == "username"
    assert f["dbms"] == "PostgreSQL"


def test_dalfox_parses_jsonl_findings():
    tool = DalfoxTool()
    out = tool.parse(json.dumps({"type": "XSS", "data": "https://example.com/?q=<script>"}), "")
    assert out["count"] == 1


# ── api_probe / auth_probe (mocked urllib) ───────────────────────────────────

class _FakeResp:
    def __init__(self, status, body=b""):
        self.status = status
        self._body = body

    def read(self, n=None):
        return self._body

    def geturl(self):
        return "https://example.com/probed"

    def getheaders(self):
        return [("Server", "nginx"), ("Set-Cookie", "session=abc; Secure; HttpOnly")]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_api_probe_flags_auth_required_on_401(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _FakeResp(401))
    tool = ApiProbeTool()
    result = tool.run("example.com", paths=["/api/v1/users"])
    assert result.status == "success"
    probe = result.results["api_probes"][0]
    assert probe["auth_required"] is True


def test_api_probe_no_paths_responding_errors(monkeypatch):
    def _raise(*a, **k):
        raise ConnectionRefusedError()
    monkeypatch.setattr("urllib.request.urlopen", _raise)
    tool = ApiProbeTool()
    result = tool.run("example.com", paths=["/api/v1/users"])
    assert result.status == "error"


def test_auth_probe_detects_login_form_and_cookie_flags(monkeypatch):
    resp = _FakeResp(200, b'<form action="/login"><input type="password"></form>')
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: resp)
    tool = AuthProbeTool()
    result = tool.run("example.com", paths=["/login"])
    assert result.status == "success"
    check = result.results["auth_checks"][0]
    assert check["login_form"] is True
    assert check["cookie_flags"]["secure"] is True
    assert check["cookie_flags"]["httponly"] is True


# ── XXE ────────────────────────────────────────────────────────────────────

def test_xxe_parse_passwd_leak(monkeypatch):
    """XXE tool detects /etc/passwd content leaked in response."""
    from tools.attack.xxe import XXEScanTool

    class _FakeResp:
        status = 200
        def __init__(self, body):
            self._body = body
            self.headers = {}
        def read(self, n): return self._body
        def getheaders(self): return []
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def geturl(self): return "http://example.com"

    fake_resp = _FakeResp(b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: fake_resp)
    tool = XXEScanTool()
    result = tool.run("http://example.com", timeout=10)
    assert result.status == "success"
    assert result.results["count"] >= 1
    f = result.results["xxe_findings"][0]
    assert f["severity"] in ("CRITICAL", "HIGH")
    assert f["type"] == "error_based"
    assert "root:" in f["evidence"]


def test_xxe_parse_no_vuln(monkeypatch):
    """XXE tool returns no findings for a clean response."""
    from tools.attack.xxe import XXEScanTool

    class _FakeResp:
        status = 200
        def __init__(self, body):
            self._body = body
            self.headers = {}
        def read(self, n): return self._body
        def getheaders(self): return []
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def geturl(self): return "http://example.com"

    fake_resp = _FakeResp(b"<root>hello</root>")
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: fake_resp)
    tool = XXEScanTool()
    result = tool.run("http://example.com", timeout=10)
    assert result.status == "success"
    assert result.results["count"] == 0


def test_xxe_build_command():
    from tools.attack.xxe import XXEScanTool
    tool = XXEScanTool()
    cmd = tool.build_command("http://example.com")
    assert "python-urllib-xxe" in cmd[0]


# ── CRLF ──────────────────────────────────────────────────────────────────

def test_crlf_parse_injected_header(monkeypatch):
    """CRLF tool only reports a marker that is injected AND absent from the
    clean baseline response (truth-marker + exclusion)."""

    from tools.attack.crlf import CRLFInjectionTool

    calls = [0]

    def fake_run(cmd, **kwargs):
        calls[0] += 1
        class FakeProc:
            stderr = ""
            returncode = 0
            stdout = ""
        # call 1 = clean baseline for the first parameter payload
        if calls[0] == 1:
            FakeProc.stdout = "HTTP/1.1 200 OK\nContent-Type: text/html\n"
        # call 2 = injected request, marker present on its own header line
        elif calls[0] == 2:
            FakeProc.stdout = "HTTP/1.1 200 OK\nX-Injected: true\nContent-Type: text/html\n"
        else:
            FakeProc.stdout = "HTTP/1.1 200 OK\nContent-Type: text/html\n"
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    tool = CRLFInjectionTool()
    result = tool.run("http://example.com", timeout=10,
                      endpoints=["/page"])
    assert result.status == "success"
    assert result.results["count"] >= 1
    f = result.results["crlf_findings"][0]
    assert f["severity"] == "HIGH"
    assert "absent_in_baseline" in f["proof_criteria"]


def test_crlf_marker_in_baseline_is_not_a_finding(monkeypatch):
    """A marker already present in the clean baseline (e.g. a pre-existing
    Location header) must NOT be reported as CRLF injection."""

    from tools.attack.crlf import CRLFInjectionTool

    def fake_run(cmd, **kwargs):
        class FakeProc:
            stderr = ""
            returncode = 0
            stdout = "HTTP/1.1 302 Found\nLocation: https://evil.com\nContent-Type: text/html\n"
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    tool = CRLFInjectionTool()
    result = tool.run("http://example.com", timeout=10, endpoints=["/page"])
    assert result.status == "success"
    assert result.results["count"] == 0


# ── CSRF ──────────────────────────────────────────────────────────────────

def test_csrf_parse_missing_token(monkeypatch):
    """CSRF tool reports a HIGH finding only when the cross-origin oracle
    proves the request is accepted tokenless (Origin not checked)."""

    from tools.attack.csrf import CSRFScanTool

    class _FakeProc:
        stdout = "200"
        stderr = ""

    def _fake_run(cmd, **kwargs):
        return _FakeProc()

    monkeypatch.setattr("subprocess.run", _fake_run)
    tool = CSRFScanTool()
    # Now expects csrf_surface from recon detection phase
    csrf_surface = [{"action_url": "http://example.com/transfer",
                     "method": "POST", "has_csrf_token": False, "risk": "high",
                     "form_html_snippet": ""}]
    result = tool.run("http://example.com", timeout=10,
                      csrf_surface=csrf_surface)
    assert result.status == "success"
    assert result.results["count"] >= 1
    f = result.results["csrf_findings"][0]
    assert f["severity"] == "HIGH"
    assert "CSRF" in f["issue"]
    assert "cross_origin_accepted" in f["proof_criteria"]
    assert f["confidence"] >= 50


def test_csrf_cross_site_rejected_is_protected(monkeypatch):
    """A server that rejects the cross-site request must be reported as
    protected, never as vulnerable."""

    from tools.attack.csrf import CSRFScanTool

    def _fake_run(cmd, **kwargs):
        class _FakeProc:
            stdout = "200"
            stderr = ""
        if "-X" in cmd and "evil.example" in " ".join(cmd):
            _FakeProc.stdout = "403"
        return _FakeProc()

    monkeypatch.setattr("subprocess.run", _fake_run)
    tool = CSRFScanTool()
    csrf_surface = [{"action_url": "http://example.com/transfer",
                     "method": "POST", "has_csrf_token": False, "risk": "high"}]
    result = tool.run("http://example.com", timeout=10, csrf_surface=csrf_surface)
    assert result.status == "success"
    assert result.results["count"] == 0
    assert result.results["protected"]
    assert "cross-site request rejected" in result.results["protected"][0]["reason"]


# ── File Upload ───────────────────────────────────────────────────────────

def test_file_upload_parse_detected(monkeypatch):
    """File upload tool detects upload forms without type restrictions."""
    from tools.attack.file_upload import FileUploadScanTool

    class _FakeProc:
        stdout = "201"
        stderr = ""

    def _fake_run(cmd, **kwargs):
        return _FakeProc()

    monkeypatch.setattr("subprocess.run", _fake_run)
    tool = FileUploadScanTool()
    # Now expects upload_urls from recon detection phase
    result = tool.run("http://example.com", timeout=10,
                      upload_urls=["http://example.com/upload"])
    assert result.status == "success"
    assert result.results["count"] >= 1
    f = result.results["upload_findings"][0]
    assert f["severity"] == "HIGH"
    assert "Extension bypass" in f["issue"]


def test_file_upload_parse_with_accept(monkeypatch):
    """File upload tool reports accepted malicious filenames."""
    from tools.attack.file_upload import FileUploadScanTool

    class _FakeProc:
        stdout = "201"
        stderr = ""

    def _fake_run(cmd, **kwargs):
        return _FakeProc()

    monkeypatch.setattr("subprocess.run", _fake_run)
    tool = FileUploadScanTool()
    result = tool.run("http://example.com", timeout=10,
                      upload_urls=["http://example.com/upload"])
    assert result.status == "success"
    # Tool now reports accepted malicious filenames (curl-based, not HTML parsing)
    assert result.results["count"] >= 1
    f = result.results["upload_findings"][0]
    assert "severity" in f
    assert f["severity"] == "HIGH"


# ── Deserialization ───────────────────────────────────────────────────────

def test_deserialization_parse_java_serial(monkeypatch):
    """Deserialization tool only reports when a server fingerprint of a
    deserialization attempt is present in the response body."""

    from tools.attack.deserialization import DeserializationScanTool

    def fake_run(cmd, **kwargs):
        class FakeProc:
            stdout = "<pre>java.io.ObjectInputStream rejected</pre>\n200 123"
            stderr = ""
            returncode = 0
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    tool = DeserializationScanTool()
    result = tool.run("http://example.com", timeout=10,
                      endpoints=["http://example.com/rpc"])
    assert result.status == "success"
    assert result.results["count"] == 1
    f = result.results["deserialization_findings"][0]
    assert f["severity"] == "MEDIUM"  # deserialization attempt observed, RCE unproven
    assert "fingerprint_matched" in f["proof_criteria"]


def test_deserialization_parse_clean(monkeypatch):
    """Deserialization tool returns no findings for a clean 2xx response --
    a blind 2xx is explicitly NOT evidence (recorded as unconfirmed)."""

    from tools.attack.deserialization import DeserializationScanTool

    def fake_run(cmd, **kwargs):
        class FakeProc:
            stdout = "<html>Hello world</html>\n200 100"
            stderr = ""
            returncode = 0
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    tool = DeserializationScanTool()
    result = tool.run("http://example.com", timeout=10,
                      endpoints=["http://example.com/upload"])
    assert result.status == "success"
    assert result.results["count"] == 0
    assert len(result.results["unconfirmed"]) >= 1
    assert result.results["unconfirmed"][0]["unconfirmed"] is True


# ── WAF Bypass Payloads ───────────────────────────────────────────────────

def test_waf_bypass_payloads_findings(monkeypatch):
    """WAF bypass requires a two-sided proof: the encoded probe both differs
    from the raw-attack blocked baseline AND carries a server fingerprint of
    the payload in the response body."""

    from tools.attack.waf_bypass_payloads import WafBypassTool

    def fake_run(cmd, **kwargs):
        s = " ".join(cmd)
        class FakeProc:
            stderr = ""
            returncode = 0
            stdout = ""
        # benign baselines
        if "?id=1" in s or "?q=hello" in s or "?q=id=1" in s or "?q=hello&" in s:
            FakeProc.stdout = "hello\n200 100"
        # the double_url-encoded XSS payload gets through AND triggers a
        # server fingerprint (unescaped <script> reflected)
        elif "%253Cscript%253E" in s:
            FakeProc.stdout = "<script>alert(1)</script>\n200 260"
        # everything else stays blocked/censored by the WAF
        else:
            FakeProc.stdout = "Request blocked by WAF\n403 50"
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    tool = WafBypassTool()
    result = tool.run("http://example.com", timeout=10,
                      waf_type="Cloudflare", endpoint="http://example.com/search")
    assert result.status == "success"
    assert result.results["count"] >= 1
    f = result.results["bypass_findings"][0]
    assert f["severity"] == "HIGH"
    assert "fingerprint_matched" in f["proof_criteria"]
    assert f["encoding"] == "double_url"
