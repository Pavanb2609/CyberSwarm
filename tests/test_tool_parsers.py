"""Golden parser tests for the recon-phase tool wrappers in tools/.

Each wrapper's job is: take whatever the real binary printed (or wrote to
its own temp file) and turn it into our normalized results dict. This file
feeds each parse() a realistic sample of that raw output and asserts the
parsed shape -- this is where format-drift bugs (a binary changing its
JSON schema between versions, a field renamed, an empty-output edge case)
actually live, and it's the coverage gap the plan called out: only
wafw00f had any parser test before this file.
"""

import json
from unittest.mock import MagicMock

import pytest

from tools.cloud.s3_enum import S3EnumTool
from tools.cms.wpscan import WPScanTool
from tools.content.ffuf import FFUFTool
from tools.directory.smb_enum import WindowsServiceEnumerationTool
from tools.dns.dns_resolve import DNSResolutionTool
from tools.javascript.linkfinder import LinkFinderTool
from tools.params.arjun import ArjunTool
from tools.passive.amass import AmassTool
from tools.passive.subfinder import SubfinderTool
from tools.portscan.host_discovery import HostDiscoveryTool
from tools.portscan.naabu import NaabuTool
from tools.portscan.nmap import NmapTool
from tools.screenshots.gowitness import GowitnessTool
from tools.tls.testssl import TestSSLTool
from tools.tls.tls_analysis import TLSAnalysisTool
from tools.web.gau import GauTool
from tools.web.header_analysis import HeaderAnalysisTool
from tools.web.httpx import HttpxTool
from tools.web.katana import KatanaTool
from tools.web.waybackurls import WaybackURLsTool
from tools.web.whatweb import WhatWebTool

# ── subfinder ─────────────────────────────────────────────────────────────

def test_subfinder_parses_jsonl():
    tool = SubfinderTool()
    out = tool.parse('{"host":"api.example.com","input":"example.com"}\n'
                     '{"host":"www.example.com","input":"example.com"}\n', "")
    assert out["subdomains"] == ["api.example.com", "www.example.com"]
    assert out["count"] == 2


def test_subfinder_falls_back_to_plaintext_on_malformed_json():
    tool = SubfinderTool()
    out = tool.parse("api.example.com\nwww.example.com\n", "")
    assert out["subdomains"] == ["api.example.com", "www.example.com"]


def test_subfinder_dedupes():
    tool = SubfinderTool()
    out = tool.parse('{"host":"api.example.com"}\n{"host":"api.example.com"}\n', "")
    assert out["subdomains"] == ["api.example.com"]


def test_subfinder_empty_output():
    tool = SubfinderTool()
    out = tool.parse("", "")
    assert out == {"subdomains": [], "count": 0}


# ── amass ─────────────────────────────────────────────────────────────────

def test_amass_parses_json_file(tmp_path):
    tool = AmassTool()
    tool._json_path = tmp_path / "amass.json"
    tool._json_path.write_text(
        '{"name":"api.example.com","domain":"example.com"}\n'
        '{"name":"www.example.com","domain":"example.com"}\n')
    out = tool.parse("", "")
    assert out["subdomains"] == ["api.example.com", "www.example.com"]


def test_amass_missing_file_returns_empty(tmp_path):
    tool = AmassTool()
    tool._json_path = tmp_path / "does-not-exist-amass.json"
    out = tool.parse("", "")
    assert out == {"subdomains": [], "count": 0}


def test_amass_skips_malformed_lines(tmp_path):
    tool = AmassTool()
    tool._json_path = tmp_path / "amass.json"
    tool._json_path.write_text('not json\n{"name":"good.example.com"}\n')
    out = tool.parse("", "")
    assert out["subdomains"] == ["good.example.com"]


# ── naabu ─────────────────────────────────────────────────────────────────

def test_naabu_parses_jsonl_sorted_and_deduped():
    tool = NaabuTool()
    out = tool.parse(
        '{"host":"example.com","port":443}\n'
        '{"host":"example.com","port":80}\n'
        '{"host":"example.com","port":80}\n', "")
    assert out["open_ports"] == [80, 443]
    assert out["count"] == 2


# ── nmap (SERVICE_DETECTION) ─────────────────────────────────────────────────

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.22.1"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="http" product="nginx" version="1.22.1"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_parses_open_ports_services_and_technologies(tmp_path):
    tool = NmapTool()
    tool._xml_path = tmp_path / "nmap.xml"
    tool._xml_path.write_text(NMAP_XML)
    out = tool.parse("", "")
    assert out["reachable"] is True
    assert out["open_ports"] == [80, 443]  # closed port excluded
    assert out["services"] == ["http"]  # deduped
    assert "nginx 1.22.1" in out["technologies"]
    assert len(out["port_details"]) == 2


def test_nmap_no_host_element_returns_unreachable(tmp_path):
    tool = NmapTool()
    tool._xml_path = tmp_path / "nmap.xml"
    tool._xml_path.write_text('<?xml version="1.0"?><nmaprun></nmaprun>')
    out = tool.parse("", "")
    assert out == {"reachable": False, "open_ports": [], "services": [], "technologies": []}


def test_nmap_missing_xml_file_raises(tmp_path):
    tool = NmapTool()
    tool._xml_path = tmp_path / "does-not-exist-nmap.xml"
    with pytest.raises(RuntimeError):
        tool.parse("", "")


# ── host_discovery ───────────────────────────────────────────────────────────

def test_host_discovery_up(tmp_path):
    tool = HostDiscoveryTool()
    tool._xml_path = tmp_path / "hd.xml"
    tool._xml_path.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/></host></nmaprun>')
    assert tool.parse("", "")["reachable"] is True


def test_host_discovery_down(tmp_path):
    tool = HostDiscoveryTool()
    tool._xml_path = tmp_path / "hd.xml"
    tool._xml_path.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="down"/></host></nmaprun>')
    assert tool.parse("", "")["reachable"] is False


# ── dns_resolve (pure Python, no parse()) ────────────────────────────────────

def test_dns_resolve_success(monkeypatch):
    tool = DNSResolutionTool()
    monkeypatch.setattr("socket.gethostbyname", lambda host: "93.184.216.34")
    result = tool.run("example.com")
    assert result.status == "success"
    assert result.results["resolved_ip"] == "93.184.216.34"


def test_dns_resolve_failure(monkeypatch):
    import socket
    tool = DNSResolutionTool()

    def _raise(host):
        raise socket.gaierror("not found")
    monkeypatch.setattr("socket.gethostbyname", _raise)
    result = tool.run("nonexistent.invalid")
    assert result.status == "error"


# ── httpx ─────────────────────────────────────────────────────────────────

def test_httpx_parses_probes_and_dedupes_tech():
    tool = HttpxTool()
    out = tool.parse(
        '{"url":"https://example.com","status_code":200,"title":"Example",'
        '"webserver":"nginx","tech":["nginx","PHP"]}\n'
        '{"url":"https://example.com/api","status_code":404,"tech":["nginx"]}\n', "")
    assert out["reachable"] is True
    assert len(out["probes"]) == 2
    assert out["technologies"] == ["nginx", "PHP"]


def test_httpx_unreachable_when_no_lines():
    tool = HttpxTool()
    out = tool.parse("", "")
    assert out["reachable"] is False


# ── whatweb ───────────────────────────────────────────────────────────────

def test_whatweb_filters_noisy_generic_plugins():
    tool = WhatWebTool()
    out = tool.parse(
        '{"target":"http://example.com","plugins":'
        '{"HTTPServer":{},"WordPress":{"version":["6.4"]},"Title":{},"PHP":{}}}\n', "")
    assert set(out["technologies"]) == {"WordPress", "PHP"}
    assert "HTTPServer" not in out["technologies"]
    assert "Title" not in out["technologies"]


# ── katana ────────────────────────────────────────────────────────────────

def test_katana_extracts_urls_from_nested_request_endpoint():
    tool = KatanaTool()
    out = tool.parse(
        '{"request":{"endpoint":"https://example.com/a"}}\n'
        '{"endpoint":"https://example.com/b"}\n', "")
    assert out["discovered_urls"] == ["https://example.com/a", "https://example.com/b"]


def test_katana_plaintext_mode():
    tool = KatanaTool()
    out = tool.parse("https://example.com/c\nhttps://example.com/d\n", "")
    assert out["discovered_urls"] == ["https://example.com/c", "https://example.com/d"]


def test_katana_drops_non_url_garbage_and_counts_skipped():
    tool = KatanaTool()
    out = tool.parse("not a url\nhttps://example.com/ok\n", "")
    assert out["discovered_urls"] == ["https://example.com/ok"]
    assert out["skipped_malformed_lines"] == 1


# ── gau / waybackurls ─────────────────────────────────────────────────────

@pytest.mark.parametrize("tool_cls", [GauTool, WaybackURLsTool])
def test_historical_url_tools_filter_and_dedupe(tool_cls):
    tool = tool_cls()
    out = tool.parse(
        "https://example.com/old\nnot-a-url\nhttps://example.com/old\n"
        "http://example.com/legacy\n", "")
    assert out["historical_urls"] == ["https://example.com/old", "http://example.com/legacy"]


# ── ffuf ──────────────────────────────────────────────────────────────────

def test_ffuf_parses_results_and_caps_at_50(tmp_path):
    tool = FFUFTool()
    tool._json_path = tmp_path / "ffuf.json"
    results = [{"url": f"https://example.com/p{i}", "status": 200, "length": 100 + i}
               for i in range(60)]
    tool._json_path.write_text(json.dumps({"results": results}))
    out = tool.parse("", "")
    assert out["count"] == 60
    assert len(out["discovered_paths"]) == 50
    assert "note" in out


def test_ffuf_drops_redirect_everything_false_positive_pattern(tmp_path):
    tool = FFUFTool()
    tool._json_path = tmp_path / "ffuf.json"
    # 25 results all sharing the exact same (status, length) -- classic
    # "every path redirects identically" false-positive pattern.
    results = [{"url": f"https://example.com/p{i}", "status": 200, "length": 500}
               for i in range(25)]
    results.append({"url": "https://example.com/real", "status": 200, "length": 42})
    tool._json_path.write_text(json.dumps({"results": results}))
    out = tool.parse("", "")
    assert out["count"] == 1  # only the genuinely different one survives
    assert "false_positive_filter" in out


def test_ffuf_missing_file_returns_empty(tmp_path):
    tool = FFUFTool()
    tool._json_path = tmp_path / "does-not-exist-ffuf.json"
    assert tool.parse("", "") == {"discovered_paths": [], "count": 0}


def test_ffuf_build_command_uses_a_real_wordlist_path(tmp_path):
    wordlist = tmp_path / "real.txt"
    wordlist.write_text("admin\nlogin\n")
    tool = FFUFTool()
    cmd = tool.build_command("example.com", wordlist=str(wordlist))
    assert str(wordlist) in cmd


def test_ffuf_build_command_raises_a_clear_error_for_a_nonexistent_wordlist():
    # Real bug from a live run: a caller-supplied relative wordlist path
    # that didn't exist reached ffuf itself, which failed with its own
    # cryptic "stat ...: no such file or directory" subprocess error.
    # validate() can't catch this -- it's called with no kwargs, by
    # design, across the whole Tool interface -- so build_command() must
    # raise FileNotFoundError itself; Tool.run() already converts that
    # into a clean ToolResult(status="not_installed", ...).
    tool = FFUFTool()
    with pytest.raises(FileNotFoundError, match="does not exist"):
        tool.build_command("example.com", wordlist="definitely-not-a-real-file.txt")


def test_ffuf_run_turns_missing_wordlist_into_a_clean_toolresult(tmp_path, monkeypatch):
    tool = FFUFTool()
    tool._json_path = tmp_path / "ffuf.json"
    monkeypatch.setattr(tool, "validate", lambda: None)  # pretend the ffuf binary is installed
    result = tool.run("example.com", wordlist="definitely-not-a-real-file.txt")
    assert result.status == "not_installed"
    assert "does not exist" in result.error


def test_ffuf_wordlist_is_capped_to_max_words(tmp_path, monkeypatch):
    """Request cap: a wordlist larger than the cap is trimmed to its first N
    entries so the scan can't hammer the target into an IP block."""
    import os
    from pathlib import Path
    big = tmp_path / "big.txt"
    big.write_text("\n".join(f"word{i}" for i in range(2000)) + "\n")
    tool = FFUFTool()
    monkeypatch.delenv("FFUF_MAX_WORDS", raising=False)
    cmd = tool.build_command("example.com", wordlist=str(big))
    used = cmd[cmd.index("-w") + 1]
    assert used != str(big)
    assert len(used) > 0
    trimmed = Path(used).read_text().splitlines()
    assert len(trimmed) == tool._resolve_max_words({})
    assert trimmed[0] == "word0"
    assert tool._wordlist_note and "capped at" in tool._wordlist_note


def test_ffuf_small_wordlist_is_untouched_by_the_cap(tmp_path):
    small = tmp_path / "small.txt"
    small.write_text("admin\nlogin\nbackup\n")
    tool = FFUFTool()
    cmd = tool.build_command("example.com", wordlist=str(small))
    assert cmd[cmd.index("-w") + 1] == str(small)
    assert tool._wordlist_note is None


def test_ffuf_max_words_kwarg_overrides_and_zero_disables(tmp_path):
    from pathlib import Path
    big = tmp_path / "big.txt"
    big.write_text("\n".join(f"w{i}" for i in range(30)) + "\n")
    tool = FFUFTool()
    cmd = tool.build_command("example.com", wordlist=str(big), max_words=5)
    assert len(Path(cmd[cmd.index("-w") + 1]).read_text().splitlines()) == 5
    tool2 = FFUFTool()
    cmd2 = tool2.build_command("example.com", wordlist=str(big), max_words=0)
    assert cmd2[cmd2.index("-w") + 1] == str(big)  # cap disabled


# ── arjun ─────────────────────────────────────────────────────────────────

def test_arjun_parses_per_url_params(tmp_path):
    tool = ArjunTool()
    tool._json_path = tmp_path / "arjun.json"
    tool._json_path.write_text(json.dumps({
        "https://example.com/search": {"params": ["q", "page"]},
        "https://example.com/api": {"params": ["id", "q"]},  # "q" repeated across URLs
    }))
    out = tool.parse("", "")
    # URL-associated injectable entries plus bare names for LLM context
    assert "https://example.com/search?q=1" in out["discovered_parameters"]
    assert "https://example.com/search?page=1" in out["discovered_parameters"]
    assert "https://example.com/api?id=1" in out["discovered_parameters"]
    assert {"q", "page", "id"} <= set(out["discovered_parameters"])
    # every param name appears exactly once as a bare entry (deduped)
    bare = [p for p in out["discovered_parameters"] if "?" not in p]
    assert set(bare) == {"q", "page", "id"}


def test_arjun_missing_file_returns_empty(tmp_path):
    tool = ArjunTool()
    tool._json_path = tmp_path / "does-not-exist-arjun.json"
    assert tool.parse("", "") == {"discovered_parameters": [], "count": 0}


# ── linkfinder ────────────────────────────────────────────────────────────

def test_linkfinder_keeps_only_path_or_url_like_lines():
    tool = LinkFinderTool()
    out = tool.parse(
        "/api/v1/users\nhttps://example.com/admin\nnot a real endpoint line\n", "")
    assert out["js_endpoints"] == ["/api/v1/users", "https://example.com/admin"]


# ── header_analysis (run(), mocked urlopen) ──────────────────────────────────

class _FakeHTTPResponse:
    def __init__(self, headers, status=200):
        self._headers = headers
        self.status = status

    def getheaders(self):
        return list(self._headers.items())

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeRequestsResponse:
    def __init__(self, headers, status=200):
        self.headers = headers
        self.status_code = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_header_analysis_flags_missing_security_headers(monkeypatch):
    tool = HeaderAnalysisTool()
    resp = _FakeRequestsResponse({"Server": "nginx"})
    monkeypatch.setattr("requests.get", lambda *a, **k: resp)
    result = tool.run("example.com")
    assert result.status == "success"
    assert "strict-transport-security" in result.results["missing_security_headers"]
    assert "server" in result.results["info_disclosure_headers"]


def test_header_analysis_all_headers_present_means_no_findings(monkeypatch):
    tool = HeaderAnalysisTool()
    resp = _FakeRequestsResponse({
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    })
    monkeypatch.setattr("requests.get", lambda *a, **k: resp)
    result = tool.run("example.com")
    assert result.results["missing_security_headers"] == []


def test_header_analysis_unreachable_target_errors(monkeypatch):
    tool = HeaderAnalysisTool()

    def _raise(*a, **k):
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr("requests.get", _raise)
    result = tool.run("unreachable.invalid")
    assert result.status == "error"


# ── wpscan ────────────────────────────────────────────────────────────────

def test_wpscan_skips_when_cms_hint_is_not_wordpress():
    tool = WPScanTool()
    result = tool.run("example.com", cms="Drupal")
    assert result.status == "success"
    assert result.results["cms_assessment_skipped"] is True


def test_wpscan_parses_plugins_themes_users(tmp_path):
    tool = WPScanTool()
    tool._json_path = tmp_path / "wpscan.json"
    tool._json_path.write_text(json.dumps({
        "version": {"number": "6.4.2"},
        "plugins": {"akismet": {}, "jetpack": {}},
        "themes": {"twentytwentyfour": {}},
        "users": {"1": {"username": "admin"}},
        "interesting_findings": [{"to_s": "XML-RPC enabled"}],
    }))
    out = tool.parse("", "")
    assessment = out["cms_assessment"]
    assert assessment["wordpress_version"] == "6.4.2"
    assert set(assessment["plugins_found"]) == {"akismet", "jetpack"}
    assert assessment["users_found"] == ["admin"]
    assert "XML-RPC enabled" in assessment["interesting_findings"]


# ── testssl (JSON string is the "stdout" argument) ───────────────────────────

def test_testssl_parses_protocols_ciphers_vulns():
    tool = TestSSLTool()
    tool._target, tool._port = "example.com", 443
    raw = json.dumps({
        "version": "3.2",
        "scanResult": [
            {"targetHost": "example.com",
             "protocols": [{"id": "TLS1_2", "finding": "offered", "severity": "OK"},
                          {"id": "TLS1", "finding": "offered", "severity": "MEDIUM"}],
             "ciphers": [{"id": "RC4", "finding": "RC4 cipher", "severity": "HIGH", "cve": "CVE-2015-1234"}],
             "vulnerabilities": [{"id": "heartbleed", "finding": "not vulnerable", "severity": "OK"},
                                 {"id": "ROBOT", "finding": "vulnerable", "severity": "HIGH", "cve": "CVE-2017-1000"}],
             "serverDefaults": [], "headerResponse": [], "cipherTests": []},
        ],
    })
    out = tool.parse(raw, "")
    assert out["tls_reachable"] is True
    assert out["protocols"]["TLS1"]["severity"] == "MEDIUM"
    assert any("CIPHER" in f for f in out["tls_findings"])
    assert out["vuln_summary"]["high"] == 1
    assert out["vuln_summary"]["ok"] == 1
    assert "ROBOT" in out["vulnerabilities"]


def test_testssl_scan_problem_marks_unreachable():
    tool = TestSSLTool()
    tool._target, tool._port = "example.com", 443
    raw = json.dumps({"scanResult": [{"id": "scanProblem", "finding": "connection refused"}]})
    out = tool.parse(raw, "")
    assert out["tls_reachable"] is False
    assert any("SCAN PROBLEM" in f for f in out["tls_findings"])


def test_testssl_invalid_json_raises():
    tool = TestSSLTool()
    with pytest.raises(ValueError):
        tool.parse("not json", "")


# ── tls_analysis (openssl s_client output parsing) ───────────────────────────

OPENSSL_HANDSHAKE = """CONNECTED(00000003)
depth=2 C = US, O = Example CA
verify return:1
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256
Protocol  : TLSv1.2
Cipher    : ECDHE-RSA-AES128-GCM-SHA256
---
Verify return code: 0 (ok)
"""


def test_tls_analysis_parses_protocol_cipher_and_verify_code():
    tool = TLSAnalysisTool()
    out = tool.parse(OPENSSL_HANDSHAKE, "")
    assert out["protocol"] == "TLSv1.2"
    assert out["cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert out["verify_return_code"] == {"code": 0, "message": "ok"}
    assert out["tls_findings"] == []


def test_tls_analysis_flags_weak_protocol_and_failed_verify():
    tool = TLSAnalysisTool()
    weak = OPENSSL_HANDSHAKE.replace("TLSv1.2", "TLSv1").replace(
        "Verify return code: 0 (ok)", "Verify return code: 21 (unable to verify)")
    out = tool.parse(weak, "")
    assert any("weak/deprecated protocol" in f for f in out["tls_findings"])
    assert any("verification failed" in f for f in out["tls_findings"])


def test_tls_analysis_cert_fields_expired():
    from datetime import datetime, timedelta, timezone
    past = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    x509_out = f"notBefore=Jan  1 00:00:00 2020 GMT\nnotAfter={past}\n" \
               "subject=CN = example.com\nissuer=CN = Example CA\n"
    fields = TLSAnalysisTool._parse_cert_fields(x509_out)
    assert fields["cert_days_until_expiry"] < 0
    assert "EXPIRED" in fields["tls_findings"][0]


def test_tls_analysis_cert_fields_expiring_soon():
    from datetime import datetime, timedelta, timezone
    soon = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    x509_out = f"notAfter={soon}\n"
    fields = TLSAnalysisTool._parse_cert_fields(x509_out)
    assert "expires soon" in fields["tls_findings"][0]


# ── smb_enum ──────────────────────────────────────────────────────────────

SMB_NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host>
  <ports><port portid="445"><script id="smb-os-discovery" output="OS: Windows Server 2019"/>
  <script id="smb-enum-shares" output="\\\\HOST\\C$&#10;\\\\HOST\\ADMIN$"/></port></ports>
</host></nmaprun>"""


def test_smb_enum_skips_without_smb_ports():
    tool = WindowsServiceEnumerationTool()
    result = tool.run("example.com", ports="80,443")
    assert result.status == "success"
    assert result.results["windows_enum_skipped"] is True


def test_smb_enum_parses_os_discovery_and_shares(tmp_path):
    tool = WindowsServiceEnumerationTool()
    tool._xml_path = tmp_path / "smb.xml"
    tool._xml_path.write_text(SMB_NMAP_XML)
    out = tool.parse("", "")
    assert "Windows Server 2019" in out["windows_enum"]["os_discovery"]
    assert len(out["windows_enum"]["shares"]) == 2


# ── s3_enum (mocked urllib) ───────────────────────────────────────────────

S3_LISTING_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>false</IsTruncated>
  <Contents><Key>file1.txt</Key></Contents>
  <Contents><Key>file2.txt</Key></Contents>
</ListBucketResult>"""


def test_s3_enum_lists_public_bucket(monkeypatch):
    tool = S3EnumTool()

    class _Resp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self, n=None):
            return S3_LISTING_XML.encode()
        status = 200
        headers = {"Content-Type": "text/xml"}

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _Resp())
    result = tool.run("mybucket", buckets=["mybucket"])
    assert result.status == "success"
    asset = result.results["s3_assets"][0]
    assert asset["publicly_listable"] is True
    assert asset["object_count"] == 2
    assert set(asset["sample_keys"]) == {"file1.txt", "file2.txt"}


def test_s3_enum_private_bucket_returns_error(monkeypatch):
    import urllib.error
    tool = S3EnumTool()

    def _raise(*a, **k):
        raise urllib.error.HTTPError("url", 403, "Forbidden", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", _raise)
    result = tool.run("privatebucket", buckets=["privatebucket"])
    assert result.status == "error"


# ── gowitness ─────────────────────────────────────────────────────────────

def test_gowitness_parses_jsonl_and_lists_screenshot_files(tmp_path, monkeypatch):
    tool = GowitnessTool()
    shot_dir = tmp_path / "shots"
    shot_dir.mkdir()
    monkeypatch.setattr(tool, "_shot_dir", shot_dir)
    jsonl_path = tmp_path / "gowitness.jsonl"
    jsonl_path.write_text(json.dumps({
        "final_url": "https://example.com", "response_code": 200, "title": "Example",
    }) + "\n")
    monkeypatch.setattr(tool, "_jsonl_path", jsonl_path)
    (shot_dir / "https---example.com-443.jpeg").write_bytes(b"fake-jpeg-bytes")

    out = tool.parse("", "")
    assert out["screenshot_captured"] is True
    assert len(out["screenshots"]) == 1
    assert out["screenshots"][0]["status_code"] == 200


def test_gowitness_no_screenshots_captured(tmp_path, monkeypatch):
    tool = GowitnessTool()
    shot_dir = tmp_path / "shots_empty"
    shot_dir.mkdir()
    monkeypatch.setattr(tool, "_shot_dir", shot_dir)
    monkeypatch.setattr(tool, "_jsonl_path", tmp_path / "does-not-exist.jsonl")
    out = tool.parse("", "")
    assert out["screenshot_captured"] is False
    assert out["screenshots"] == []


# ── dns_enum (mocked dnspython) ──────────────────────────────────────────────

def test_dns_enum_collects_records_across_types(monkeypatch):
    import dns.resolver

    from tools.dns.dns_enum import DNSEnumTool

    def fake_resolve(target, rtype, lifetime=None):
        if rtype == "A":
            return ["93.184.216.34"]
        if rtype == "MX":
            return ["10 mail.example.com."]
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    tool = DNSEnumTool()
    result = tool.run("example.com")
    assert result.status == "success"
    assert result.results["dns_records"]["A"] == ["93.184.216.34"]
    assert result.results["dns_records"]["TXT"] == []


def test_dns_enum_nxdomain_all_types_returns_error(monkeypatch):
    import dns.resolver

    from tools.dns.dns_enum import DNSEnumTool

    def fake_resolve(target, rtype, lifetime=None):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    tool = DNSEnumTool()
    result = tool.run("nonexistent.invalid")
    assert result.status == "error"
    assert result.results["record_count"] == 0


# ── cloud_enum (mocked requests) ─────────────────────────────────────────────

def test_cloud_enum_skips_without_cloud_technology_evidence():
    from tools.cloud.cloud_enum import CloudAssetDiscoveryTool
    tool = CloudAssetDiscoveryTool()
    result = tool.run("example.com", technologies=["nginx", "PHP"])
    assert result.status == "success"
    assert result.results["cloud_assets_skipped"] is True


def test_cloud_enum_finds_public_bucket(monkeypatch):
    from tools.cloud.cloud_enum import CloudAssetDiscoveryTool
    tool = CloudAssetDiscoveryTool()

    class _Resp:
        def __init__(self, code):
            self.status_code = code

    def fake_head(url, timeout=None, headers=None, allow_redirects=None):
        if "example.s3.amazonaws.com" in url:
            return _Resp(200)
        return _Resp(404)

    monkeypatch.setattr("requests.head", fake_head)
    result = tool.run("example.com", technologies=["AWS S3"])
    assert result.status == "success"
    found = result.results["cloud_assets_found"]
    assert any(f["bucket"] == "example" and f["publicly_listable"] for f in found)


# ── cms_identify (mocked requests) ───────────────────────────────────────────

def test_cms_identify_detects_wordpress_from_homepage_markers(monkeypatch):
    from tools.cms.cms_identify import CMSIdentifyTool
    tool = CMSIdentifyTool()

    class _Resp:
        status_code = 200
        headers = {}
        text = '<html><head><meta name="generator" content="WordPress 6.4"/></head>' \
               '<body>wp-content wp-includes</body></html>'

    class _Session:
        headers = {}
        def update(self, *a, **k):
            pass
        def get(self, url, timeout=None, allow_redirects=None, verify=None):
            return _Resp()

    monkeypatch.setattr("requests.Session", lambda: _Session())
    result = tool.run("example.com")
    assert result.status == "success"
    assert result.results["cms_detected"] == "WordPress"
    assert result.results["cms_version"] == "6.4"


def test_cms_identify_no_match_returns_none(monkeypatch):
    from tools.cms.cms_identify import CMSIdentifyTool
    tool = CMSIdentifyTool()

    class _Resp:
        status_code = 200
        headers = {}
        text = "<html><body>plain static site, nothing special</body></html>"

    class _Session:
        headers = {}
        def update(self, *a, **k):
            pass
        def get(self, url, timeout=None, allow_redirects=None, verify=None):
            return _Resp()

    monkeypatch.setattr("requests.Session", lambda: _Session())
    result = tool.run("example.com")
    assert result.results["cms_detected"] is None


# ── ldap_enum (mocked ldap3) ──────────────────────────────────────────────────

def test_ldap_enum_skips_without_ldap_ports():
    from tools.directory.ldap_enum import DirectoryServiceEnumerationTool
    tool = DirectoryServiceEnumerationTool()
    result = tool.run("example.com", ports="80,443")
    assert result.status == "success"
    assert result.results["directory_enum_skipped"] is True


# ── api_discover (mocked requests) ───────────────────────────────────────────

def test_api_discover_classifies_rest_api_from_swagger_response(monkeypatch):
    from tools.api.api_discover import APIDiscoverTool
    tool = APIDiscoverTool()

    class _Resp:
        def __init__(self, code, text=""):
            self.status_code = code
            self.text = text

    def fake_get(url, timeout=None, headers=None, allow_redirects=None, verify=None):
        if url.endswith("/openapi.json"):
            return _Resp(200, '{"openapi": "3.0.0", "swagger": "..."}')
        return _Resp(404)

    monkeypatch.setattr("requests.get", fake_get)
    result = tool.run("example.com")
    assert result.status == "success"


# ── Recon detection tools (passive) ────────────────────────────────────────

def test_deserialization_detect_finds_java_serial(monkeypatch):
    from tools.recon.deserialization_detect import DeserializationDetectionTool

    class _FakeResp:
        status = 200
        def __init__(self, body): self._body = body
        def read(self, n): return self._body
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def geturl(self): return "http://example.com"

    fake_resp = _FakeResp(b"<pre>java.io.ObjectInputStream rejected</pre>")
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: fake_resp)
    tool = DeserializationDetectionTool()
    result = tool.run("http://example.com", timeout=10)
    assert result.status == "success"
    assert result.results["count"] >= 1
    assert result.results["deserialization_vectors"][0]["type"] == "java_class_reference"


def test_deserialization_detect_clean(monkeypatch):
    from tools.recon.deserialization_detect import DeserializationDetectionTool

    class _FakeResp:
        status = 200
        def __init__(self, body): self._body = body
        def read(self, n): return self._body
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def geturl(self): return "http://example.com"

    fake_resp = _FakeResp(b"<html>Hello</html>")
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: fake_resp)
    tool = DeserializationDetectionTool()
    result = tool.run("http://example.com", timeout=10)
    assert result.status == "success"
    assert result.results["count"] == 0


def test_upload_form_detect_finds_file_input(monkeypatch):
    from tools.recon.upload_form_detect import UploadFormDetectionTool

    html = b'<form action="/upload" enctype="multipart/form-data"><input type="file" name="avatar"></form>'

    class _FakeResp:
        status = 200
        def __init__(self, body): self._body = body
        def read(self, n): return self._body
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def geturl(self): return "http://example.com/upload"

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _FakeResp(html))
    tool = UploadFormDetectionTool()
    result = tool.run("http://example.com", timeout=10, endpoints=["/upload"])
    assert result.status == "success"
    assert result.results["count"] >= 1
    form = result.results["upload_forms"][0]
    assert form["input_name"] == "avatar"
    assert form["has_type_restriction"] is False


def test_csrf_surface_detect_finds_tokenless_form(monkeypatch):
    from tools.recon.csrf_surface_detect import CSRFSurfaceDetectionTool

    html = b'<form action="/transfer" method="POST"><input name="amount"><input type="submit"></form>'

    class _FakeResp:
        status = 200
        def __init__(self, body): self._body = body
        def read(self, n): return self._body
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def geturl(self): return "http://example.com/transfer"

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _FakeResp(html))
    tool = CSRFSurfaceDetectionTool()
    result = tool.run("http://example.com", timeout=10, auth_paths=["/transfer"])
    assert result.status == "success"
    assert result.results["count"] >= 1
    surface = result.results["csrf_surface"][0]
    assert surface["risk"] == "high"
    assert surface["has_csrf_token"] is False


def test_csrf_surface_detect_with_token(monkeypatch):
    from tools.recon.csrf_surface_detect import CSRFSurfaceDetectionTool

    html = b'<form action="/transfer" method="POST"><input type="hidden" name="_token" value="abc123"><input name="amount"></form>'

    class _FakeResp:
        status = 200
        def __init__(self, body): self._body = body
        def read(self, n): return self._body
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def geturl(self): return "http://example.com/transfer"

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _FakeResp(html))
    tool = CSRFSurfaceDetectionTool()
    result = tool.run("http://example.com", timeout=10, auth_paths=["/transfer"])
    assert result.status == "success"
    surface = result.results["csrf_surface"][0]
    assert surface["has_csrf_token"] is True
    assert surface["risk"] == "low"


# ── Cookie Analyzer ────────────────────────────────────────────────────────

def test_cookie_analyzer_detects_insecure(monkeypatch):
    from requests.structures import CaseInsensitiveDict

    from tools.recon.cookie_analyzer import CookieAnalyzerTool

    class _FakeResp:
        headers = CaseInsensitiveDict({"Set-Cookie": "session=abc123; path=/"})
        status_code = 200
    monkeypatch.setattr("requests.get", lambda *a, **k: _FakeResp())
    tool = CookieAnalyzerTool()
    result = tool.run("http://example.com")
    assert result.status == "success"
    assert result.results["insecure_count"] >= 1
    cookie = result.results["cookies"][0]
    assert cookie["name"] == "session"
    assert "missing Secure flag" in cookie["issues"]


def test_cookie_analyzer_secure_cookies(monkeypatch):
    from requests.structures import CaseInsensitiveDict

    from tools.recon.cookie_analyzer import CookieAnalyzerTool

    class _FakeResp:
        headers = CaseInsensitiveDict({"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict; path=/"})
        status_code = 200
    monkeypatch.setattr("requests.get", lambda *a, **k: _FakeResp())
    tool = CookieAnalyzerTool()
    result = tool.run("http://example.com")
    assert result.status == "success"
    assert result.results["insecure_count"] == 0


def test_cookie_analyzer_no_cookies(monkeypatch):
    from requests.structures import CaseInsensitiveDict

    from tools.recon.cookie_analyzer import CookieAnalyzerTool

    class _FakeResp:
        headers = CaseInsensitiveDict({"Content-Type": "text/html"})
        status_code = 200
    monkeypatch.setattr("requests.get", lambda *a, **k: _FakeResp())
    tool = CookieAnalyzerTool()
    result = tool.run("http://example.com")
    assert result.status == "success"
    assert result.results["count"] == 0


# ── GraphQL Introspection ─────────────────────────────────────────────────

def test_graphql_introspection_finds_schema(monkeypatch):
    from tools.recon.graphql_introspection import GraphQLIntrospectionTool

    schema_resp = {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [{"name": "getUser", "type": {"name": "User"}}]},
            {"name": "User", "kind": "OBJECT", "fields": [{"name": "id", "type": {"name": "ID"}}, {"name": "email", "type": {"name": "String"}}]},
            {"name": "UserInput", "kind": "INPUT_OBJECT", "inputFields": [{"name": "password", "type": {"name": "String"}}]},
        ]
    }}}

    class _FakeResp:
        status_code = 200
        def json(self): return schema_resp
    monkeypatch.setattr("requests.post", lambda *a, **k: _FakeResp())
    tool = GraphQLIntrospectionTool()
    result = tool.run("http://example.com", endpoints=["/graphql"])
    assert result.status == "success"
    assert result.results["count"] >= 1
    ep = result.results["endpoints"][0]
    assert ep["type_count"] == 3
    assert any("email" in f["fields"] for f in ep["sensitive_types"])


def test_graphql_introspection_not_found(monkeypatch):
    from tools.recon.graphql_introspection import GraphQLIntrospectionTool

    class _FakeResp:
        status_code = 404
        def json(self): return {"error": "not found"}
    monkeypatch.setattr("requests.post", lambda *a, **k: _FakeResp())
    tool = GraphQLIntrospectionTool()
    result = tool.run("http://example.com", endpoints=["/graphql"])
    assert result.status == "success"
    assert result.results["count"] == 0


# ── Robots.txt Parser ─────────────────────────────────────────────────────

def test_robots_txt_parser_with_content(monkeypatch):
    from tools.recon.robots_txt_parser import RobotsTxtParserTool

    body = """User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /restapi/soa2/
Sitemap: https://example.com/sitemap.xml
# internal API
Disallow: /flights/graphql/
"""
    class _FakeResp:
        status = 200
        def read(self): return body.encode()
        def __enter__(self): return self
        def __exit__(self, *a): pass
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _FakeResp())
    tool = RobotsTxtParserTool()
    result = tool.run("http://example.com")
    assert result.status == "success"
    assert result.results["found"] is True
    assert "/admin/" in result.results["sensitive_paths"]
    assert "/api/" in result.results["internal_apis"]
    assert result.results["sitemaps"] == ["https://example.com/sitemap.xml"]


def test_robots_txt_parser_not_found(monkeypatch):
    import urllib.error

    from tools.recon.robots_txt_parser import RobotsTxtParserTool
    def _raise(*a, **k):
        raise urllib.error.HTTPError(*a, code=404, msg="Not Found", hdrs=None, fp=None)
    monkeypatch.setattr("urllib.request.urlopen", _raise)
    tool = RobotsTxtParserTool()
    result = tool.run("http://example.com")
    assert result.status == "success"
    assert result.results["found"] is False


# ── Cert Info ──────────────────────────────────────────────────────────────

def test_cert_info_returns_cert_data(monkeypatch):
    from tools.recon.cert_info import CertInfoTool

    mock_cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Let's Encrypt"),),),
        "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
        "version": 3,
        "serialNumber": "ABC123",
    }

    mock_socket_cls = MagicMock()
    mock_context = MagicMock()
    mock_ssl_module = MagicMock()
    mock_ssl_module.create_default_context.return_value = mock_context

    mock_wrapped = MagicMock()
    mock_wrapped.getpeercert.return_value = mock_cert
    mock_wrapped.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
    mock_wrapped.version.return_value = "TLSv1.3"
    mock_context.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_wrapped)
    mock_context.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

    monkeypatch.setattr("tools.recon.cert_info.ssl", mock_ssl_module)
    monkeypatch.setattr("tools.recon.cert_info.socket", mock_socket_cls)
    tool = CertInfoTool()
    result = tool.run("example.com")
    assert result.status == "success"
    assert result.results["san_count"] == 2
    assert result.results["days_until_expiry"] > 0
    assert result.results["cipher"] == "ECDHE-RSA-AES256-GCM-SHA384"


# ── Sensitive Endpoint Detect ─────────────────────────────────────────────

def test_sensitive_endpoint_detect_finds_git(monkeypatch):
    import urllib.error

    from tools.recon.sensitive_endpoint_detect import SensitiveEndpointDetectTool

    def fake_urlopen(req, **kwargs):
        url = req.full_url if hasattr(req, 'full_url') else str(req)
        if url.endswith("/.git/config"):
            from unittest.mock import MagicMock
            resp = MagicMock()
            resp.status = 200
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            resp.read = MagicMock(return_value=b"[core]")
            return resp
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    monkeypatch.setattr("tools.recon.sensitive_endpoint_detect.urllib.request.urlopen", fake_urlopen)
    tool = SensitiveEndpointDetectTool()
    result = tool.run("http://example.com")
    assert result.status == "success"
    git_findings = [f for f in result.results["found"] if f["path"] == "/.git/config"]
    assert len(git_findings) == 1
    assert git_findings[0]["status"] == 200
    assert git_findings[0]["severity"] == "CRITICAL"


def test_sensitive_endpoint_detect_nothing_found(monkeypatch):
    import urllib.error

    from tools.recon.sensitive_endpoint_detect import SensitiveEndpointDetectTool

    def fake_urlopen(req, **kwargs):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", None, None)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    tool = SensitiveEndpointDetectTool()
    result = tool.run("http://example.com")
    assert result.status == "success"
    assert result.results["count"] == 0


# ── Session Analysis / Hijacking tests ────────────────────────────────────────

class TestSessionAnalyzer:

    def test_analyze_token_high_risk(self):
        from tools.recon.session_analyzer import SessionAnalyzerTool
        token_result = SessionAnalyzerTool._analyze_token(
            "abc123", "session", [])
        assert token_result["risk"] in ("HIGH", "CRITICAL")
        assert token_result["token_name"] == "session"
        assert any("Secure" in i for i in token_result["issues"])
        assert any("HttpOnly" in i for i in token_result["issues"])

    def test_analyze_token_low_risk(self):
        from tools.recon.session_analyzer import SessionAnalyzerTool
        token_result = SessionAnalyzerTool._analyze_token(
            "aB3$xK9#mN2@pQ5!rT8&vW1", "auth_token",
            ["auth_token=aB3$xK9#mN2@pQ5!rT8&vW1; Secure; HttpOnly; SameSite=Strict"])
        assert token_result["risk"] == "LOW"
        assert token_result["flags"]["secure"] is True
        assert token_result["flags"]["httponly"] is True
        assert token_result["flags"]["samesite"] is True
        assert len(token_result["issues"]) == 0

    def test_analyze_sequential_numeric(self):
        from tools.recon.session_analyzer import SessionAnalyzerTool
        token_result = SessionAnalyzerTool._analyze_token(
            "12345678901234567890", "sid", [])
        assert token_result["token_format"] == "sequential_numeric"
        assert token_result["risk"] in ("HIGH", "CRITICAL")
        assert any("sequential" in i.lower() for i in token_result["issues"])

    def test_analyze_jwt(self):
        from tools.recon.session_analyzer import SessionAnalyzerTool
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abcdef1234567890"
        token_result = SessionAnalyzerTool._analyze_token(jwt, "jwt", [])
        assert token_result["token_format"] == "jwt"
        assert any("JWT" in i for i in token_result["issues"])

    def test_run_returns_sessions(self, monkeypatch):
        from tools.recon.session_analyzer import SessionAnalyzerTool
        import requests
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.headers = {"Set-Cookie": "session=abc123def456ghi; Path=/"}
        cookie_obj = MagicMock()
        cookie_obj.name = "session"
        cookie_obj.value = "abc123def456ghi"
        resp.cookies = [cookie_obj]
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = SessionAnalyzerTool()
        result = tool.run("http://example.com")
        assert result.status == "success"
        assert result.results["count"] >= 1
        assert result.results["sessions"][0]["token_name"] == "session"


class TestSessionFixation:

    def test_fixation_returns_findings(self, monkeypatch):
        from tools.attack.session_fixation import SessionFixationTool
        import requests
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.headers = {}
        resp.cookies = []
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = SessionFixationTool()
        result = tool.run("http://example.com", auth_paths=["/login"])
        assert result.status == "success"
        assert "findings" in result.results

    def test_fixation_rejects_external_id(self, monkeypatch):
        from tools.attack.session_fixation import SessionFixationTool
        import requests
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.headers = {}
        resp.cookies = []
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = SessionFixationTool()
        result = tool.run("http://example.com", auth_paths=["/login"])
        assert result.status == "success"
        critical = [f for f in result.results["findings"]
                    if f.get("risk") == "CRITICAL"]
        assert len(critical) == 0

    def test_fixation_detects_accepted_id(self, monkeypatch):
        from tools.attack.session_fixation import SessionFixationTool
        import requests
        fixed_id = "AAAA1111BBBB2222CCCC3333"
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.headers = {}
        cookie_obj = MagicMock()
        cookie_obj.name = "session"
        cookie_obj.value = fixed_id
        resp.cookies = [cookie_obj]
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = SessionFixationTool()
        result = tool.run("http://example.com", auth_paths=["/login"])
        assert result.status == "success"
        critical = [f for f in result.results["findings"]
                    if f.get("risk") == "CRITICAL"]
        assert len(critical) == 1

    def test_detects_url_session(self, monkeypatch):
        from tools.attack.session_fixation import SessionFixationTool
        import requests
        resp = MagicMock()
        resp.status_code = 302
        resp.text = ""
        resp.headers = {"location": "http://example.com/dashboard?session=abc123"}
        resp.cookies = []
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = SessionFixationTool()
        result = tool.run("http://example.com", auth_paths=["/login"])
        high = [f for f in result.results["findings"]
                if f.get("risk") == "HIGH"]
        assert len(high) >= 1


class TestSessionHijack:

    def test_token_exposure_found(self, monkeypatch):
        from tools.attack.session_hijack import SessionHijackTool
        import requests
        resp = MagicMock()
        resp.status_code = 200
        resp.text = '<html><div class="token">abc123def456ghi</div></html>'
        resp.headers = {}
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = SessionHijackTool()
        result = tool.run("http://example.com", cookies={"session": "abc123def456ghi"})
        assert result.status == "success"
        assert result.results["count"] >= 1
        exposure = [f for f in result.results["findings"]
                    if f.get("type") == "token_exposed_in_body"]
        assert len(exposure) == 1
        assert exposure[0]["severity"] == "HIGH"

    def test_no_findings_clean(self, monkeypatch):
        from tools.attack.session_hijack import SessionHijackTool
        import requests
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html><body>Normal page</body></html>"
        resp.headers = {}
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = SessionHijackTool()
        result = tool.run("http://example.com")
        assert result.status == "success"
        assert result.results["count"] == 0

    def test_ua_spoof_detected(self, monkeypatch):
        from tools.attack.session_hijack import SessionHijackTool
        import requests
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "Dashboard content"
            resp.headers = {}
            return resp
        monkeypatch.setattr(requests, "get", mock_get)
        tool = SessionHijackTool()
        result = tool.run("http://example.com", cookies={"session": "tok123"})
        ua_findings = [f for f in result.results["findings"]
                       if f.get("type") == "session_not_bound_to_ua"]
        assert len(ua_findings) >= 1


# ── SSTI Exploitation tests ────────────────────────────────────────────────

class TestSSTIExploit:

    def test_ssti_no_param_returns_empty(self, monkeypatch):
        from tools.attack.ssti import SSTIExploitTool
        import requests
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Normal page content"
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = SSTIExploitTool()
        result = tool.run("http://example.com")
        assert result.status == "success"
        assert result.results["count"] == 0

    def test_ssti_detects_engine(self, monkeypatch):
        from tools.attack.ssti import SSTIExploitTool
        import requests
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if "7" in url and ("*" in url or "%2A" in url):
                resp.text = "49"
            else:
                resp.text = "Normal page"
            resp.headers = {}
            return resp
        monkeypatch.setattr(requests, "get", mock_get)
        tool = SSTIExploitTool()
        result = tool.run("http://example.com", param="name")
        assert result.status == "success"
        engine_findings = [f for f in result.results["ssti_findings"]
                          if f.get("type") == "engine_fingerprint"]
        assert len(engine_findings) >= 1
        assert result.results["engine"] is not None

    def test_ssti_blind_detection(self, monkeypatch):
        from tools.attack.ssti import SSTIExploitTool
        import requests
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if "%7B7" in url and "%7D" in url:
                # First call is 7*7, second is 7*8 — differentiate by length
                if "7*7" in requests.utils.unquote(url) or "%7B7*7" in url:
                    resp.text = "A" * 100
                else:
                    resp.text = "B" * 110
            else:
                resp.text = "Normal"
            resp.headers = {}
            return resp
        monkeypatch.setattr(requests, "get", mock_get)
        tool = SSTIExploitTool()
        result = tool.run("http://example.com", param="input")
        assert result.status == "success"


# ── LFI Exploitation tests ─────────────────────────────────────────────────

class TestLFIExploit:

    def test_lfi_no_endpoints(self, monkeypatch):
        from tools.attack.lfi import LFIExploitTool
        import requests

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "Normal page"
            resp.headers = {}
            return resp

        # No real network: this test is about the "nothing to test" path,
        # but the tool still sends probes for every payload — unmocked it
        # makes dozens of live example.com requests and can hang the suite.
        monkeypatch.setattr(requests, "get", mock_get)
        monkeypatch.setattr(requests, "post", mock_get)
        tool = LFIExploitTool()
        result = tool.run("http://example.com")
        assert result.status == "success"
        assert result.results["count"] == 0

    def test_lfi_detects_path_traversal(self, monkeypatch):
        from tools.attack.lfi import LFIExploitTool
        import requests
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if "passwd" in url or "etc/passwd" in url:
                resp.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
            else:
                resp.text = "Normal page"
            resp.headers = {}
            return resp
        monkeypatch.setattr(requests, "get", mock_get)
        tool = LFIExploitTool()
        result = tool.run("http://example.com", param="file")
        assert result.status == "success"
        traversal = [f for f in result.results["lfi_findings"]
                    if f.get("type") == "path_traversal"]
        assert len(traversal) >= 1
        assert traversal[0]["severity"] == "CRITICAL"

    def test_lfi_php_filter_detection(self, monkeypatch):
        from tools.attack.lfi import LFIExploitTool
        import requests
        import base64
        passwd_content = "root:x:0:0:root:/root:/bin/bash"
        b64_content = base64.b64encode(passwd_content.encode()).decode()
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if "php://filter" in url:
                resp.text = b64_content
            else:
                resp.text = "Normal"
            resp.headers = {}
            return resp
        monkeypatch.setattr(requests, "get", mock_get)
        tool = LFIExploitTool()
        result = tool.run("http://example.com", param="page")
        assert result.status == "success"


# ── SSRF Exploitation tests ────────────────────────────────────────────────

class TestSSRFExploit:

    def test_ssrf_no_endpoints(self, monkeypatch):
        from tools.attack.ssrf import SSRFExploitTool
        import requests
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Normal page"
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = SSRFExploitTool()
        result = tool.run("http://example.com")
        assert result.status == "success"
        assert "ssrf_findings" in result.results

    def test_ssrf_detects_aws_metadata(self, monkeypatch):
        from tools.attack.ssrf import SSRFExploitTool
        import requests
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if "169.254.169.254" in url:
                resp.text = "ami-12345678\ninstance-id: i-0abc1234def56789\nhostname: ip-10-0-1-100.ec2.internal"
            else:
                resp.text = "Normal"
            resp.headers = {}
            return resp
        monkeypatch.setattr(requests, "get", mock_get)
        tool = SSRFExploitTool()
        result = tool.run("http://example.com", param="url")
        assert result.status == "success"
        aws = [f for f in result.results["ssrf_findings"]
               if f.get("type") == "cloud_metadata" and f.get("provider") == "AWS"]
        assert len(aws) >= 1
        assert aws[0]["severity"] == "CRITICAL"

    def test_ssrf_detects_internal_network(self, monkeypatch):
        from tools.attack.ssrf import SSRFExploitTool
        import requests
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if "10.0.0.1" in url:
                resp.text = "Router admin page"
            else:
                resp.text = "Normal"
            resp.headers = {}
            return resp
        monkeypatch.setattr(requests, "get", mock_get)
        tool = SSRFExploitTool()
        result = tool.run("http://example.com", param="target")
        assert result.status == "success"


# ── JWT Exploit tests ──────────────────────────────────────────────────────

class TestJWTExploit:

    def test_jwt_no_token_returns_empty(self, monkeypatch):
        from tools.attack.jwt_exploit import JWTExploitTool
        import requests
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Normal page"
        resp.headers = {}
        resp.cookies = {}
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = JWTExploitTool()
        result = tool.run("http://example.com")
        assert result.status == "success"
        assert result.results["count"] == 0

    def test_jwt_detects_weak_secret(self, monkeypatch):
        from tools.attack.jwt_exploit import JWTExploitTool
        import requests
        # Create a token with weak secret "secret"
        from tools.attack.jwt_exploit import _format_token, _b64url_encode
        import hmac, hashlib
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
        parts = _format_token(header, payload).split(".")
        sig = hmac.new(b"secret", f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        token = f"{parts[0]}.{parts[1]}.{_b64url_encode(sig)}"
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Normal page"
        resp.headers = {}
        resp.cookies = {}
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = JWTExploitTool()
        result = tool.run("http://example.com", token=token)
        assert result.status == "success"
        weak = [f for f in result.results["jwt_findings"]
                if f.get("type") == "weak_secret"]
        assert len(weak) == 1
        assert weak[0]["secret"] == "secret"

    def test_jwt_detects_alg_none(self, monkeypatch):
        from tools.attack.jwt_exploit import JWTExploitTool
        import requests
        from tools.attack.jwt_exploit import _format_token
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "admin", "role": "admin"}
        token = _format_token(header, payload)
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Normal page"
        resp.headers = {}
        resp.cookies = {}
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = JWTExploitTool()
        result = tool.run("http://example.com", token=token)
        assert result.status == "success"
        alg_findings = [f for f in result.results["jwt_findings"]
                       if f.get("type") == "weak_algorithm"]
        assert len(alg_findings) >= 1

    def test_jwt_token_analysis_sensitive_claims(self, monkeypatch):
        from tools.attack.jwt_exploit import JWTExploitTool
        import requests
        from tools.attack.jwt_exploit import _format_token
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "123", "password": "hunter2", "api_key": "abc123"}
        token = _format_token(header, payload, "fake_sig")
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Normal"
        resp.headers = {}
        resp.cookies = {}
        monkeypatch.setattr(requests, "get", MagicMock(return_value=resp))
        tool = JWTExploitTool()
        result = tool.run("http://example.com", token=token)
        assert result.status == "success"
        sensitive = [f for f in result.results["jwt_findings"]
                    if f.get("type") == "sensitive_claims"]
        assert len(sensitive) >= 1


# ── Enhanced File Upload tests ──────────────────────────────────────────────

class TestFileUploadEnhanced:

    def test_file_upload_no_endpoints(self):
        from tools.attack.file_upload import FileUploadScanTool
        tool = FileUploadScanTool()
        result = tool.run("http://example.com")
        assert result.status == "success"
        assert result.results["count"] == 0

    def test_file_upload_webshell_content(self, monkeypatch):
        from tools.attack.file_upload import FileUploadScanTool
        import subprocess
        def mock_run(cmd, **kwargs):
            resp = MagicMock()
            if "-w" in cmd and "file" in str(cmd):
                resp.stdout = "200"
                resp.returncode = 0
            else:
                resp.stdout = "404"
                resp.returncode = 1
            resp.stderr = ""
            return resp
        monkeypatch.setattr(subprocess, "run", mock_run)
        tool = FileUploadScanTool()
        result = tool.run("http://example.com", upload_urls=["http://example.com/upload"])
        assert result.status == "success"


# ── Enhanced Deserialization tests ──────────────────────────────────────────

class TestDeserializationEnhanced:

    def test_deser_no_endpoints(self):
        from tools.attack.deserialization import DeserializationScanTool
        tool = DeserializationScanTool()
        result = tool.run("http://example.com")
        assert result.status == "success"
        assert result.results["count"] == 0

    def test_deser_auto_detect_languages(self):
        from tools.attack.deserialization import DeserializationScanTool
        tool = DeserializationScanTool()
        langs = tool._detect_languages(["http://example.com/servlet/LoginAction",
                                        "http://example.com/api/unserialize"])
        assert "java" in langs or "php" in langs

    def test_deser_payload_sets_populated(self):
        from tools.attack.deserialization import PAYLOAD_SETS
        assert "java" in PAYLOAD_SETS
        assert "php" in PAYLOAD_SETS
        assert "python" in PAYLOAD_SETS
        assert "dotnet" in PAYLOAD_SETS
        assert len(PAYLOAD_SETS["java"]) >= 2


# ── tools/base.py: build_command() FileNotFoundError convention ────────────
# Generic coverage for the shared Tool.run() mechanism ffuf.py relies on,
# using a minimal synthetic Tool so this is verified independent of any one
# tool wrapper's specific behavior.

class _MissingInputFileTool:
    """Minimal stand-in exercising only what Tool.run() actually touches,
    to keep this test decoupled from any real tool's other behavior."""
    from tools.base import Tool as _Base

    class _Impl(_Base):
        name = "fake_tool"
        capability = "TEST_CAPABILITY"
        binary = "true"  # a real, always-present binary so validate() passes

        def build_command(self, target, **kwargs):
            raise FileNotFoundError(f"required input file '{kwargs.get('input_file')}' does not exist")

        def parse(self, stdout, stderr):
            return {}


def test_build_command_filenotfounderror_becomes_a_clean_toolresult():
    tool = _MissingInputFileTool._Impl()
    result = tool.run("example.com", input_file="missing.txt")
    assert result.status == "not_installed"
    assert "missing.txt" in result.error
    assert "does not exist" in result.error
