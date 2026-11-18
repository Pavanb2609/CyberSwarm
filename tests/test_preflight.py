"""Preflight sweep tests: deterministic, no subprocess calls."""

import pytest


def _make_report(monkeypatch, present: set[str]):
    import tools.preflight as mod

    def fake_which(binary):
        # absolute-path binaries resolve only if the path exists; fake it by
        # matching on the last path component
        if binary.replace("/", "").lstrip(".py") in present or binary.split("/")[-1] in present:
            return f"/usr/local/bin/{binary.split('/')[-1]}"
        return None

    monkeypatch.setattr(mod.shutil, "which", fake_which)
    return mod.run_preflight()


def test_preflight_reports_missing_binary_owners(monkeypatch):
    """All tools sharing one binary roll up under the same missing entry."""
    report = _make_report(monkeypatch, {"curl"})  # nothing else present
    assert "nuclei" in report.missing
    assert report.missing["nuclei"]  # non-empty owner list
    assert "nmap" in report.missing
    for owner in report.missing["nmap"]:
        assert owner.startswith("nmap") or owner == "smb_enum"


def test_preflight_resolves_present_binaries(monkeypatch):
    report = _make_report(monkeypatch, {"curl", "nuclei", "nmap"})
    assert "curl" in report.resolved
    assert "nuclei" in report.resolved
    assert report.resolved["curl"].endswith("curl")


def test_preflight_all_ok_only_when_nothing_missing(monkeypatch):
    report = _make_report(monkeypatch, {
        "curl", "nuclei", "nmap", "subfinder", "amass", "httpx", "whatweb",
        "ffuf", "feroxbuster", "katana", "arjun", "gau", "wafw00f", "sqlmap",
        "nikto", "searchsploit", "commix", "dalfox", "corsy", "subjack",
        "jwt_tool", "wpscan", "gowitness", "naabu", "hydra", "sslyze",
        "testssl", "openssl", "linkfinder", "waybackurls", "GetNPUsers.py",
        "GetUserSPNs.py",
    })
    assert report.all_ok
    assert not report.pinned_warnings


def test_preflight_missing_binary_recorded_twice_is_one_entry(monkeypatch):
    report = _make_report(monkeypatch, set())
    assert "nuclei" in report.missing
    # the many nuclei_* wrappers must inflate owners, not add duplicate keys
    assert len([k for k in report.missing if k == "nuclei"]) == 1


def test_preflight_text_renders(monkeypatch):
    report = _make_report(monkeypatch, set())
    text = report.as_text()
    assert "MISSING binaries" in text
    assert "nuclei" in text


def test_preflight_pure_python_wrappers_listed(monkeypatch):
    report = _make_report(monkeypatch, set())
    assert "payload_gen" in report.pure_python or "api_discover" in report.pure_python