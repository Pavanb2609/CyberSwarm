"""Regression tests for OS detection tooling.

Two concerns are locked in:

1. OS detection must NEVER broker an interactive sudo password prompt
   mid-scan (the old `script(1)`-wrapped `sudo` pty hack hung until timeout
   and leaked raw terminal control sequences).

2. Without passwordless sudo, OS identification must still degrade
   gracefully to a non-privileged TTL heuristic instead of hard-failing the
   whole OPERATING_SYSTEM_IDENTIFICATION capability. Previously it returned
   a validation problem (capability skipped forever); now validate() passes
   and build_command/parse use an unprivileged `nmap -sP` TTL heuristic.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.portscan.os_identify import OSIdentificationTool


def test_os_detect_degrades_to_ttl_heuristic_without_passwordless_sudo(monkeypatch):
    # No passwordless sudo -> validate() must NOT return a hard problem.
    # Instead the tool stays available and falls back to unprivileged TTL.
    tool = OSIdentificationTool()
    monkeypatch.setattr(tool, "is_available", lambda: True)
    monkeypatch.setattr(tool, "_can_sudo_nopass", lambda: False)

    assert tool.validate() is None  # no longer blocks the capability

    result = tool.run("example.com")
    assert result.status == "success"  # heuristic still produces a result
    assert "os_guesses" in result.results


def test_os_detect_never_uses_script_wrapper_when_no_sudo(monkeypatch):
    # Without sudo, build_command is an unprivileged nmap -sP (TTL probe),
    # never a sudo invocation and never script(1).
    tool = OSIdentificationTool()
    monkeypatch.setattr(tool, "_can_sudo_nopass", lambda: False)
    cmd = tool.build_command("example.com")
    assert cmd[0] == "nmap"
    assert "-sP" in cmd
    assert "sudo" not in cmd
    assert "script" not in cmd


def test_os_detect_ttl_heuristic_guesses_os_family():
    tool = OSIdentificationTool()
    assert "Linux" in tool._ttl_guess(64)
    assert "Windows" in tool._ttl_guess(128)
    assert "Cisco" in tool._ttl_guess(255)
    assert "Unknown" in tool._ttl_guess(None)


def test_os_detect_ttl_parse_extracts_ttl_from_stdout():
    tool = OSIdentificationTool()
    tool._skipped_no_sudo = True
    out = tool.parse("Host is up (0.05s latency).\nNmap scan report for 1.2.3.4\n  ICMP: ttl=64", "")
    assert out["mode"] == "ttl_heuristic"
    assert "os_guesses" in out


def test_os_detect_runs_when_passwordless_sudo_available(monkeypatch):
    # With sudo, build_command stays a direct sudo -n -O invocation (no pty).
    tool = OSIdentificationTool()
    monkeypatch.setattr(tool, "is_available", lambda: True)
    monkeypatch.setattr(tool, "_can_sudo_nopass", lambda: True)
    assert tool.validate() is None
    cmd = tool.build_command("example.com")
    assert cmd[0] == "sudo"
    assert "-n" in cmd
    assert "-O" in cmd
    assert "script" not in cmd
