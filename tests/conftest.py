"""Shared fixtures for the CyberSwarm test suite.

Centralizes what used to be duplicated across test files: a fake LLM
client, a fixture that isolates every module's on-disk store to a tmp
directory (so tests never read/write the real results/ folder), and a
small library of realistic canned tool output for golden parser tests.
"""

import filecmp
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session", autouse=True)
def _protect_real_results_dir(tmp_path_factory):
    """Safety net: whatever a test writes into the real results/ folder is
    reverted when the session ends.

    `isolated_stores` redirects the main stores, but several modules
    (batch reports, tool_memory.json, evidence exports, RAG index) write to
    paths fixed at import time, and the suite used to leave files behind --
    overwriting real engagement data in the process. This snapshots results/
    before the run and, afterwards, restores changed files and removes files
    created during the session. Set CYBERSWARM_TESTS_KEEP_RESULTS=1 to skip.
    """
    results = ROOT / "results"
    if os.environ.get("CYBERSWARM_TESTS_KEEP_RESULTS") == "1":
        yield
        return
    backup = tmp_path_factory.mktemp("results_snapshot") / "results"
    existed = results.exists()
    if existed:
        shutil.copytree(results, backup)
    started = time.time()
    yield
    if not results.exists():
        if existed:
            shutil.copytree(backup, results)
        return
    for path in sorted(results.rglob("*"), reverse=True):
        rel = path.relative_to(results)
        orig = backup / rel
        if path.is_dir():
            if not orig.exists() and not any(path.iterdir()):
                path.rmdir()
            continue
        if not orig.exists():
            if path.stat().st_mtime >= started - 1:
                path.unlink()
        elif not filecmp.cmp(path, orig, shallow=False):
            shutil.copy2(orig, path)
    if existed:  # files a test deleted
        for orig in backup.rglob("*"):
            target = results / orig.relative_to(backup)
            if orig.is_file() and not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(orig, target)

import system_map as sm
import evidence_store
import attack_evidence_store
import approval_gate
import run_recon_loop as rrl
import run_agent_loop as ral
import agents.memory_agent as mem_mod
import agents.intelligence_agent as intel_mod


class FakeModelClient:
    """Returns a scripted sequence of responses, or the same response every
    call if given a single string. Set .should_fail = True to make chat()
    raise, simulating a model backend that's down."""

    def __init__(self, responses=None):
        if responses is None:
            self._responses = None
            self._fixed = ""
        elif isinstance(responses, str):
            self._responses = None
            self._fixed = responses
        else:
            self._responses = list(responses)
            self._fixed = None
        self.should_fail = False
        self.calls = 0

    def chat(self, system_prompt: str, user_prompt: str, temperature=None) -> str:
        self.calls += 1
        if self.should_fail:
            raise RuntimeError("simulated model backend failure")
        if self._responses is not None:
            return self._responses.pop(0) if self._responses else ""
        return self._fixed


@pytest.fixture
def fake_model_client():
    return FakeModelClient


@pytest.fixture
def isolated_stores(tmp_path, monkeypatch):
    """Redirect every on-disk store (SystemMap, recon evidence, attack
    evidence/memory, decision logs, intelligence cache) to tmp_path so
    tests never touch the real results/ directory and never see stale
    state left over from a previous test."""
    monkeypatch.setattr(sm, "STORE_DIR", tmp_path / "system_map")
    monkeypatch.setattr(evidence_store, "STORE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(evidence_store, "DECISION_LOG_PATH", tmp_path / "decision_log.jsonl")
    monkeypatch.setattr(attack_evidence_store, "STORE_DIR", tmp_path / "attack_evidence")
    monkeypatch.setattr(mem_mod, "STORE_DIR", tmp_path / "attack_evidence")
    monkeypatch.setattr(intel_mod, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(approval_gate, "LOG_PATH", tmp_path / "decision_log.jsonl")
    monkeypatch.setattr(rrl, "DECISION_LOG_PATH", tmp_path / "decision_log.jsonl")
    monkeypatch.setattr(ral, "LOG_PATH", tmp_path / "attack_decision_log.jsonl")
    return tmp_path


# ── Realistic canned tool output, for golden parser tests ──────────────────
# Kept intentionally close to real captured output shapes (field names,
# nesting, JSONL-vs-array quirks) rather than simplified fixtures, since
# the whole point is to catch a wrapper drifting from what the real binary
# actually emits.
sample_tool_output = {
    "naabu_jsonl": '{"host":"example.com","ip":"1.2.3.4","port":80}\n'
                   '{"host":"example.com","ip":"1.2.3.4","port":443}\n',
    "subfinder_jsonl": '{"host":"api.example.com","input":"example.com"}\n'
                       '{"host":"www.example.com","input":"example.com"}\n',
    "subfinder_plain": "api.example.com\nwww.example.com\n",
    "amass_jsonl": '{"name":"api.example.com","domain":"example.com"}\n'
                   '{"name":"www.example.com","domain":"example.com"}\n',
    "httpx_jsonl": '{"url":"https://example.com","status_code":200,'
                   '"title":"Example","webserver":"nginx","tech":["nginx","PHP"]}\n',
    "whatweb_jsonl": '{"target":"http://example.com","plugins":'
                     '{"HTTPServer":{},"WordPress":{"version":["6.4"]},"PHP":{}}}\n',
    "katana_jsonl": '{"endpoint":"https://example.com/","request":{}}\n'
                    '{"endpoint":"https://example.com/about","request":{}}\n',
    "gau_urls": "https://example.com/old-page\nhttps://example.com/archive?id=1\nnot-a-url\n",
    "nuclei_jsonl": (
        '{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel",'
        '"severity":"medium","description":"Admin panel is exposed",'
        '"tags":["panel","exposure"],"reference":["https://example.org"],'
        '"classification":{"cve-id":["CVE-2021-1234"],"cwe-id":["CWE-200"],"cvss-score":5.3}},'
        '"matched-at":"https://example.com/admin","type":"http"}\n'
    ),
    "wafw00f_json": '[{"url": "https://example.com", "detected": true, '
                    '"firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}]',
    "nikto_json": '{"vulnerabilities": [{"id": "OSVDB-3092", "OSVDB": "3092", '
                  '"method": "GET", "url": "/admin/", "msg": "Admin dir found"}]}',
}


@pytest.fixture
def sample_output():
    return dict(sample_tool_output)
