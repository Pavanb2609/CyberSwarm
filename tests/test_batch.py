"""Batch (multi-target) coverage: targets-file parsing, authorization gating,
per-target isolation (tool-memory files, traces), and summary roll-up."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import batch
import authorization as auth


class _Args:
    def __init__(self, targets_file="", dry_run=True, no_high_risk=False,
                 max_actions=100, max_time=1800.0, auto_approve=False,
                 force=False, creds_file=None, cookies_file=None, identity=None):
        self.targets_file = targets_file
        self.dry_run = dry_run
        self.no_high_risk = no_high_risk
        self.max_actions = max_actions
        self.max_time = max_time
        self.auto_approve = auto_approve
        self.force = force
        self.creds_file = creds_file
        self.cookies_file = cookies_file
        self.identity = identity


def _targets_file(tmp_path, lines):
    p = tmp_path / "targets.txt"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def _summary(max_actions_run=5, found=1, stop="time budget exhausted"):
    def make(target):
        return {
            "target": target,
            "actions_run": max_actions_run,
            "elapsed_s": 1.0,
            "stop_reason": stop,
            "asset_total": 2,
            "assets": {"dns": 2},
            "evidence_count": 3,
            "findings": found,
            "coverage_pct": 33,
            "dry_run": True,
            "trace": f"traces/{target}.json",
        }
    return make


def test_read_targets_file_comments_and_blanks(tmp_path):
    p = _targets_file(tmp_path, ["example.com", "# comment", "", "  host.a  ",
                                 "example.org # trailing"])
    assert batch.read_targets_file(p) == ["example.com", "host.a", "example.org"]


def test_normalize_drops_scheme_path_port():
    assert batch._normalize("https://sub.example.com:8443/path") == "sub.example.com"
    assert batch._normalize("example.com") == "example.com"


def test_run_assess_batch_runs_one_per_target(tmp_path, monkeypatch):
    scratch = tmp_path / "scope.json"
    scratch.write_text(json.dumps({"targets": ["other.test"]}), encoding="utf-8")
    monkeypatch.setattr(auth, "CONFIG_PATH", scratch)
    run = []
    monkeypatch.setattr(batch, "run_one",
                        lambda t, args: (_summary()(t), run.append(t))[0])
    tf = _targets_file(tmp_path, ["example.com", "example.org"])
    rc = batch.run_assess_batch(_Args(targets_file=tf, auto_approve=True))
    assert rc == 0
    assert run == ["example.com", "example.org"]
    assert json.loads(scratch.read_text(encoding="utf-8"))["targets"] == \
        ["other.test", "example.com", "example.org"]


def test_run_assess_batch_authorizes_with_auto_approve(tmp_path, monkeypatch):
    scratch = tmp_path / "scope.json"
    scratch.write_text(json.dumps({"targets": ["other.test"]}), encoding="utf-8")
    monkeypatch.setattr(auth, "CONFIG_PATH", scratch)
    assert "bootstrap.test" not in auth.scope()

    calls = []
    monkeypatch.setattr(batch, "run_one",
                        lambda t, args: (_summary()(t), calls.append(t))[0])
    tf = _targets_file(tmp_path, ["bootstrap.test"])
    rc = batch.run_assess_batch(_Args(targets_file=tf, auto_approve=True))
    assert rc == 0
    assert calls == ["bootstrap.test"]
    assert "bootstrap.test" in auth.scope()
    js = list(batch.REPORT_DIR.glob("_batch.*.json"))
    assert js, "expected a batch summary file"
    data = json.loads(sorted(js)[-1].read_text(encoding="utf-8"))
    assert data["rows"][0]["target"] == "bootstrap.test"


def test_run_assess_batch_skips_unauthorized(tmp_path, monkeypatch):
    scratch = tmp_path / "scope.json"
    scratch.write_text(json.dumps({"targets": ["other.test"]}), encoding="utf-8")
    monkeypatch.setattr(auth, "CONFIG_PATH", scratch)

    def boom(t, args):
        raise AssertionError("should never run an unauthorized target")

    monkeypatch.setattr(batch, "run_one", boom)
    before = set(batch.REPORT_DIR.glob("_batch.*.json"))
    tf = _targets_file(tmp_path, ["no.mans.land"])
    rc = batch.run_assess_batch(_Args(targets_file=tf))
    assert rc == 1
    assert set(batch.REPORT_DIR.glob("_batch.*.json")) == before


def test_batch_summary_writes_markdown_and_json():
    rows = [{
        "target": "a.test", "actions_run": 3, "elapsed_s": 1.0,
        "stop_reason": "time budget exhausted", "asset_total": 2,
        "assets": {"dns": 2}, "evidence_count": 1, "findings": 0,
        "coverage_pct": 50, "dry_run": True, "trace": "traces/a.test.json",
    }]
    rc = batch._write_summary(rows, 1000.0)
    assert rc == 0
    mds = sorted(batch.REPORT_DIR.glob("_batch.*.md"))
    js = sorted(batch.REPORT_DIR.glob("_batch.*.json"))
    assert mds and js
    md_text = mds[-1].read_text(encoding="utf-8")
    data = json.loads(js[-1].read_text(encoding="utf-8"))
    assert "| a.test |" in md_text
    assert data["rows"][0]["target"] == "a.test"
    assert data["totals"]["asset_total"] == 2
    assert data["totals"]["findings"] == 0


def test_run_one_builds_per_target_tool_memory(tmp_path, monkeypatch):
    """run_one must isolate tool-memory + traces per target, never the shared file."""
    seen = {}

    class FakeToolManager:
        def __init__(self, memory_path=None):
            seen["memory_path"] = str(memory_path)
            self.memory_path = memory_path

    class FakeMemoryStore:
        def __init__(self, target, tool_manager=None):
            seen["mem_target"] = target

    class FakeCtrl:
        def __init__(self, target, *a, **kw):
            self.target = target

        def assess(self):
            return {
                "target": self.target,
                "actions_run": 5,
                "elapsed_s": 1.0,
                "stop_reason": "time budget exhausted",
                "coverage": {"dns_recon": 1, "web_discovery": 1},
                "snapshot": {"assets_by_type": {"dns": [1], "url": [1, 2]},
                             "evidence_count": 3, "findings": 1},
                "decisions": [],
                "dry_run": True,
            }

    class FakeTrace:
        @staticmethod
        def from_decisions(target, decisions):
            return FakeTrace()

        def export_trace(self, path):
            seen["trace"] = path

    monkeypatch.setattr(batch, "ToolManager", FakeToolManager)
    monkeypatch.setattr(batch, "MemoryStore", FakeMemoryStore)
    monkeypatch.setattr(batch, "DecisionTrace", FakeTrace)
    monkeypatch.setattr(batch, "Controller", FakeCtrl)

    row = batch.run_one("https://deep.example.com/x", _Args())
    assert seen["mem_target"] == "deep.example.com"
    assert "tool_memory.deep_example" in seen["memory_path"]
    assert "deep.example.com" in seen["trace"]
    assert row["target"] == "deep.example.com"
    assert row["asset_total"] == 3
    assert 0 <= row["coverage_pct"] <= 100