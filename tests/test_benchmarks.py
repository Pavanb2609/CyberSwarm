"""Tests for the XBOW detection benchmark harness.

No Docker and no model here: the Docker lifecycle is injected, and everything
that decides a number — classification, scoring, aggregation — is pure and
tested directly. Those are the parts a reviewer will challenge.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks import scoring, taxonomy, xbow_bench  # noqa: E402


# ── Classification ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expected", [
    ("Reflected Cross-Site Scripting", "xss"),
    ("SQL Injection in id parameter", "sqli"),
    ("Server-Side Template Injection", "ssti"),
    ("XML External Entity processing", "xxe"),
    ("Local File Inclusion", "lfi"),
    ("Directory traversal in path", "path_traversal"),
    ("Default credentials accepted", "default_credentials"),
    ("Insecure deserialization of user input", "insecure_deserialization"),
    ("SSRF via url parameter", "ssrf"),
])
def test_finding_names_map_to_classes(name, expected):
    assert expected in taxonomy.classify_finding(name=name)


def test_class_specific_tool_implies_its_class():
    """A specialist tool firing is evidence even when the wording is odd."""
    assert "sqli" in taxonomy.classify_finding(name="Anomaly in parameter",
                                               tool="sqlmap")
    assert "ssti" in taxonomy.classify_finding(name="Odd response",
                                               tool="ssti_exploit")


def test_generic_scanners_do_not_imply_a_class():
    """nuclei detects everything, so nuclei alone must imply nothing."""
    classes = taxonomy.classify_finding(name="Some issue", tool="nuclei")
    assert classes == set()


def test_unrelated_finding_maps_to_nothing():
    assert taxonomy.classify_finding(name="Robots.txt present") == set()


def test_classification_is_case_insensitive():
    assert "xss" in taxonomy.classify_finding(name="REFLECTED XSS")


# ── Scope honesty ────────────────────────────────────────────────────────────

def test_unreachable_classes_are_marked_out_of_scope():
    """Claiming these as failures would overstate the gap; claiming them as
    successes would be a lie. They are excluded and reported separately."""
    for tag in ("privilege_escalation", "business_logic", "race_condition",
                "nosqli"):
        assert taxonomy.in_scope(tag) is False
        assert taxonomy.out_of_scope_reason(tag)


def test_detectable_classes_are_in_scope():
    for tag in ("xss", "sqli", "ssti", "idor", "default_credentials"):
        assert taxonomy.in_scope(tag) is True


def test_unknown_tag_is_out_of_scope():
    assert taxonomy.in_scope("quantum_injection") is False


def test_coverage_report_computes_a_ceiling():
    report = taxonomy.coverage_report({"xss": 10, "privilege_escalation": 10})
    assert report["in_scope"] == 10
    assert report["out_of_scope"] == 10
    assert report["ceiling"] == 0.5
    assert "privilege_escalation" in report["reasons"]


# ── Scoring one benchmark ────────────────────────────────────────────────────

def _finding(name, verdict="CONFIRM", tool=""):
    return {"name": name, "description": "", "tool": tool, "verdict": verdict}


def test_hit_is_scored():
    result = scoring.score_benchmark("XBEN-001", ["xss"],
                                     [_finding("Reflected XSS")])
    assert result.hits == {"xss"}
    assert result.misses == set()
    assert result.solved is True


def test_miss_is_scored():
    result = scoring.score_benchmark("XBEN-002", ["ssti"], [])
    assert result.misses == {"ssti"}
    assert result.solved is False


def test_false_positive_is_counted():
    result = scoring.score_benchmark("XBEN-003", ["xss"],
                                     [_finding("Reflected XSS"),
                                      _finding("SQL Injection found")])
    assert result.hits == {"xss"}
    assert "sqli" in result.false_positives


def test_out_of_scope_truth_is_not_a_false_positive():
    """A privesc-tagged benchmark reporting something adjacent is not a clean FP."""
    result = scoring.score_benchmark(
        "XBEN-004", ["xss", "privilege_escalation"],
        [_finding("Reflected XSS"), _finding("Privilege escalation possible")])
    assert result.skipped == {"privilege_escalation"}
    assert result.false_positives == set()
    assert result.solved is True, "solved judged on in-scope classes only"


def test_benchmark_with_no_in_scope_class_has_no_expectations():
    result = scoring.score_benchmark("XBEN-005", ["business_logic"], [])
    assert result.expected == set()
    assert result.solved is False


def test_confirmed_findings_counted_separately():
    result = scoring.score_benchmark(
        "XBEN-006", ["xss"],
        [_finding("XSS", verdict="CONFIRM"), _finding("XSS", verdict="DISPUTE")])
    assert result.findings == 2
    assert result.confirmed_findings == 1


def test_result_serialises():
    payload = scoring.score_benchmark("X", ["xss"], [_finding("XSS")]).to_dict()
    assert payload["solved"] is True
    assert payload["hits"] == ["xss"]


# ── Aggregation ──────────────────────────────────────────────────────────────

def _suite():
    return [
        scoring.score_benchmark("a", ["xss"], [_finding("Reflected XSS")]),
        scoring.score_benchmark("b", ["ssti"], []),
        scoring.score_benchmark("c", ["sqli"], [_finding("SQL Injection"),
                                                _finding("XXE entity")]),
        scoring.score_benchmark("d", ["business_logic"], []),
        scoring.score_benchmark("e", ["xss"], [], error="build failed"),
    ]


def test_aggregate_splits_scored_excluded_and_errored():
    agg = scoring.aggregate(_suite())
    assert agg.benchmarks == 5
    assert agg.scored == 3
    assert agg.excluded == 1      # business_logic only
    assert agg.errored == 1


def test_recall_and_precision_both_reported():
    """A system reporting everything scores perfect recall and is useless, so
    precision must never be omitted."""
    agg = scoring.aggregate(_suite())
    assert agg.true_positives == 2
    assert agg.false_negatives == 1
    assert agg.false_positives == 1      # the stray XXE
    assert agg.recall == pytest.approx(2 / 3, abs=0.01)
    assert agg.precision == pytest.approx(2 / 3, abs=0.01)
    assert 0 < agg.f1 <= 1


def test_shotgun_detector_is_punished_on_precision():
    everything = [_finding(n) for n in
                  ("XSS", "SQL Injection", "SSTI", "XXE", "LFI", "SSRF")]
    agg = scoring.aggregate(
        [scoring.score_benchmark("a", ["xss"], everything)])
    assert agg.recall == 1.0
    assert agg.precision < 0.3, "reporting everything must not look like success"


def test_per_class_breakdown():
    agg = scoring.aggregate(_suite())
    assert agg.per_class["xss"] == {"present": 1, "detected": 1}
    assert agg.per_class["ssti"] == {"present": 1, "detected": 0}


def test_empty_suite_does_not_divide_by_zero():
    agg = scoring.aggregate([])
    assert agg.recall == 0.0 and agg.precision == 0.0 and agg.f1 == 0.0
    assert agg.solve_rate == 0.0 and agg.fp_per_benchmark == 0.0


def test_report_states_the_scoring_basis():
    """Anyone reading the output must see it is not XBOW's own metric."""
    results = _suite()
    report = scoring.format_report(results, scoring.aggregate(results))
    assert "detection" in report.lower()
    assert "not flag capture" in report.lower()
    assert "Precision" in report


def test_compare_renders_variants():
    table = scoring.compare({"baseline": scoring.aggregate(_suite()),
                             "no-difficulty": scoring.aggregate(_suite()[:2])})
    assert "baseline" in table and "no-difficulty" in table


# ── Harness plumbing ─────────────────────────────────────────────────────────

def test_load_benchmarks_reads_metadata(tmp_path):
    bench = tmp_path / "benchmarks" / "XBEN-001-24"
    bench.mkdir(parents=True)
    (bench / "benchmark.json").write_text(json.dumps(
        {"name": "IDOR thing", "level": "2", "tags": ["idor", "XSS"]}),
        encoding="utf-8")
    loaded = xbow_bench.load_benchmarks(tmp_path)
    assert len(loaded) == 1
    assert loaded[0]["id"] == "XBEN-001-24"
    assert loaded[0]["tags"] == ["idor", "xss"], "tags normalise to lowercase"


def test_load_benchmarks_skips_malformed(tmp_path):
    bench = tmp_path / "benchmarks" / "BAD"
    bench.mkdir(parents=True)
    (bench / "benchmark.json").write_text("{ not json", encoding="utf-8")
    assert xbow_bench.load_benchmarks(tmp_path) == []


def test_missing_repo_yields_nothing(tmp_path):
    assert xbow_bench.load_benchmarks(tmp_path / "absent") == []


def test_variant_env_toggles_features():
    assert xbow_bench.variant_env("baseline") == {}
    assert xbow_bench.variant_env("no-difficulty")["CYBERSWARM_DIFFICULTY_ENABLED"] == "0"
    assert xbow_bench.variant_env("no-rag")["CYBERSWARM_RAG_ENABLED"] == "0"
    assert len(xbow_bench.variant_env("minimal")) == 2


def test_unknown_variant_is_inert():
    assert xbow_bench.variant_env("nonsense") == {}


def test_read_findings_handles_a_missing_file(tmp_path):
    assert xbow_bench.read_findings(tmp_path, "nothing") == []


def test_read_findings_parses_attack_evidence(tmp_path):
    path = tmp_path / "results" / "attack_evidence"
    path.mkdir(parents=True)
    (path / "localhost.json").write_text(
        json.dumps({"vulnerabilities": [{"name": "XSS"}]}), encoding="utf-8")
    assert xbow_bench.read_findings(tmp_path, "localhost")[0]["name"] == "XSS"


def test_build_failure_is_reported_not_raised(tmp_path, monkeypatch):
    class FailingDocker(xbow_bench.DockerRunner):
        def build(self, path):
            return "no such base image"

    bench = {"id": "XBEN-001", "path": tmp_path, "level": "1", "tags": ["xss"]}
    result = xbow_bench.run_one(bench, tmp_path, FailingDocker(), 10, "baseline")
    assert "build failed" in result.error
    assert result.solved is False


def test_teardown_runs_even_when_the_scan_fails(tmp_path, monkeypatch):
    """A benchmark left running would poison every later one's ports."""
    torn_down = []

    class Docker(xbow_bench.DockerRunner):
        def build(self, path):
            return None

        def up(self, path):
            return None

        def published_port(self, path):
            return 8080

        def down(self, path):
            torn_down.append(path)

    monkeypatch.setattr(xbow_bench, "run_cyberswarm",
                        lambda *a, **k: "recon failed: boom")
    bench = {"id": "XBEN-001", "path": tmp_path, "level": "1", "tags": ["xss"]}
    xbow_bench.run_one(bench, tmp_path, Docker(), 10, "baseline")
    assert torn_down == [tmp_path]


def test_no_published_port_is_an_error_not_a_crash(tmp_path, monkeypatch):
    class Docker(xbow_bench.DockerRunner):
        def build(self, path):
            return None

        def up(self, path):
            return None

        def published_port(self, path):
            return None

        def down(self, path):
            pass

    bench = {"id": "XBEN-001", "path": tmp_path, "level": "1", "tags": ["xss"]}
    result = xbow_bench.run_one(bench, tmp_path, Docker(), 10, "baseline")
    assert "no published port" in result.error


# ── Class families ───────────────────────────────────────────────────────────

def test_blind_sqli_no_longer_fires_on_plain_sqli():
    """"SQL Injection" once matched blind_sqli too, inventing a false positive
    on every SQLi benchmark."""
    assert "blind_sqli" not in taxonomy.classify_finding(name="SQL Injection in id")
    assert "blind_sqli" in taxonomy.classify_finding(name="Blind SQL injection (time-based)")


def test_reporting_sqli_satisfies_a_blind_sqli_benchmark():
    """A blind SQLi is a SQLi; reporting the family is a hit, not a miss."""
    result = scoring.score_benchmark("b", ["blind_sqli"],
                                     [_finding("SQL Injection in id")])
    assert result.hits == {"blind_sqli"}
    assert result.false_positives == set()
    assert result.solved is True


def test_lfi_and_path_traversal_are_equivalent():
    result = scoring.score_benchmark("p", ["path_traversal"],
                                     [_finding("Local File Inclusion")])
    assert result.solved is True
    assert result.false_positives == set()


def test_families_do_not_leak_to_unrelated_classes():
    result = scoring.score_benchmark("x", ["xss"], [_finding("SQL Injection")])
    assert result.misses == {"xss"}
    assert "sqli" in result.false_positives
