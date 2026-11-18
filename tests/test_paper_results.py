"""paper_results: the rendering and aggregation helpers that turn experiment
outputs into the paper's tables and figure data. Pure over dicts; the heavy
runs (model, Docker, lab) are exercised by their own benchmarks."""

import csv

from benchmarks import paper_results as pr


def test_mean_sd_handles_empty_single_and_many():
    assert pr._mean_sd([])["mean"] is None
    one = pr._mean_sd([1.0])
    assert one["mean"] == 1.0 and one["sd"] == 0.0 and one["n"] == 1
    many = pr._mean_sd([0.4, 0.6])
    assert many["mean"] == 0.5 and many["sd"] > 0 and many["n"] == 2


def _data(lab_ok=True, recon_llm_ok=False, xbow_ok=False):
    lab = ({"status": "ok", "recall": pr._mean_sd([1.0]),
            "false_positives": pr._mean_sd([0])} if lab_ok else pr._skip("no flask"))
    recon = {"rules": {"status": "ok", "full_pass": 1.0, "profile_acc": 1.0,
                       "capability_acc": 1.0, "scenarios": 52}}
    if recon_llm_ok:
        recon["llm"] = {"status": "ok", "full_pass": pr._mean_sd([0.6, 0.7]),
                        "valid_json": pr._mean_sd([1.0, 1.0])}
        recon["guarded"] = {"status": "ok", "full_pass": pr._mean_sd([0.8, 0.9])}
    else:
        recon["llm"] = recon["guarded"] = pr._skip("no backend")
    xbow = ({"status": "ok", "benchmarks": 40,
             "variants": {"baseline": {"recall": 0.55, "precision": 0.9,
                                       "false_positives_per_benchmark": 0.2,
                                       "solved": 20, "scored": 38, "errored": 2,
                                       "solve_rate": 0.53}}}
            if xbow_ok else pr._skip("no docker"))
    return {"generated_at": "t", "env": {}, "lab": lab, "recon": recon,
            "xbow": xbow, "efficiency": {"historical": pr.HISTORICAL_EFFICIENCY,
                                         "measured_e2e": pr._skip("not set")}}


def test_table3_fills_verified_and_marks_to_run():
    md = pr.render_table3(_data())
    assert "100%" in md                      # lab recall + rules
    assert "_[to run]_" in md                 # llm/guarded/xbow
    assert "0.0" in md                        # control false positives


def test_table3_populates_model_rows_when_present():
    md = pr.render_table3(_data(recon_llm_ok=True, xbow_ok=True))
    assert "65%" in md or "0.65" in md or "±" in md   # llm mean 0.65 with sd
    assert "55%" in md                        # xbow recall 0.55


def test_table4_to_run_without_xbow_and_filled_with():
    assert "_[to run]_" in pr.render_table4(_data())
    filled = pr.render_table4(_data(xbow_ok=True))
    assert "baseline" in filled and "55%" in filled


def test_figures_written(tmp_path):
    pr.render_figures(_data(recon_llm_ok=True), tmp_path)
    for name in ("fig3_benchmark.csv", "fig4_critic.csv", "fig5_ablation.csv",
                 "fig6_efficiency.csv"):
        assert (tmp_path / name).exists()
    rows = list(csv.reader((tmp_path / "fig3_benchmark.csv").open()))
    assert rows[0] == ["metric", "setting", "value", "status"]
    assert any(r[0] == "lab_recall" and r[2] == "1.0" for r in rows[1:])
    eff = list(csv.reader((tmp_path / "fig6_efficiency.csv").open()))
    assert any("historical" in r for r in eff)        # speedup rows present


def test_skip_shape():
    s = pr._skip("because")
    assert s == {"status": "skipped", "reason": "because"}
