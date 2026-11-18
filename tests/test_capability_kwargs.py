"""Regression test for the build_capability_kwargs crash.

discovered_urls holds URL strings; discovered_paths holds dicts. Concatenating
them and calling dict.fromkeys() crashed on the unhashable dicts, killing any
run that reached PARAMETER_DISCOVERY with real path data.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import run_recon_loop  # noqa: E402


def test_mixed_urls_and_path_dicts_do_not_crash():
    """The exact shape from the certifiedhacker/amazon runs."""
    evidence = {
        "discovered_urls": ["http://t.com", "http://t.com/about"],
        "discovered_paths": [
            {"url": "https://t.com/.htaccess", "status": 403, "length": 358},
            {"url": "https://t.com/admin", "status": 200, "length": 1024},
        ],
    }
    kwargs, _timeout = run_recon_loop.build_capability_kwargs(
        evidence, {}, 180)
    endpoints = kwargs.get("endpoints", [])
    assert "https://t.com/admin" in endpoints, "dict entries must contribute their url"
    assert "http://t.com" in endpoints
    assert all(isinstance(e, str) for e in endpoints)


def test_path_dicts_are_deduplicated_by_url():
    evidence = {
        "discovered_urls": ["https://t.com/x"],
        "discovered_paths": [{"url": "https://t.com/x", "status": 200}],
    }
    kwargs, _ = run_recon_loop.build_capability_kwargs(evidence, {}, 180)
    assert kwargs.get("endpoints", []).count("https://t.com/x") == 1


def test_empty_and_missing_fields_are_safe():
    for evidence in ({}, {"discovered_urls": None, "discovered_paths": None},
                     {"discovered_paths": [{}]}):
        kwargs, _ = run_recon_loop.build_capability_kwargs(evidence, {}, 180)
        assert isinstance(kwargs, dict)
