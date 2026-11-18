"""Tests for the Target model — the unified persisted per-target object."""

import system_map as sm
from target import Target


def test_target_builds_sparse_map(tmp_path, monkeypatch):
    monkeypatch.setattr(sm, "STORE_DIR", tmp_path)
    t = Target("sparse.test")
    m = t.load_map()
    assert m.get("target") == "sparse.test"
    assert m["assets"]["subdomains"] == []
    assert t.system_map["target"] == "sparse.test"


def test_target_memory_roundtrip(tmp_path, monkeypatch):
    import agents.memory_agent as ma
    monkeypatch.setattr(ma, "STORE_DIR", tmp_path)
    monkeypatch.setattr(sm, "STORE_DIR", tmp_path)

    t = Target("mem.test")
    mem = t.load_memory()
    assert mem["target"] == "mem.test"
    assert mem["completed_agents"] == []
    mem["completed_agents"].append("web_fuzz")
    mem["risk_rating"] = "MEDIUM"
    t.save_memory()

    t2 = Target("mem.test")
    mem2 = t2.load_memory()
    assert mem2["completed_agents"] == ["web_fuzz"]
    assert mem2["risk_rating"] == "MEDIUM"


def test_target_reset_memory(tmp_path, monkeypatch):
    import agents.memory_agent as ma
    monkeypatch.setattr(ma, "STORE_DIR", tmp_path)
    monkeypatch.setattr(sm, "STORE_DIR", tmp_path)

    t = Target("reset.test")
    t.load_memory()["completed_agents"].append("network")
    t.save_memory()
    t.reset_memory()
    assert t.memory["completed_agents"] == []


def test_target_attach_full_url(tmp_path, monkeypatch):
    monkeypatch.setattr(sm, "STORE_DIR", tmp_path)
    t = Target("url.test")
    t.load_map()
    t.attach_full_url("https://url.test/admin")
    assert t.system_map["full_url"] == "https://url.test/admin"
    assert "https://url.test/admin" in t.system_map["endpoints"]
    assert t.system_map["web_surfaces"][0]["url"] == "https://url.test/admin"
    t.clear_full_url()
    assert "full_url" not in t.system_map


def test_target_to_context_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(sm, "STORE_DIR", tmp_path)
    t = Target("ctx.test")
    c = t.to_context()
    for k in ("target", "subdomains", "services", "ports", "technologies",
              "endpoints", "auth_paths", "api_paths", "links", "provenance",
              "recon_actions", "attack_memory"):
        assert k in c, f"missing context key {k}"
    assert c["target"] == "ctx.test"
    assert c["attack_memory"]["risk_rating"] in (None, "UNKNOWN")
