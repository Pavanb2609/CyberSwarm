"""Tests for rag_memory — the cross-engagement lesson store.

Every test builds its own store under tmp_path, so nothing here reads or
writes the real results/ directory or results/idx/.
"""

import json
import sqlite3

import pytest

import rag_memory as rag


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def results_dir(tmp_path):
    """A miniature results/ tree covering all four indexed sources."""
    root = tmp_path / "results"
    (root / "attack_evidence").mkdir(parents=True)
    (root / "evidence").mkdir(parents=True)

    (root / "attack_evidence" / "alpha.example.com.json").write_text(json.dumps({
        "target": "alpha.example.com",
        "vulnerabilities": [
            {
                "source_agent": "web_attack", "tool": "nuclei",
                "name": "Exposed Admin Panel", "severity": "HIGH",
                "confidence": 80, "url": "https://alpha.example.com/admin",
                "description": "Admin panel reachable without auth.\n[CRITIC]: confirmed.",
                "verdict": "CONFIRM",
            },
            {
                "source_agent": "infra", "tool": "testssl",
                "name": "LUCKY13", "severity": "LOW", "confidence": 70,
                "description": "potentially vulnerable, uses TLS CBC ciphers",
                "verdict": "CONFIRM",
            },
        ],
        "completed_agents": ["web_attack", "infra"],
        "attack_graph": [
            {"agent": "web_attack", "priority": 1,
             "reason": "WordPress detected on the web surface", "skip": False},
            {"agent": "cloud", "priority": 9,
             "reason": "No cloud metadata endpoints observed", "skip": True},
        ],
    }), encoding="utf-8")

    (root / "evidence" / "alpha.example.com.json").write_text(json.dumps({
        "target": "alpha.example.com",
        "target_type": "WEB_APPLICATION",
        "technologies": ["WordPress", "PHP", "Apache httpd", "MySQL"],
        "open_ports": [80, 443, 3306],
        "completed_actions": ["PORT_SCAN", "WEB_TECH_DISCOVERY"],
        "failed_actions": ["CONTENT_DISCOVERY"],
        "zero_findings_actions": ["SUBDOMAIN_TAKEOVER_SCAN"],
        "failure_patterns": {"CONTENT_DISCOVERY": "timed out after 240s behind the CDN"},
        "missing_security_headers": ["content-security-policy", "strict-transport-security"],
        "detected_api_types": ["REST"],
    }), encoding="utf-8")

    (root / "tool_memory.json").write_text(json.dumps({
        "version": 1,
        "tools": {
            "feroxbuster": {"successes": 2, "failures": 6, "timeout_failures": 5},
            "nuclei": {"successes": 9, "failures": 1, "timeout_failures": 0},
            "never_run": {"successes": 0, "failures": 0},
        },
    }), encoding="utf-8")

    (root / "attack_decision_log.jsonl").write_text("\n".join([
        json.dumps({"event": "attack_graph", "target": "alpha.example.com",
                    "graph": [{"agent": "web_attack", "priority": 1}]}),
        json.dumps({"event": "agent_result", "target": "alpha.example.com",
                    "agent": "web_attack", "approved": True,
                    "result": {"agent": "web_attack", "status": "partial",
                               "findings": [{"name": "x"}], "duration_s": 294.3,
                               "tools_run": ["feroxbuster", "nuclei"], "error": ""}}),
        json.dumps({"event": "agent_result", "target": "alpha.example.com",
                    "agent": "web_attack",
                    "result": {"agent": "web_attack", "status": "partial",
                               "findings": [], "duration_s": 120.0,
                               "tools_run": ["corsy"], "error": "tool missing"}}),
        "not valid json at all",
        "",
    ]), encoding="utf-8")

    return root


@pytest.fixture
def memory(tmp_path, results_dir):
    mem = rag.RagMemory(db_path=tmp_path / "idx" / "memory.sqlite",
                        results_dir=results_dir)
    yield mem
    mem.close()


# ── Query construction ───────────────────────────────────────────────────────

def test_fts_query_escapes_operator_characters():
    """Raw SystemMap text is full of ':', '-', '/' and '.' — all FTS5 operators."""
    q = rag.fts_query("jQuery UI:1.7.2 nginx/1.29.8 OpenSSH-9.9")
    assert q
    assert '"' in q and " OR " in q
    # The bare operator characters must not survive into the expression.
    assert ":" not in q and "/" not in q


def test_fts_query_is_valid_sqlite_syntax(memory):
    """The escaped expression must actually execute, not just look safe."""
    memory.update_from_results()
    conn = memory.connect()
    for raw in ["jQuery UI:1.7.2", "nginx/1.29.8", "a-b-c", 'quote" AND OR *',
                "(parens) ^caret", "NEAR NOT AND OR"]:
        expr = rag.fts_query(raw)
        if not expr:
            continue
        conn.execute("SELECT rowid FROM doc_idx WHERE doc_idx MATCH ?", (expr,)).fetchall()


def test_fts_query_empty_for_stopwords_only():
    assert rag.fts_query("") == ""
    assert rag.fts_query("the and of it") == ""
    assert rag.fts_query("!!! ??? ...") == ""


def test_build_query_extracts_signals():
    smap = {
        "technologies": [{"name": "WordPress", "version": "6.4"},
                         {"name": "nginx", "version": ""}],
        "services": [{"port": 443, "service": "https"},
                     {"port": 3306, "service": "mysql", "version": "5.7"}],
        "signals": {"cms": "WordPress", "api_types": ["REST", "GRAPHQL"], "ad": False},
        "api_paths": ["/api/v1/users"],
        "auth_paths": ["/login"],
        "web_surfaces": [{"url": "https://example.com"}],
    }
    q = rag.build_query(smap).lower()
    assert "wordpress" in q
    assert "mysql" in q
    assert "graphql" in q
    assert "3306" in q          # non-web port is discriminating, so it is kept
    assert "443" not in q       # standard web ports carry no signal
    assert "api" in q and "login" in q


def test_build_query_handles_active_directory_signals():
    q = rag.build_query({"signals": {"ad": True}}).lower()
    assert "kerberos" in q and "ldap" in q


def test_build_query_tolerates_garbage():
    assert rag.build_query({}) == ""
    assert rag.build_query(None) == ""
    assert rag.build_query({"technologies": None, "services": "nope",
                            "signals": []}) == ""


def test_query_from_smap_matches_build_query():
    smap = {"technologies": [{"name": "Drupal"}]}
    assert rag.query_from_smap(smap) == rag.build_query(smap)


# ── Indexing ─────────────────────────────────────────────────────────────────

def test_index_then_retrieve(memory):
    stats = memory.update_from_results()
    assert stats["collected"] > 0
    assert stats["added"] == stats["collected"]
    assert memory.count() == stats["collected"]

    hits = memory.retrieve("wordpress php admin panel", k=5)
    assert hits
    assert all(isinstance(h, rag.Hit) for h in hits)
    assert any("Admin Panel" in h.body for h in hits)


def test_all_four_sources_are_indexed(memory):
    memory.update_from_results()
    kinds = {row["kind"] for row in
             memory.connect().execute("SELECT DISTINCT kind FROM documents")}
    assert {"finding", "plan", "tool", "recon", "decision"} <= kinds


def test_reindex_is_idempotent(memory):
    first = memory.update_from_results()
    total_after_first = memory.count()

    second = memory.update_from_results()
    assert second["added"] == 0
    assert second["updated"] == 0
    assert second["skipped"] == first["collected"]
    assert memory.count() == total_after_first, "repeat indexing must not bloat the DB"


def test_changed_source_updates_in_place(memory, results_dir):
    memory.update_from_results()
    before = memory.count()

    path = results_dir / "attack_evidence" / "alpha.example.com.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["vulnerabilities"][0]["severity"] = "CRITICAL"
    path.write_text(json.dumps(data), encoding="utf-8")

    stats = memory.update_from_results()
    assert stats["updated"] >= 1
    assert stats["added"] == 0
    assert memory.count() == before, "an edited finding must update, not duplicate"

    hits = memory.retrieve("exposed admin panel", k=5)
    assert any(h.severity == "CRITICAL" for h in hits)


def test_fts_index_stays_in_sync_after_update(memory, results_dir):
    """The FTS triggers must delete the stale row, not leave a ghost behind."""
    memory.update_from_results()
    path = results_dir / "attack_evidence" / "alpha.example.com.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["vulnerabilities"][0]["description"] = "Completely different wording: teapot."
    path.write_text(json.dumps(data), encoding="utf-8")
    memory.update_from_results()

    assert memory.retrieve("teapot", k=5)
    # Old wording is gone from the index entirely.
    assert not [h for h in memory.retrieve("reachable without auth", k=5)
                if "reachable" in h.body]


def test_full_rebuild_clears_first(memory, results_dir):
    memory.update_from_results()
    (results_dir / "attack_evidence" / "alpha.example.com.json").unlink()
    stats = memory.update_from_results(full=True)
    assert stats["added"] == stats["collected"]
    assert not memory.retrieve("exposed admin panel", k=5)


# ── Retrieval / ranking ──────────────────────────────────────────────────────

def test_bm25_ranks_more_relevant_first(memory):
    memory.update_from_results()
    hits = memory.retrieve("tls ciphers lucky13", k=5)
    assert hits
    assert "LUCKY13" in hits[0].body
    # bm25() is ascending-better, and `ORDER BY rank` must preserve that.
    scores = [h.score for h in hits]
    assert scores == sorted(scores)


def test_retrieve_respects_k(memory):
    memory.update_from_results()
    assert len(memory.retrieve("wordpress php apache mysql tls", k=2)) <= 2
    assert memory.retrieve("wordpress", k=0) == []


def test_retrieve_can_filter_by_kind(memory):
    memory.update_from_results()
    hits = memory.retrieve("feroxbuster nuclei", k=10, kind="tool")
    assert hits
    assert all(h.kind == "tool" for h in hits)


def test_retrieval_is_cross_engagement(tmp_path, results_dir):
    """A lesson learned on one target must surface for a different target."""
    (results_dir / "evidence" / "beta.example.org.json").write_text(json.dumps({
        "target": "beta.example.org",
        "technologies": ["WordPress", "PHP"],
        "failed_actions": ["CONTENT_DISCOVERY"],
        "failure_patterns": {"CONTENT_DISCOVERY": "blocked by WAF, zero results"},
    }), encoding="utf-8")

    mem = rag.RagMemory(db_path=tmp_path / "x.sqlite", results_dir=results_dir)
    try:
        mem.update_from_results()
        targets = {h.target for h in mem.retrieve("wordpress content discovery", k=10)}
        assert len(targets) > 1
    finally:
        mem.close()


def test_tool_memory_skips_zero_run_tools(memory):
    memory.update_from_results()
    bodies = " ".join(h.body for h in memory.retrieve("feroxbuster nuclei never_run", k=10))
    assert "feroxbuster" in bodies
    assert "never_run" not in bodies


def test_decision_log_aggregates_per_agent(memory):
    """Two log lines for one agent become one lesson, not two documents."""
    memory.update_from_results()
    rows = memory.connect().execute(
        "SELECT body FROM documents WHERE kind='decision'").fetchall()
    assert len(rows) == 1
    assert "ran 2x" in rows[0]["body"]
    assert "1 errored" in rows[0]["body"]


# ── Context enrichment ───────────────────────────────────────────────────────

def test_context_makes_lessons_retrievable_by_technology(memory):
    """The whole point of the context column.

    "capability CONTENT_DISCOVERY FAILED" never says "WordPress", but it was
    learned on a WordPress host, so a WordPress query must surface it.
    """
    memory.update_from_results()
    hits = memory.retrieve("wordpress mysql apache", k=10)
    bodies = " ".join(h.body for h in hits)
    assert "CONTENT_DISCOVERY" in bodies
    assert "agent web_attack" in bodies


def test_context_is_never_shown_in_the_prompt(memory):
    memory.update_from_results()
    block = rag.format_lessons(memory.retrieve("wordpress mysql", k=5))
    # 'WordPress' reaches the index via context; it must not leak into a body
    # that never mentioned it.
    for line in block.splitlines():
        if line.startswith("- ") and "CONTENT_DISCOVERY" in line:
            assert "WordPress" not in line


def test_recon_profile_opts_out_of_context(memory):
    """The profile already lists its technologies; duplicating them would let
    it crowd out every actionable lesson."""
    memory.update_from_results()
    row = memory.connect().execute(
        "SELECT context FROM documents WHERE kind='recon'").fetchone()
    assert row["context"] == ""


def test_actionable_lessons_outrank_the_profile_dump(memory):
    memory.update_from_results()
    hits = memory.retrieve("wordpress php apache mysql", k=5)
    assert len(hits) >= 3, "tech query should reach more than the profile doc"
    assert not all(h.kind == "recon" for h in hits)


# ── Diversity ────────────────────────────────────────────────────────────────

def test_max_per_target_spreads_results(tmp_path, results_dir):
    for name in ("beta.example.org", "gamma.example.net"):
        (results_dir / "evidence" / f"{name}.json").write_text(json.dumps({
            "target": name,
            "technologies": ["WordPress", "PHP"],
            "failed_actions": ["CONTENT_DISCOVERY"],
            "zero_findings_actions": ["JAVASCRIPT_ANALYSIS"],
            "completed_actions": ["PORT_SCAN"],
        }), encoding="utf-8")

    mem = rag.RagMemory(db_path=tmp_path / "d.sqlite", results_dir=results_dir)
    try:
        mem.update_from_results()
        capped = mem.retrieve("wordpress php content discovery", k=6,
                              max_per_target=1)
        targets = [h.target for h in capped]
        assert len(set(targets)) >= 3, "cap should pull in distinct engagements"
    finally:
        mem.close()


def test_max_per_target_backfills_rather_than_starving(memory):
    """With only one matching engagement, the cap must not shrink the result."""
    memory.update_from_results()
    uncapped = memory.retrieve("wordpress mysql apache", k=5)
    capped = memory.retrieve("wordpress mysql apache", k=5, max_per_target=1)
    assert len(capped) == len(uncapped)


# ── Schema migration ─────────────────────────────────────────────────────────

def test_outdated_schema_is_rebuilt(tmp_path, results_dir):
    """The store is a derived cache; a stale schema is discarded, not migrated."""
    db = tmp_path / "old.sqlite"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE documents(id INTEGER PRIMARY KEY, doc_key TEXT);"
        "INSERT INTO meta VALUES('schema_version', '1');")
    conn.commit()
    conn.close()

    mem = rag.RagMemory(db_path=db, results_dir=results_dir)
    try:
        stats = mem.update_from_results()   # must not raise on the old shape
        assert stats["collected"] > 0
        assert mem.count() > 0
        version = mem.connect().execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        assert int(version["value"]) == rag.SCHEMA_VERSION
    finally:
        mem.close()


def test_fresh_db_is_not_treated_as_migration(tmp_path, results_dir):
    mem = rag.RagMemory(db_path=tmp_path / "fresh.sqlite", results_dir=results_dir)
    try:
        assert mem.update_from_results()["collected"] > 0
    finally:
        mem.close()


# ── Graceful degradation ─────────────────────────────────────────────────────

def test_retrieve_on_missing_db_returns_empty(tmp_path):
    mem = rag.RagMemory(db_path=tmp_path / "nope" / "missing.sqlite",
                        results_dir=tmp_path / "nothing")
    try:
        assert mem.retrieve("anything at all", k=5) == []
        assert mem.count() == 0
        assert not mem.exists()
    finally:
        mem.close()


def test_empty_db_retrieves_nothing(tmp_path):
    mem = rag.RagMemory(db_path=tmp_path / "empty.sqlite",
                        results_dir=tmp_path / "no_results", index_skills=False)
    try:
        stats = mem.update_from_results()
        assert stats["collected"] == 0
        assert mem.retrieve("wordpress", k=5) == []
    finally:
        mem.close()


def test_malformed_sources_are_skipped(tmp_path):
    root = tmp_path / "results"
    (root / "attack_evidence").mkdir(parents=True)
    (root / "evidence").mkdir(parents=True)
    (root / "attack_evidence" / "bad.json").write_text("{ not json", encoding="utf-8")
    (root / "evidence" / "list.json").write_text("[1, 2, 3]", encoding="utf-8")
    (root / "tool_memory.json").write_text('{"tools": "wrong type"}', encoding="utf-8")

    mem = rag.RagMemory(db_path=tmp_path / "m.sqlite", results_dir=root,
                        index_skills=False)
    try:
        stats = mem.update_from_results()   # must not raise
        assert stats["collected"] == 0
    finally:
        mem.close()


def test_lessons_for_smap_is_noop_when_disabled(tmp_path):
    out = rag.lessons_for_smap({"technologies": [{"name": "WordPress"}]},
                               db_path=tmp_path / "m.sqlite",
                               config={"rag": {"enabled": False}})
    assert out == ""


def test_lessons_for_smap_returns_block(tmp_path, results_dir):
    db = tmp_path / "m.sqlite"
    rag.update_from_results(db_path=db, results_dir=results_dir,
                            config={"rag": {"enabled": True}})
    block = rag.lessons_for_smap(
        {"technologies": [{"name": "WordPress"}, {"name": "PHP"}],
         "signals": {"cms": "WordPress"}},
        k=5, db_path=db, config={"rag": {"enabled": True}})
    assert block.startswith(rag.LESSON_HEADER)
    assert block.count("\n- ") <= 5


def test_update_from_results_respects_disabled_config(tmp_path, results_dir):
    db = tmp_path / "m.sqlite"
    stats = rag.update_from_results(db_path=db, results_dir=results_dir,
                                    config={"rag": {"enabled": False}})
    assert stats["collected"] == 0
    assert not db.exists()


# ── Prompt formatting ────────────────────────────────────────────────────────

def test_format_lessons_empty_input():
    assert rag.format_lessons([]) == ""


def test_format_lessons_caps_and_dedupes():
    hits = [rag.Hit(doc_key=f"k{i}", kind="tool", body="same body", target="t")
            for i in range(10)]
    out = rag.format_lessons(hits, max_lines=5)
    assert out.count("- [t] same body") == 1


def test_format_lessons_shape():
    hits = [rag.Hit(doc_key="a", kind="finding", body="HIGH finding 'X'",
                    target="alpha.example.com"),
            rag.Hit(doc_key="b", kind="tool", body="tool y is flaky",
                    target="beta.example.org")]
    out = rag.format_lessons(hits)
    assert out.startswith(rag.LESSON_HEADER)
    assert "[alpha.example.com] HIGH finding 'X'" in out
    assert "[beta.example.org] tool y is flaky" in out
    assert len(out.splitlines()) == 4      # header + preamble + 2 bullets


def test_lesson_bodies_stay_short(memory):
    """Lessons are injected into a small-context prompt; keep them one-liners."""
    memory.update_from_results()
    rows = memory.connect().execute(
        "SELECT body FROM documents WHERE kind != 'skill'").fetchall()
    assert rows
    for row in rows:
        assert len(row["body"]) <= rag.MAX_BODY_CHARS
        assert "\n" not in row["body"]


# ── Config plumbing ──────────────────────────────────────────────────────────

def test_rag_config_defaults():
    cfg = rag.rag_config({})
    assert cfg["enabled"] is True
    assert cfg["top_k"] == rag.DEFAULT_TOP_K
    assert cfg["auto_reindex"] is True


def test_rag_config_reads_overrides():
    cfg = rag.rag_config({"rag": {"enabled": False, "top_k": 3,
                                  "auto_reindex": False, "db_path": "x/y.sqlite"}})
    assert cfg["enabled"] is False
    assert cfg["top_k"] == 3
    assert cfg["auto_reindex"] is False
    assert cfg["db_path"] == "x/y.sqlite"


def test_rag_config_tolerates_wrong_type():
    assert rag.rag_config({"rag": "not a dict"})["enabled"] is True


def test_relative_db_path_resolves_under_root():
    mem = rag.get_memory(config={"rag": {"db_path": "results/idx/test.sqlite"}})
    try:
        assert mem.db_path.is_absolute()
        assert mem.db_path.parts[-3:] == ("results", "idx", "test.sqlite")
    finally:
        mem.close()


def test_fts5_is_available():
    """If this fails the whole feature degrades to a no-op by design."""
    assert rag.fts5_available() is True


# ── Planner integration ──────────────────────────────────────────────────────

class RecordingModelClient:
    """Captures the prompts the planner builds, and returns a valid graph."""

    def __init__(self):
        self.prompts = []

    def chat(self, system_prompt, user_prompt, temperature=None):
        self.prompts.append(user_prompt)
        return json.dumps({
            "target_profile": "WEB_APPLICATION",
            "attack_graph": [{"agent": "web_attack", "priority": 1,
                              "reason": "web surface", "skip": False}],
            "skip_agents": [],
            "reasoning": "focus on the web surface",
        })


@pytest.fixture
def planner_smap():
    """Built through the project's own constructor so every nested key the
    rule engine dereferences (posture, assets, ...) is present."""
    import system_map as sm
    return sm.build_from_evidence("new.example.com", {
        "resolved_ip": "203.0.113.10",
        "reachable": True,
        "port_details": [{"port": 443, "service": "https", "state": "open"}],
        "open_ports": [443],
        "technologies": ["WordPress", "PHP", "Apache httpd"],
        "discovered_urls": ["https://new.example.com/"],
        "subdomains": [],
        "completed_actions": ["portscan"],
        "failed_actions": [],
        "zero_findings_actions": [],
        "discovered_parameters": [],
        "cms_signals": "WordPress",
    })


def test_planner_prompt_contains_rag_block(tmp_path, results_dir, planner_smap,
                                           monkeypatch):
    from agents.planner_agent import PlannerAgent

    db = tmp_path / "planner.sqlite"
    rag.update_from_results(db_path=db, results_dir=results_dir,
                            config={"rag": {"enabled": True}})
    monkeypatch.setattr(rag, "rag_config", lambda config=None: {
        "enabled": True, "db_path": str(db), "top_k": 5, "auto_reindex": False})

    client = RecordingModelClient()
    graph = PlannerAgent(client).build_attack_graph(planner_smap, [], {}, use_llm=True)

    assert client.prompts, "planner should have called the LLM"
    prompt = client.prompts[0]
    assert rag.LESSON_HEADER in prompt

    block = prompt.split(rag.LESSON_HEADER)[1]
    bullets = [ln for ln in block.splitlines() if ln.startswith("- ")]
    assert bullets, "the block should carry at least one lesson"
    assert len(bullets) <= 5
    # Lessons must come from the prior engagement, not the target being planned.
    assert all("[alpha.example.com]" in ln for ln in bullets)

    assert prompt.rstrip().endswith("Return the refined attack graph JSON.")
    assert graph["attack_graph"]


def test_planner_injects_operational_lessons_not_just_profiles(
        tmp_path, planner_smap, monkeypatch):
    """A tech-matched query must reach the actionable lessons, not only the
    recon profile dump — the regression the context column exists to prevent."""
    from agents.planner_agent import PlannerAgent

    root = tmp_path / "results"
    (root / "evidence").mkdir(parents=True)
    (root / "evidence" / "prior.example.com.json").write_text(json.dumps({
        "target": "prior.example.com",
        "technologies": ["WordPress", "PHP", "Apache httpd"],
        "failed_actions": ["CONTENT_DISCOVERY"],
        "failure_patterns": {"CONTENT_DISCOVERY": "timed out after 240s behind the CDN"},
    }), encoding="utf-8")

    db = tmp_path / "ops.sqlite"
    rag.update_from_results(db_path=db, results_dir=root,
                            config={"rag": {"enabled": True}})
    monkeypatch.setattr(rag, "rag_config", lambda config=None: {
        "enabled": True, "db_path": str(db), "top_k": 5, "auto_reindex": False})

    client = RecordingModelClient()
    PlannerAgent(client).build_attack_graph(planner_smap, [], {}, use_llm=True)
    assert "CONTENT_DISCOVERY FAILED" in client.prompts[0]


def test_planner_works_with_no_index(tmp_path, planner_smap, monkeypatch):
    """Missing DB must leave the prompt byte-identical to the pre-RAG version."""
    from agents.planner_agent import PlannerAgent

    monkeypatch.setattr(rag, "rag_config", lambda config=None: {
        "enabled": True, "db_path": str(tmp_path / "absent.sqlite"),
        "top_k": 5, "auto_reindex": False})

    client = RecordingModelClient()
    graph = PlannerAgent(client).build_attack_graph(planner_smap, [], {}, use_llm=True)
    assert rag.LESSON_HEADER not in client.prompts[0]
    assert graph["attack_graph"]


def test_planner_skips_rag_when_disabled(tmp_path, results_dir, planner_smap,
                                         monkeypatch):
    from agents.planner_agent import PlannerAgent

    db = tmp_path / "planner.sqlite"
    rag.update_from_results(db_path=db, results_dir=results_dir,
                            config={"rag": {"enabled": True}})
    monkeypatch.setattr(rag, "rag_config", lambda config=None: {
        "enabled": False, "db_path": str(db), "top_k": 5, "auto_reindex": False})

    client = RecordingModelClient()
    PlannerAgent(client).build_attack_graph(planner_smap, [], {}, use_llm=True)
    assert rag.LESSON_HEADER not in client.prompts[0]


def test_planner_survives_broken_rag(planner_smap, monkeypatch):
    """A raising RAG layer must not take the planner down with it."""
    from agents.planner_agent import PlannerAgent

    def boom(*_a, **_kw):
        raise RuntimeError("index on fire")

    monkeypatch.setattr(rag, "rag_config", boom)
    client = RecordingModelClient()
    graph = PlannerAgent(client).build_attack_graph(planner_smap, [], {}, use_llm=True)
    assert graph["attack_graph"]
    assert rag.LESSON_HEADER not in client.prompts[0]


def test_rule_only_planning_makes_no_rag_call(planner_smap, monkeypatch):
    """use_llm=False must not touch the index at all."""
    from agents.planner_agent import PlannerAgent

    called = []
    monkeypatch.setattr(rag, "rag_config", lambda config=None: called.append(1) or {
        "enabled": True, "db_path": ":memory:", "top_k": 5, "auto_reindex": False})
    graph = PlannerAgent(None).build_attack_graph(planner_smap, [], {}, use_llm=False)
    assert not called
    assert graph["attack_graph"]


def test_maybe_auto_reindex_respects_flag(tmp_path, results_dir, monkeypatch):
    monkeypatch.setattr(rag, "DEFAULT_RESULTS_DIR", results_dir)
    db = tmp_path / "auto.sqlite"

    off = rag.maybe_auto_reindex({"rag": {"enabled": True, "auto_reindex": False,
                                          "db_path": str(db)}}, quiet=True)
    assert off["collected"] == 0
    assert not db.exists()

    on = rag.maybe_auto_reindex({"rag": {"enabled": True, "auto_reindex": True,
                                         "db_path": str(db)}}, quiet=True)
    assert on["collected"] > 0
    assert db.exists()


def test_maybe_auto_reindex_swallows_errors(monkeypatch):
    monkeypatch.setattr(rag, "update_from_results",
                        lambda **_kw: (_ for _ in ()).throw(RuntimeError("disk full")))
    assert rag.maybe_auto_reindex({"rag": {"enabled": True, "auto_reindex": True}},
                                  quiet=True)["collected"] == 0


def test_schema_has_expected_tables(memory):
    memory.update_from_results()
    names = {r[0] for r in memory.connect().execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
    assert {"documents", "doc_idx", "meta"} <= names


# ── Skill packs ──────────────────────────────────────────────────────────────

@pytest.fixture
def skills_dir(tmp_path):
    root = tmp_path / "skills"
    (root / "references").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "# Overview\n\nCyberSwarm drives specialist agents against a target.\n\n"
        "## WordPress targets\n\n"
        "Enumerate plugins with wpscan before any brute force. Plugin version "
        "drift is the usual foothold on WordPress sites and is far cheaper to "
        "check than content discovery.\n", encoding="utf-8")
    (root / "references" / "network.md").write_text(
        "# Network reference\r\n\r\n## SMB enumeration\r\n\r\n"
        "Check signing and null sessions on port 445 before anything else. "
        "Unsigned SMB is the single highest-value network finding.\r\n",
        encoding="utf-8")
    (root / "references" / "tiny.md").write_text(
        "# T\n\n## Skip\n\ntoo short\n", encoding="utf-8")
    return root


def test_split_markdown_sections_handles_crlf_and_preamble():
    sections = rag.split_markdown_sections(
        "intro text\r\n\r\n# Title\r\n\r\nbody one\r\n\r\n## Sub\r\n\r\nbody two\r\n")
    headings = [h for h, _ in sections]
    assert headings == ["", "Title", "Sub"]
    assert "body two" in sections[-1][1]


def test_split_markdown_handles_no_headings():
    sections = rag.split_markdown_sections("just prose, no headings")
    assert len(sections) == 1
    assert sections[0][0] == ""


def test_skill_sections_indexed_with_larger_body(skills_dir):
    docs = rag.collect_skill_documents(skills_dir)
    assert docs
    assert all(d.kind == "skill" for d in docs)
    assert all(d.body_limit == rag.MAX_SKILL_BODY_CHARS for d in docs)
    assert all(d.target == "" for d in docs), "skills are not engagement evidence"
    bodies = " ".join(d.body for d in docs)
    assert "wpscan" in bodies
    assert "too short" not in bodies, "trivial sections should be dropped"


def test_skill_docs_survive_a_missing_directory(tmp_path):
    assert rag.collect_skill_documents(tmp_path / "nope") == []


def test_skills_do_not_pollute_lesson_retrieval(tmp_path, results_dir, skills_dir):
    mem = rag.RagMemory(db_path=tmp_path / "s.sqlite", results_dir=results_dir,
                        skills_dir=skills_dir)
    try:
        stats = mem.update_from_results()
        assert stats["skills"] > 0
        # A WordPress query matches both a skill section and real lessons, but
        # retrieve() is lesson-only.
        assert all(h.kind != "skill" for h in mem.retrieve("wordpress wpscan", k=10))
        assert mem.retrieve("wordpress", k=10, kind="skill")
    finally:
        mem.close()


def test_skills_retrieved_for_matching_technology(tmp_path, results_dir, skills_dir):
    db = tmp_path / "s.sqlite"
    rag.update_from_results(db_path=db, results_dir=results_dir,
                            skills_dir=skills_dir, config={"rag": {"enabled": True}})
    block = rag.skills_for_smap(
        {"technologies": [{"name": "WordPress"}]}, k=2, db_path=db,
        config={"rag": {"enabled": True}})
    assert block.startswith(rag.SKILL_HEADER)
    assert "wpscan" in block


def test_skills_block_empty_when_disabled(tmp_path, results_dir, skills_dir):
    db = tmp_path / "s.sqlite"
    rag.update_from_results(db_path=db, results_dir=results_dir, skills_dir=skills_dir,
                            config={"rag": {"enabled": True}})
    assert rag.skills_for_smap({"technologies": [{"name": "WordPress"}]}, db_path=db,
                               config={"rag": {"index_skills": False}}) == ""


def test_index_skills_false_skips_them(tmp_path, results_dir, skills_dir):
    mem = rag.RagMemory(db_path=tmp_path / "s.sqlite", results_dir=results_dir,
                        skills_dir=skills_dir, index_skills=False)
    try:
        assert mem.update_from_results()["skills"] == 0
    finally:
        mem.close()


def test_format_skills_caps_and_dedupes():
    hits = [rag.Hit(doc_key=f"k{i}", kind="skill", body="same excerpt")
            for i in range(6)]
    out = rag.format_skills(hits, max_lines=2)
    assert out.count("- same excerpt") == 1
    assert rag.format_skills([]) == ""


def test_planner_prompt_carries_both_blocks(tmp_path, results_dir, skills_dir,
                                            planner_smap, monkeypatch):
    from agents.planner_agent import PlannerAgent

    db = tmp_path / "both.sqlite"
    rag.update_from_results(db_path=db, results_dir=results_dir, skills_dir=skills_dir,
                            config={"rag": {"enabled": True}})
    monkeypatch.setattr(rag, "rag_config", lambda config=None: {
        "enabled": True, "db_path": str(db), "top_k": 5, "auto_reindex": False,
        "index_skills": True, "skills_dir": str(skills_dir), "skill_top_k": 2})

    client = RecordingModelClient()
    PlannerAgent(client).build_attack_graph(planner_smap, [], {}, use_llm=True)
    prompt = client.prompts[0]
    assert rag.SKILL_HEADER in prompt
    assert rag.LESSON_HEADER in prompt
    assert prompt.index(rag.SKILL_HEADER) < prompt.index(rag.LESSON_HEADER)
    assert prompt.rstrip().endswith("Return the refined attack graph JSON.")


def test_planner_survives_broken_skill_lookup(planner_smap, monkeypatch):
    from agents.planner_agent import PlannerAgent

    monkeypatch.setattr(rag, "skills_for_smap",
                        lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("boom")))
    client = RecordingModelClient()
    graph = PlannerAgent(client).build_attack_graph(planner_smap, [], {}, use_llm=True)
    assert graph["attack_graph"]
    assert rag.SKILL_HEADER not in client.prompts[0]


# ── Imported skill packs ─────────────────────────────────────────────────────

def test_frontmatter_parsed_from_skill_files():
    meta, body = rag.parse_frontmatter(
        "---\nname: web-sqli\ndescription: SQLi. Triggers - sleep-based delay\n"
        "tags: [exploitation]\n---\n\n# SQL Injection\n\nbody\n")
    assert meta["name"] == "web-sqli"
    assert "Triggers" in meta["description"]
    assert body.lstrip().startswith("# SQL Injection")


def test_frontmatter_absent_or_malformed_degrades():
    assert rag.parse_frontmatter("# No frontmatter")[0] == {}
    assert rag.parse_frontmatter("---\nunterminated\n")[0] == {}
    assert rag.parse_frontmatter("")[0] == {}


def test_skill_named_from_its_directory(tmp_path):
    root = tmp_path / "skills"
    (root / "web" / "sqli").mkdir(parents=True)
    (root / "web" / "sqli" / "SKILL.md").write_text(
        "---\ndescription: SQL injection. Triggers - order by, sleep delay\n---\n"
        "## Detect\n\nDrive detection with sqlmap rather than manual probing, "
        "because it covers boolean, error, union and time techniques.\n",
        encoding="utf-8")
    docs = rag.collect_skill_documents(root, excludes=[])
    assert docs
    assert all("SKILL" not in d.body.split(":")[0] for d in docs)


def test_frontmatter_description_makes_sections_retrievable(tmp_path):
    """Trigger keywords live in the frontmatter, not the section body."""
    root = tmp_path / "skills"
    (root / "web" / "sqli").mkdir(parents=True)
    (root / "web" / "sqli" / "SKILL.md").write_text(
        "---\ndescription: Triggers - order by, boolean differential, sleep delay\n---\n"
        "## Detect\n\nRun the scanner and parse its output before probing by hand, "
        "since it covers every injection class in one pass.\n", encoding="utf-8")
    mem = rag.RagMemory(db_path=tmp_path / "s.sqlite",
                        results_dir=tmp_path / "none", skills_dir=root,
                        skill_excludes=[])
    try:
        mem.update_from_results()
        # "sleep delay" appears only in the frontmatter.
        assert mem.retrieve("sleep delay boolean differential", k=5, kind="skill")
    finally:
        mem.close()


def test_multiple_skill_roots_are_merged(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for root, text in ((a, "alpha guidance about nginx servers and their configuration"),
                       (b, "beta guidance about mysql databases and their hardening")):
        root.mkdir()
        (root / "one.md").write_text(f"## Topic\n\n{text}\n", encoding="utf-8")
    docs = rag.collect_skill_documents([a, b], excludes=[])
    bodies = " ".join(d.body for d in docs)
    assert "alpha" in bodies and "beta" in bodies


def test_excluded_categories_are_not_indexed(tmp_path):
    root = tmp_path / "skills"
    (root / "playbooks" / "ad").mkdir(parents=True)
    (root / "web" / "sqli").mkdir(parents=True)
    (root / "playbooks" / "ad" / "SKILL.md").write_text(
        "## Kerberoast\n\nRequest service tickets and crack them offline for "
        "accounts with SPNs set, which is the standard path here.\n", encoding="utf-8")
    (root / "web" / "sqli" / "SKILL.md").write_text(
        "## Detect\n\nDrive detection with the scanner rather than by hand, "
        "since it covers every class in one pass.\n", encoding="utf-8")

    kept = rag.collect_skill_documents(root, excludes=["playbooks/ad"])
    assert kept
    assert all("playbooks/ad" not in d.tool for d in kept)
    assert len(rag.collect_skill_documents(root, excludes=[])) > len(kept)


def test_default_excludes_cover_unsupported_categories():
    """Categories with no matching agent must stay off by default."""
    for pattern in ("playbooks/ad", "services/pivoting"):
        assert pattern in rag.DEFAULT_SKILL_EXCLUDES
