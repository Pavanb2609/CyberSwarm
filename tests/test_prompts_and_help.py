"""Tests for prompt_library.py and help_text.py."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import help_text  # noqa: E402
import prompt_library  # noqa: E402


@pytest.fixture
def prompts_dir(tmp_path):
    root = tmp_path / "prompts"
    (root / "nested").mkdir(parents=True)
    (root / "triage.md").write_text(
        "---\n"
        "description: Rank findings by exploitability\n"
        "tags: [reporting, triage]\n"
        "variables: [target]\n"
        "---\n"
        "Review the findings for {{target}} and rank them.\n", encoding="utf-8")
    (root / "bare.md").write_text(
        "No frontmatter here, just a body.\n", encoding="utf-8")
    (root / "nested" / "dollar.md").write_text(
        "---\ndescription: Uses dollar syntax\n---\n"
        "Assess $TARGET for the $CLIENT engagement.\n", encoding="utf-8")
    (root / "empty.md").write_text("---\ndescription: nothing\n---\n", encoding="utf-8")
    return root


# ── Loading ──────────────────────────────────────────────────────────────────

def test_loads_prompts_recursively(prompts_dir):
    prompts = prompt_library.load_prompts(prompts_dir)
    assert set(prompts) == {"triage", "bare", "dollar"}


def test_frontmatter_is_parsed(prompts_dir):
    prompt = prompt_library.load_prompts(prompts_dir)["triage"]
    assert prompt.description == "Rank findings by exploitability"
    assert prompt.tags == ["reporting", "triage"]
    assert prompt.variables == ["target"]
    assert prompt.body.startswith("Review the findings")
    assert "---" not in prompt.body


def test_prompt_without_frontmatter_still_loads(prompts_dir):
    prompt = prompt_library.load_prompts(prompts_dir)["bare"]
    assert prompt.description == ""
    assert prompt.body.startswith("No frontmatter")


def test_empty_body_is_skipped(prompts_dir):
    assert "empty" not in prompt_library.load_prompts(prompts_dir)


def test_missing_directory_is_not_an_error(tmp_path):
    assert prompt_library.load_prompts(tmp_path / "nope") == {}


def test_search_matches_name_description_and_tags(prompts_dir):
    def names(query):
        return {p.name for p in prompt_library.search_prompts(query, prompts_dir)}

    assert names("triage") == {"triage"}
    assert names("exploitability") == {"triage"}
    assert names("reporting") == {"triage"}
    assert names("") == {"triage", "bare", "dollar"}


# ── Variables ────────────────────────────────────────────────────────────────

def test_variables_found_in_body_not_just_frontmatter(prompts_dir):
    prompt = prompt_library.load_prompts(prompts_dir)["dollar"]
    assert set(prompt.required_variables()) == {"target", "client"}


def test_declared_and_body_variables_are_deduped(prompts_dir):
    prompt = prompt_library.load_prompts(prompts_dir)["triage"]
    assert prompt.required_variables() == ["target"]


def test_missing_variables_reported(prompts_dir):
    prompt = prompt_library.load_prompts(prompts_dir)["dollar"]
    assert prompt.missing_variables({"target": "x"}) == ["client"]
    assert prompt.missing_variables({"target": "x", "client": "y"}) == []


def test_blank_value_counts_as_missing(prompts_dir):
    prompt = prompt_library.load_prompts(prompts_dir)["triage"]
    assert prompt.missing_variables({"target": ""}) == ["target"]


# ── Rendering ────────────────────────────────────────────────────────────────

def test_render_substitutes_both_syntaxes(prompts_dir):
    prompts = prompt_library.load_prompts(prompts_dir)
    assert "example.com" in prompts["triage"].render({"target": "example.com"})
    out = prompts["dollar"].render({"target": "example.com", "client": "Acme"})
    assert "example.com" in out and "Acme" in out
    assert "$TARGET" not in out


def test_render_is_case_insensitive_on_keys(prompts_dir):
    prompt = prompt_library.load_prompts(prompts_dir)["triage"]
    assert "example.com" in prompt.render({"TARGET": "example.com"})


def test_unknown_placeholders_are_left_alone():
    prompt = prompt_library.Prompt(name="x", body="keep {{unknown}} and $OTHER")
    out = prompt.render({})
    assert "{{unknown}}" in out and "$OTHER" in out


def test_strict_render_raises_on_missing(prompts_dir):
    prompt = prompt_library.load_prompts(prompts_dir)["dollar"]
    with pytest.raises(KeyError):
        prompt.render({"target": "x"}, strict=True)


def test_braces_in_body_do_not_break_rendering():
    """A prompt file is data, not a template language."""
    prompt = prompt_library.Prompt(
        name="x", body="payload: {\"a\": 1} and ${weird} and { spaced }")
    assert prompt.render({"a": "X"}) == prompt.body


def test_render_handles_none_values():
    prompt = prompt_library.Prompt(name="x", body="hi {{target}}")
    assert prompt.render({"target": None}) == "hi "


# ── Config ───────────────────────────────────────────────────────────────────

def test_prompts_dir_from_config_default():
    assert prompt_library.prompts_dir_from_config({}).name == "prompts"


def test_prompts_dir_from_config_override():
    path = prompt_library.prompts_dir_from_config({"prompts": {"dir": "custom/p"}})
    assert path.is_absolute()
    assert path.parts[-2:] == ("custom", "p")


def test_prompts_dir_tolerates_wrong_type():
    assert prompt_library.prompts_dir_from_config({"prompts": "nope"}).name == "prompts"


def test_split_list_accepts_both_forms():
    assert prompt_library._split_list("[a, b]") == ["a", "b"]
    assert prompt_library._split_list("a, b") == ["a", "b"]
    assert prompt_library._split_list(["a", "b"]) == ["a", "b"]
    assert prompt_library._split_list(None) == []


# ── Help ─────────────────────────────────────────────────────────────────────

def test_every_topic_renders():
    for topic in help_text.TOPICS:
        text = help_text.render(topic)
        assert text.strip()
        assert "unavailable" not in text.lower(), f"{topic} failed to build"


def test_default_topic_is_the_overview():
    assert help_text.render("") == help_text.render("overview")


def test_aliases_resolve():
    assert help_text.render("gates") == help_text.render("phases")
    assert help_text.render("rag") == help_text.render("memory")
    assert help_text.render("scope") == help_text.render("safety")


def test_unknown_topic_lists_what_exists():
    text = help_text.render("banana")
    assert "No help topic" in text
    for topic in help_text.TOPICS:
        assert topic in text


def test_overview_lists_every_topic():
    """The overview must not drift from the topic registry."""
    overview = help_text.render("overview")
    for topic in help_text.TOPICS:
        if topic != "overview":
            assert topic in overview, f"{topic} missing from the overview"


def test_agents_topic_is_generated_from_the_registry():
    import agents.registry as registry
    mapping = getattr(registry, "AGENT_REGISTRY", None) or getattr(registry, "AGENTS", {})
    text = help_text.render("agents")
    for name in list(mapping)[:5]:
        assert name in text


def test_phases_topic_matches_the_phase_module():
    import phases
    text = help_text.render("phases")
    for phase in phases.PHASE_ORDER:
        assert phase in text


def test_a_broken_topic_does_not_break_help(monkeypatch):
    def explode():
        raise RuntimeError("registry on fire")

    monkeypatch.setitem(help_text.TOPICS, "agents", explode)
    text = help_text.render("agents")
    assert "unavailable" in text
    assert "registry on fire" in text


def test_safety_topic_states_the_scope_default():
    """Lenient-by-default authorization must be documented, not implied."""
    text = help_text.render("safety").lower()
    assert "lenient" in text
    assert "authorization.py" in text
