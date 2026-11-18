"""
help_text.py — the built-in help section.

Everything here is generated from the live registries rather than written out
by hand, so it cannot drift from the code. If an agent is added to
``agents/registry.py`` or a capability to ``tools/registry.py``, it appears in
``help`` on the next run with no edit here.

    python cli.py help                # overview
    python cli.py help agents         # one topic
    python -m help_text phases        # same, without the CLI

Every lookup is defensive: a topic whose backing module fails to import
degrades to a short note instead of taking the help command down with it.
"""

from __future__ import annotations

import importlib
from typing import Any, Callable, Dict, List, Optional

try:
    from utils import ROOT
except ImportError:  # standalone import
    from pathlib import Path
    ROOT = Path(__file__).resolve().parent

_WIDTH = 78


# ── helpers ──────────────────────────────────────────────────────────────────

def _rule(title: str = "") -> str:
    if not title:
        return "-" * _WIDTH
    return f"{title}\n{'-' * len(title)}"


def _safe(fn: Callable[[], str], label: str) -> str:
    """Run a section builder, reporting failures instead of raising."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - help must never be the thing that breaks
        return f"({label} unavailable: {exc})"


def _wrap(items: List[str], indent: str = "  ", width: int = _WIDTH) -> str:
    lines, current = [], indent
    for item in items:
        candidate = f"{current}{item}, "
        if len(candidate) > width and current.strip():
            lines.append(current.rstrip().rstrip(","))
            current = f"{indent}{item}, "
        else:
            current = candidate
    if current.strip():
        lines.append(current.rstrip().rstrip(","))
    return "\n".join(lines)


# ── topics ───────────────────────────────────────────────────────────────────

def topic_overview() -> str:
    return f"""{_rule("CyberSwarm")}
An LLM-orchestrated assessment toolkit. Recon builds a SystemMap of a target;
a planner turns that map into an attack graph; specialist agents run the
underlying tools and a critic reviews what they report.

Two entry points:

  python run_recon_loop.py <target>     phase 1 — recon, builds the SystemMap
  python run_agent_loop.py <target>     phase 2 — planned agent execution
  python cli.py <command>               both, plus reporting and the dashboard

Help topics — `python cli.py help <topic>`:

  ask           running the tool from a plain-English request
  agents        specialist agents and what triggers each
  capabilities  recon capabilities and the tools behind them
  phases        the phase model and its quality gates
  modes         run modes and pause policy
  prompts       reusable prompts in prompts/
  skills        indexed reference material
  memory        cross-engagement RAG memory
  config        the config.yaml sections
  scripts       the helper CLIs under scripts/
  safety        scope, approval and audit behaviour
"""


def topic_ask() -> str:
    return "\n".join([
        _rule("Asking in plain English"),
        "",
        '  python cli.py ask "find the subdomains of example.com"',
        "",
        "Resolves the request to one registered capability or agent and prints",
        "it. Nothing runs. Add --execute to run it.",
        "",
        "  --execute            run the resolved capability",
        "  --min-confidence N   refuse to execute below N (default 50)",
        "",
        "What it will not do:",
        "  * emit a shell command — the model picks a name from a fixed list,",
        "    and anything not on that list is refused",
        "  * act on a target you did not write out; if the model returns a host",
        "    that is not in your text, the request is refused",
        "  * skip the checks — --execute runs authorization.is_authorized() and",
        "    the phase gate first, then hands off to the same executor the",
        "    recon loop uses. There is no second execution path.",
        "",
        "Agents are resolved but not executed here; they need the planner, so",
        "use `cli.py attack <target>`.",
    ])


def topic_agents() -> str:
    registry = importlib.import_module("agents.registry")
    mapping = getattr(registry, "AGENT_REGISTRY", None) or getattr(registry, "AGENTS", {})
    names = sorted(mapping) if isinstance(mapping, dict) else sorted(mapping)
    out = [_rule("Agents"),
           "Specialist agents the planner can schedule. Each decides for itself",
           "whether it applies to a target (`should_run`), so listing one here",
           "does not mean it runs.", "",
           f"{len(names)} registered:", _wrap(list(names)), "",
           "The planner orders them into an attack graph; agents whose entry",
           "conditions fail are marked skipped with a reason. See:",
           "  python cli.py help phases"]
    return "\n".join(out)


def topic_capabilities() -> str:
    registry = importlib.import_module("tools.registry")
    mapping = getattr(registry, "CAPABILITY_TOOL_MAP", {})
    try:
        phases = importlib.import_module("phases")
        by_phase = phases.PHASE_CAPABILITIES
        order = phases.PHASE_ORDER
    except Exception:  # noqa: BLE001
        by_phase, order = {}, []

    out = [_rule("Recon capabilities"),
           f"{len(mapping)} capabilities, each backed by one or more tools.", ""]
    seen = set()
    for phase in order:
        caps = [c for c in by_phase.get(phase, []) if c in mapping]
        if not caps:
            continue
        seen.update(caps)
        out.append(f"{phase}:")
        for cap in caps:
            tools = ", ".join(mapping.get(cap, [])) or "(no tool)"
            out.append(f"  {cap:<34} {tools}")
        out.append("")
    unmapped = sorted(set(mapping) - seen)
    if unmapped:
        out.append("Not phase-mapped (never gated):")
        for cap in unmapped:
            out.append(f"  {cap:<34} {', '.join(mapping.get(cap, []))}")
    return "\n".join(out)


def topic_phases() -> str:
    phases = importlib.import_module("phases")
    out = [_rule("Phases and quality gates"),
           "Progression: " + " -> ".join(phases.PHASE_ORDER), "",
           "Each phase declares entry gates over the evidence collected so far.",
           "Gates are a quality mechanism, not authorization: they stop a run",
           "exploiting a host it never enumerated. Target scope is enforced",
           "separately, in authorization.py.", ""]
    for phase in phases.PHASE_ORDER:
        gates = phases.PHASE_GATES.get(phase, [])
        caps = len(phases.PHASE_CAPABILITIES.get(phase, []))
        out.append(f"{phase}  ({caps} capabilities)")
        if not gates:
            out.append("  no entry gates")
        for gate in gates:
            out.append(f"  gate: {gate.name}")
        out.append("")
    out += ["Inspect or override:",
            "  python scripts/phase_ctl.py <target>",
            "  python scripts/phase_ctl.py <target> --advance",
            "  python scripts/phase_ctl.py <target> --set EXPLOITATION --force",
            "",
            "A forced transition records the failing gates in the phase history.",
            "Set phases.enabled: false in config.yaml to disable gating entirely."]
    return "\n".join(out)


def topic_modes() -> str:
    modes = importlib.import_module("modes")
    out = [_rule("Run modes and pause policy"), "",
           "--mode"]
    for mode in modes.Mode:
        described = modes.SessionPolicy(mode=mode).describe().split("(", 1)[1]
        out.append(f"  {mode.value:<10} {described.split(');')[0].rstrip(')')}")
    out += ["", "--pause"]
    for pause in modes.Pause:
        policy = modes.SessionPolicy(pause=pause)
        out.append(f"  {pause.value:<10} {policy.describe().rsplit('(', 1)[1].rstrip(')')}")
    out += ["",
            "They combine independently:",
            "  --mode auto --pause always      autonomous, but stops at every result",
            "  --mode guided                   approve each action before it runs",
            "  --auto-approve                  preserved; same as auto + never",
            "",
            "Free mode drops phase structure only. Every mode consults",
            "authorization.py identically — no mode bypasses the scope check."]
    return "\n".join(out)


def topic_prompts() -> str:
    library = importlib.import_module("prompt_library")
    prompts = library.load_prompts()
    out = [_rule("Prompts"),
           "Reusable prompts are markdown files with YAML frontmatter in",
           "prompts/. Drop a file in and it is available immediately — there is",
           "no registration step.", "",
           "  ---",
           "  description: what this prompt is for",
           "  tags: [reporting]",
           "  variables: [target]",
           "  ---",
           "  Body text, with {{target}} or $TARGET substituted at render time.",
           ""]
    if prompts:
        out.append(f"{len(prompts)} available:")
        for prompt in sorted(prompts.values(), key=lambda p: p.name):
            out.append(f"  {prompt.name:<24} {prompt.description}")
    else:
        out.append("(none found — add a .md file to prompts/)")
    out += ["", "Usage:",
            "  python scripts/prompt.py --list",
            "  python scripts/prompt.py <name> --target example.com",
            "  python scripts/prompt.py <name> --target example.com --run",
            "",
            "Without --run the rendered text is printed. With --run it is sent",
            "to the configured model with the target's evidence attached."]
    return "\n".join(out)


def topic_skills() -> str:
    rag = importlib.import_module("rag_memory")
    docs = rag.collect_skill_documents()
    roots = [str(p) for p in rag.DEFAULT_SKILLS_DIRS]
    files = sorted({d.tool for d in docs})
    out = [_rule("Skills"),
           "Markdown reference material, chunked by heading and indexed so the",
           "planner receives only the sections relevant to the current target.",
           "", "Roots scanned:"]
    out += [f"  {root}" for root in roots]
    out += ["", f"{len(docs)} sections across {len(files)} files.", "",
            "Excluded by default (no matching agent, so the advice is not",
            "actionable here):"]
    out += [f"  {pattern}" for pattern in rag.DEFAULT_SKILL_EXCLUDES]
    out += ["", "Adjust rag.skills_dir and rag.skill_excludes in config.yaml.",
            "Add your own by dropping a SKILL.md into a scanned root — no code",
            "change needed."]
    return "\n".join(out)


def topic_memory() -> str:
    rag = importlib.import_module("rag_memory")
    memory = rag.get_memory()
    try:
        count = memory.count()
    finally:
        memory.close()
    return "\n".join([
        _rule("Cross-engagement memory"),
        "Findings, tool reliability and recon outcomes from past engagements are",
        "indexed with SQLite FTS5 and the top matches are injected into the",
        "planner prompt, so a new target benefits from what earlier runs saw.",
        "",
        f"Index: {memory.db_path}",
        f"Documents: {count}",
        "",
        "  python scripts/rag_index.py             incremental reindex",
        "  python scripts/rag_index.py --stats     counts by kind and target",
        "  python scripts/rag_index.py --query 'wordpress php'",
        "  python scripts/rag_index.py --smap results/system_map/<target>.json",
        "",
        "Retrieval is global across every target in results/. Set rag.enabled",
        "to false to restore the pre-RAG planner prompt exactly.",
    ])


def topic_config() -> str:
    try:
        from utils import load_config
        config = load_config() or {}
    except Exception:  # noqa: BLE001
        config = {}
    notes = {
        "model": "backend, model name, base URL, per-role model overrides",
        "pipeline": "max agents, pivot depth, whether the LLM planner runs",
        "recon": "recon loop limits and tool timeouts",
        "attack": "attack loop limits and risk settings",
        "report": "report output directory and verbosity",
        "burp": "optional Burp Suite Professional active scanner",
        "phases": "phase gating and its coverage thresholds",
        "session": "default run mode and pause policy",
        "rag": "cross-engagement memory and skill indexing",
        "prompts": "where reusable prompts are loaded from",
    }
    out = [_rule("Configuration"), f"config.yaml at {ROOT / 'config.yaml'}", ""]
    for key in sorted(set(list(config) + list(notes))):
        present = "  " if key in config else "* "
        out.append(f"{present}{key:<12} {notes.get(key, '')}")
    out += ["", "* = documented but not currently present in your config.yaml;",
            "    defaults apply.",
            "",
            "CLI flags override config, which overrides defaults."]
    return "\n".join(out)


def topic_scripts() -> str:
    scripts = {
        "scripts/rag_index.py": "build and query the cross-engagement memory index",
        "scripts/phase_ctl.py": "inspect, advance or override the engagement phase",
        "scripts/prompt.py": "list, render and run reusable prompts",
    }
    out = [_rule("Helper scripts"), ""]
    for path, description in sorted(scripts.items()):
        exists = (ROOT / path).exists()
        marker = " " if exists else "?"
        out.append(f"{marker} {path:<26} {description}")
    out += ["", "Each takes --help.",
            "? = expected but not found in this checkout."]
    return "\n".join(out)


def topic_safety() -> str:
    return "\n".join([
        _rule("Scope, approval and audit"),
        "",
        "Target authorization  authorization.py checks a target against",
        "                      config/authorized_targets.json. It is lenient by",
        "                      default: with no file, or an empty one, targets",
        "                      are allowed. No run mode bypasses this check.",
        "",
        "Approval              Planner decisions and agent results pass through",
        "                      approval_gate.py. Guided mode prompts before each",
        "                      action; auto and free log and continue.",
        "",
        "Phase gates           Refuse to start exploitation against a target that",
        "                      was never meaningfully enumerated. Advisory —",
        "                      --force overrides and the override is recorded.",
        "",
        "Audit trail           Every decision, approved or not, is appended to",
        "                      results/decision_log.jsonl and",
        "                      results/attack_decision_log.jsonl. Forced phase",
        "                      transitions are recorded in results/phase_state/",
        "                      with the gates that were failing at the time.",
        "",
        "Only run this against systems you are authorized to test.",
    ])


TOPICS: Dict[str, Callable[[], str]] = {
    "overview": topic_overview,
    "ask": topic_ask,
    "agents": topic_agents,
    "capabilities": topic_capabilities,
    "phases": topic_phases,
    "modes": topic_modes,
    "prompts": topic_prompts,
    "skills": topic_skills,
    "memory": topic_memory,
    "config": topic_config,
    "scripts": topic_scripts,
    "safety": topic_safety,
}

ALIASES = {
    "": "overview", "help": "overview", "all": "overview",
    "agent": "agents", "capability": "capabilities", "caps": "capabilities",
    "phase": "phases", "gates": "phases", "mode": "modes", "pause": "modes",
    "prompt": "prompts", "skill": "skills", "rag": "memory",
    "settings": "config", "script": "scripts", "scope": "safety",
    "authorization": "safety", "audit": "safety",
}


def render(topic: str = "") -> str:
    """Render one help topic. Unknown topics list what is available."""
    key = ALIASES.get(str(topic or "").strip().lower(), str(topic or "").strip().lower())
    if not key:
        key = "overview"
    builder = TOPICS.get(key)
    if builder is None:
        return (f"No help topic {topic!r}.\n\nAvailable: "
                + ", ".join(sorted(TOPICS)) + "\n")
    return _safe(builder, f"help topic {key!r}")


def main(argv: Optional[List[str]] = None) -> int:
    import sys
    args = list(argv if argv is not None else sys.argv[1:])
    print(render(args[0] if args else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
