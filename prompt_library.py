"""
prompt_library.py — reusable prompts as markdown files.

A prompt is a markdown file with YAML frontmatter:

    ---
    description: Summarise the engagement for a non-technical reader
    tags: [reporting]
    variables: [target]
    ---
    Summarise the findings for {{target}} in plain language...

Drop a file into ``prompts/`` and it becomes available immediately — there is
no registration step and no code change, which is the whole point. Prompts are
rendered (variables substituted) and handed to a model, or printed for you to
paste somewhere else.

Rendering is deliberately dumb: ``{{name}}`` and ``$NAME`` are replaced with
supplied values, and nothing else happens. A prompt file is data, not a
template language, so a stray brace in a payload example cannot break a run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:
    from utils import ROOT, get_logger
except ImportError:  # standalone import
    ROOT = Path(__file__).resolve().parent
    import logging

    def get_logger(name: str):  # type: ignore[misc]
        return logging.getLogger(name)

log = get_logger("prompt_library")

DEFAULT_PROMPTS_DIR = ROOT / "prompts"

_BRACE_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_DOLLAR_RE = re.compile(r"\$([A-Z_][A-Z0-9_]*)\b")


@dataclass
class Prompt:
    """One prompt file."""

    name: str
    body: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    variables: List[str] = field(default_factory=list)
    path: Optional[Path] = None

    def required_variables(self) -> List[str]:
        """Variables declared in frontmatter plus any found in the body."""
        found = list(self.variables)
        for match in _BRACE_RE.findall(self.body):
            if match not in found:
                found.append(match)
        for match in _DOLLAR_RE.findall(self.body):
            lowered = match.lower()
            if lowered not in found and match not in found:
                found.append(lowered)
        return found

    def missing_variables(self, values: Dict[str, Any]) -> List[str]:
        supplied = {k.lower() for k, v in (values or {}).items() if v not in (None, "")}
        return [v for v in self.required_variables() if v.lower() not in supplied]

    def render(self, values: Optional[Dict[str, Any]] = None,
               strict: bool = False) -> str:
        """Substitute variables. Unknown placeholders are left untouched.

        ``strict=True`` raises when a declared variable has no value, which is
        what the CLI uses so a half-filled prompt is never sent to a model.
        """
        values = {str(k).lower(): "" if v is None else str(v)
                  for k, v in (values or {}).items()}
        if strict:
            missing = self.missing_variables(values)
            if missing:
                raise KeyError(f"missing values for: {', '.join(missing)}")

        def brace(match: re.Match) -> str:
            return values.get(match.group(1).lower(), match.group(0))

        def dollar(match: re.Match) -> str:
            return values.get(match.group(1).lower(), match.group(0))

        return _DOLLAR_RE.sub(dollar, _BRACE_RE.sub(brace, self.body))

    def summary(self) -> str:
        tags = f"  [{', '.join(self.tags)}]" if self.tags else ""
        return f"{self.name:<24} {self.description}{tags}"


# ── Loading ──────────────────────────────────────────────────────────────────

def _split_list(value: Any) -> List[str]:
    """Parse ``[a, b]`` or ``a, b`` into a list of strings."""
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value or "").strip().strip("[]")
    return [part.strip().strip("'\"") for part in text.split(",") if part.strip()]


def load_prompt(path: Path) -> Optional[Prompt]:
    """Read one prompt file. Returns None if it cannot be read."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        log.debug("Skipping unreadable prompt %s: %s", path, exc)
        return None

    # Reuse the skill frontmatter parser so both features accept one format.
    try:
        from rag_memory import parse_frontmatter
        meta, body = parse_frontmatter(raw)
    except ImportError:
        meta, body = {}, raw

    body = body.strip()
    if not body:
        return None

    return Prompt(
        name=meta.get("name") or path.stem,
        body=body,
        description=meta.get("description", ""),
        tags=_split_list(meta.get("tags")),
        variables=_split_list(meta.get("variables")),
        path=path,
    )


def load_prompts(prompts_dir: Optional[Path | str] = None) -> Dict[str, Prompt]:
    """Load every prompt under ``prompts_dir``, keyed by name."""
    root = Path(prompts_dir) if prompts_dir else DEFAULT_PROMPTS_DIR
    prompts: Dict[str, Prompt] = {}
    if not root.exists():
        log.debug("Prompts dir %s does not exist", root)
        return prompts
    for path in sorted(root.rglob("*.md")):
        prompt = load_prompt(path)
        if prompt is None:
            continue
        if prompt.name in prompts:
            log.warning("Duplicate prompt name %r (%s shadows %s)",
                        prompt.name, path, prompts[prompt.name].path)
        prompts[prompt.name] = prompt
    return prompts


def get_prompt(name: str, prompts_dir: Optional[Path | str] = None) -> Optional[Prompt]:
    return load_prompts(prompts_dir).get(str(name))


def search_prompts(query: str, prompts_dir: Optional[Path | str] = None) -> List[Prompt]:
    """Substring match over name, description and tags."""
    needle = str(query or "").strip().lower()
    prompts = list(load_prompts(prompts_dir).values())
    if not needle:
        return prompts
    return [p for p in prompts
            if needle in p.name.lower()
            or needle in p.description.lower()
            or any(needle in t.lower() for t in p.tags)]


def prompts_dir_from_config(config: Optional[Dict[str, Any]] = None) -> Path:
    if config is None:
        try:
            from utils import load_config
            config = load_config()
        except Exception:  # noqa: BLE001
            config = {}
    section = (config or {}).get("prompts") or {}
    if not isinstance(section, dict):
        section = {}
    configured = Path(section.get("dir") or DEFAULT_PROMPTS_DIR)
    return configured if configured.is_absolute() else (ROOT / configured)
