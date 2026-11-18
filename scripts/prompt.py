#!/usr/bin/env python3
"""
prompt.py — list, render and run the prompts in prompts/.

    python scripts/prompt.py --list
    python scripts/prompt.py --list --search reporting
    python scripts/prompt.py triage-findings --target example.com
    python scripts/prompt.py triage-findings --target example.com --run
    python scripts/prompt.py report-exec-summary -v target=example.com -v client=Acme

Without ``--run`` the rendered prompt is printed, so you can pipe it somewhere
else or paste it into another tool. With ``--run`` it is sent to the configured
model, with the target's evidence attached as context when it exists.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import prompt_library  # noqa: E402

try:
    from utils import ROOT, load_config
except ImportError:  # pragma: no cover
    ROOT = Path(__file__).resolve().parent.parent

    def load_config():  # type: ignore[misc]
        return {}


def _parse_vars(pairs) -> dict:
    values = {}
    for item in pairs or []:
        key, sep, value = str(item).partition("=")
        if not sep:
            print(f"Ignoring malformed --var {item!r}; expected key=value",
                  file=sys.stderr)
            continue
        values[key.strip().lower()] = value.strip()
    return values


def _evidence_context(target: str, limit: int = 12000) -> str:
    """Attach whatever the pipeline already knows about the target."""
    chunks = []
    for label, path in (
            ("recon evidence", ROOT / "results" / "evidence" / f"{target}.json"),
            ("attack evidence", ROOT / "results" / "attack_evidence" / f"{target}.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        chunks.append(f"## {label}\n```json\n"
                      f"{json.dumps(data, indent=1)[:limit]}\n```")
    return "\n\n".join(chunks)


def cmd_list(prompts, search: str) -> int:
    items = (prompt_library.search_prompts(search, prompts_dir=None)
             if search else list(prompts.values()))
    if not items:
        print("(no prompts matched)" if search else
              "(no prompts found — add a .md file to prompts/)")
        return 0
    for prompt in sorted(items, key=lambda p: p.name):
        print(prompt.summary())
        needed = prompt.required_variables()
        if needed:
            print(f"{'':<24} variables: {', '.join(needed)}")
    print(f"\n{len(items)} prompt(s).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List, render and run reusable prompts.")
    parser.add_argument("name", nargs="?", help="prompt to render")
    parser.add_argument("--list", action="store_true", help="list available prompts")
    parser.add_argument("--search", default="", help="filter --list by keyword")
    parser.add_argument("--target", default=None, help="shorthand for -v target=...")
    parser.add_argument("-v", "--var", action="append", dest="variables",
                        metavar="KEY=VALUE", help="supply a variable (repeatable)")
    parser.add_argument("--run", action="store_true",
                        help="send the rendered prompt to the configured model")
    parser.add_argument("--no-context", action="store_true",
                        help="with --run, do not attach the target's evidence")
    parser.add_argument("--dir", default=None, help="override the prompts directory")
    args = parser.parse_args()

    config = load_config()
    prompts_dir = Path(args.dir) if args.dir else \
        prompt_library.prompts_dir_from_config(config)
    prompts = prompt_library.load_prompts(prompts_dir)

    if args.list or not args.name:
        return cmd_list(prompts, args.search)

    prompt = prompts.get(args.name)
    if prompt is None:
        print(f"No prompt named {args.name!r}. Try --list.", file=sys.stderr)
        close = [n for n in prompts if args.name.lower() in n.lower()]
        if close:
            print(f"Did you mean: {', '.join(close)}", file=sys.stderr)
        return 1

    values = _parse_vars(args.variables)
    if args.target:
        values.setdefault("target", args.target)

    try:
        rendered = prompt.render(values, strict=True)
    except KeyError as exc:
        print(f"{exc}\nSupply them with --target or -v key=value.", file=sys.stderr)
        return 1

    if not args.run:
        print(rendered)
        return 0

    target = values.get("target", "")
    if target and not args.no_context:
        context = _evidence_context(target)
        if context:
            rendered = f"{rendered}\n\n# Engagement context\n\n{context}"
        else:
            print(f"[note] no stored evidence for {target}; running without context",
                  file=sys.stderr)

    try:
        from model_client import ModelClient
    except ImportError as exc:
        print(f"Cannot run: {exc}", file=sys.stderr)
        return 1

    client = ModelClient(config=config) if _accepts_config() else ModelClient()
    print(client.chat("You are assisting with an authorized security assessment. "
                      "Answer only from the evidence provided.", rendered))
    return 0


def _accepts_config() -> bool:
    try:
        import inspect
        from model_client import ModelClient
        return "config" in inspect.signature(ModelClient.__init__).parameters
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # Piping into head/less closes stdout early; that is not an error.
        try:
            sys.stdout.close()
        finally:
            raise SystemExit(0)
