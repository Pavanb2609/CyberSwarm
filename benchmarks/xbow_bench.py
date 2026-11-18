#!/usr/bin/env python3
"""
xbow_bench.py — run CyberSwarm against the XBOW validation benchmarks.

    # what fraction of the suite is even addressable (no Docker needed)
    python benchmarks/xbow_bench.py --repo ../validation-benchmarks --coverage

    # one benchmark, to check the plumbing before committing hours
    python benchmarks/xbow_bench.py --repo ../validation-benchmarks --only XBEN-001-24

    # the full suite
    python benchmarks/xbow_bench.py --repo ../validation-benchmarks

    # A/B: does difficulty-aware planning actually help?
    python benchmarks/xbow_bench.py --repo ../validation-benchmarks \\
        --variant baseline --variant no-difficulty --variant no-rag

Scoring is detection, not flag capture -- see benchmarks/taxonomy.py for why
and for the classes that are out of scope.

Requirements on the machine that runs this: Docker with compose, a reachable
model backend, and the benchmark repo checked out. Roughly 40% of the upstream
images have bit-rotted; the MAPTA and Keygraph forks publish fixes, and
``--skip-broken`` keeps a failed build from stopping the run.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks import scoring, taxonomy  # noqa: E402

DEFAULT_TIMEOUT = 900
_PORT_RE = re.compile(r"0\.0\.0\.0:(\d+)->|:::(\d+)->")


# ── Benchmark discovery ──────────────────────────────────────────────────────

def load_benchmarks(repo: Path) -> List[Dict[str, Any]]:
    """Read every benchmark.json under <repo>/benchmarks."""
    root = Path(repo) / "benchmarks"
    if not root.is_dir():
        root = Path(repo)
    out: List[Dict[str, Any]] = []
    for meta_path in sorted(root.glob("*/benchmark.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"  ! unreadable {meta_path}: {exc}", file=sys.stderr)
            continue
        out.append({
            "id": meta_path.parent.name,
            "path": meta_path.parent,
            "name": meta.get("name", meta_path.parent.name),
            "level": str(meta.get("level", "")),
            "tags": [str(t).lower() for t in (meta.get("tags") or [])],
        })
    return out


# ── Docker lifecycle ─────────────────────────────────────────────────────────

class DockerRunner:
    """Builds, starts and stops one benchmark's compose stack."""

    def __init__(self, flag: str = "flag{cyberswarm-bench}", quiet: bool = True):
        self.flag = flag
        self.quiet = quiet

    def available(self) -> bool:
        return shutil.which("docker") is not None

    def _run(self, args: Sequence[str], cwd: Path, timeout: int = 600):
        return subprocess.run(list(args), cwd=str(cwd), capture_output=True,
                              text=True, timeout=timeout, errors="replace")

    def build(self, path: Path) -> Optional[str]:
        proc = self._run(["docker", "compose", "build",
                          "--build-arg", f"FLAG={self.flag}",
                          "--build-arg", f"flag={self.flag}"], path, timeout=1800)
        return None if proc.returncode == 0 else (proc.stderr or proc.stdout)[-400:]

    def up(self, path: Path) -> Optional[str]:
        # Remove stray containers from previous benchmark runs first: a
        # leftover stack binds its app port on localhost VM-wide, and nmap/
        # content discovery inside the next benchmark can then race against
        # the WRONG surface (observed: XBEN-006 leftover on :8000 while
        # XBEN-076 ran on :32772, giving port-8000 results inside its map).
        try:
            strays = subprocess.run(
                ["docker", "ps", "-aq", "--filter", "name=xben-"],
                capture_output=True, text=True, timeout=60, errors="replace")
            for cid in (strays.stdout or "").split():
                subprocess.run(["docker", "rm", "-f", cid], capture_output=True,
                               timeout=60)
        except (subprocess.SubprocessError, OSError):
            pass
        proc = self._run(["docker", "compose", "up", "-d", "--wait"], path, timeout=600)
        return None if proc.returncode == 0 else (proc.stderr or proc.stdout)[-400:]

    def down(self, path: Path) -> None:
        self._run(["docker", "compose", "down", "-v", "--remove-orphans"],
                  path, timeout=300)

    def published_port(self, path: Path) -> Optional[int]:
        """First host port the stack published, which is the app under test."""
        proc = self._run(["docker", "compose", "ps", "--format", "json"], path)
        if proc.returncode != 0:
            return None
        ports: List[int] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            records = entry if isinstance(entry, list) else [entry]
            for record in records:
                # New compose (2.x containersd): "Publishers" is a list of dicts
                pubs = record.get("Publishers")
                if isinstance(pubs, list):
                    for pub in pubs:
                        try:
                            port = int(pub.get("PublishedPort") or 0)
                        except (TypeError, ValueError):
                            continue
                        if port > 0:  # -1/0 = not actually published
                            ports.append(port)
                # Legacy string form: "0.0.0.0:8000->80/tcp"
                for match in _PORT_RE.finditer(str(record.get("Ports", ""))):
                    value = match.group(1) or match.group(2)
                    if value:
                        ports.append(int(value))
        return min(ports) if ports else None


# ── Variants ─────────────────────────────────────────────────────────────────

VARIANTS: Dict[str, Dict[str, Any]] = {
    "baseline": {},
    "no-difficulty": {"difficulty": {"enabled": False}},
    "no-rag": {"rag": {"enabled": False}},
    "no-skills": {"rag": {"index_skills": False}},
    "no-llm-planner": {"pipeline": {"llm_planner": False}},
    "no-guardrails": {"pipeline": {"guardrails": False}},
    "minimal": {"difficulty": {"enabled": False}, "rag": {"enabled": False}},
}


def variant_env(name: str) -> Dict[str, str]:
    """Config overrides as environment variables the run loops already read."""
    overrides = VARIANTS.get(name, {})
    env: Dict[str, str] = {}
    if overrides.get("difficulty", {}).get("enabled") is False:
        env["CYBERSWARM_DIFFICULTY_ENABLED"] = "0"
    if overrides.get("rag", {}).get("enabled") is False:
        env["CYBERSWARM_RAG_ENABLED"] = "0"
    if overrides.get("rag", {}).get("index_skills") is False:
        env["CYBERSWARM_RAG_INDEX_SKILLS"] = "0"
    if overrides.get("pipeline", {}).get("llm_planner") is False:
        env["CYBERSWARM_NO_LLM_PLANNER"] = "1"
    if overrides.get("pipeline", {}).get("guardrails") is False:
        env["CYBERSWARM_GUARDRAILS"] = "0"
    return env


# ── Running one benchmark ────────────────────────────────────────────────────

def read_findings(root: Path, target: str) -> List[Dict[str, Any]]:
    path = root / "results" / "attack_evidence" / f"{target}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return list(data.get("vulnerabilities") or []) if isinstance(data, dict) else []


def run_cyberswarm(root: Path, url: str, timeout: int,
                   env_extra: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Recon then attack against a URL. Returns an error string or None."""
    import os

    # Discard any stored engagement state for this host so every benchmark
    # starts from a clean slate (otherwise recon replays cached evidence from
    # the previous benchmark that used localhost:<other-port>).
    host = urllib.parse.urlparse(url).hostname or url
    for pattern in (root / "results" / "attack_evidence" / f"{host}.json",
                    root / "results" / "evidence" / f"{host}.json",
                    root / "results" / "system_map" / f"{host}.json"):
        try:
            pattern.unlink()
        except OSError:
            pass
    try:
        shutil.rmtree(root / "results" / "engagements" / host)
    except OSError:
        pass

    env = dict(os.environ)
    env.update(env_extra or {})
    for stage in (["recon", url, "--auto-approve", "--run-all"],
                  ["attack", url, "--auto-approve", "--force"]):
        proc = subprocess.run([sys.executable, "cli.py", *stage], cwd=str(root),
                              capture_output=True, text=True, timeout=timeout,
                              env=env, errors="replace")
        if proc.returncode != 0:
            return f"{stage[0]} failed: {(proc.stderr or proc.stdout)[-300:]}"
    return None


def run_one(bench: Dict[str, Any], root: Path, docker: DockerRunner,
            timeout: int, variant: str,
            keep_up: bool = False) -> scoring.BenchmarkResult:
    started = time.time()
    path = bench["path"]

    error = docker.build(path)
    if error:
        return scoring.score_benchmark(bench["id"], bench["tags"], [],
                                       bench["level"], time.time() - started,
                                       error=f"build failed: {error}")
    error = docker.up(path)
    if error:
        docker.down(path)
        return scoring.score_benchmark(bench["id"], bench["tags"], [],
                                       bench["level"], time.time() - started,
                                       error=f"start failed: {error}")
    try:
        port = docker.published_port(path)
        if not port:
            return scoring.score_benchmark(
                bench["id"], bench["tags"], [], bench["level"],
                time.time() - started, error="no published port found")

        url = f"http://localhost:{port}"
        run_error = run_cyberswarm(root, url, timeout, variant_env(variant))
        findings = read_findings(root, "localhost")
        # Persist the raw findings so scoring can be recomputed offline if a
        # taxonomy/mapping bug is found later (the shared localhost.json is
        # overwritten by the next run otherwise).
        try:
            import json as _json
            import os as _os
            ev_dir = Path(_os.environ.get("CYBERSWARM_XBOW_OUT", "results/xbow/matrix"))
            ev_dir.mkdir(parents=True, exist_ok=True)
            (ev_dir / f"evidence_{variant}_{bench['id']}.json").write_text(
                _json.dumps(findings, indent=1, default=str), encoding="utf-8")
        except OSError:
            pass
        return scoring.score_benchmark(bench["id"], bench["tags"], findings,
                                       bench["level"], time.time() - started,
                                       error=run_error or "")
    finally:
        if not keep_up:
            docker.down(path)


# ── Entry point ──────────────────────────────────────────────────────────────

def cmd_coverage(benches: List[Dict[str, Any]]) -> int:
    """Ceiling analysis. Needs no Docker and no model."""
    counts: Dict[str, int] = {}
    for bench in benches:
        for tag in bench["tags"]:
            counts[tag] = counts.get(tag, 0) + 1

    report = taxonomy.coverage_report(counts)
    addressable = [b for b in benches
                   if any(taxonomy.in_scope(t) for t in b["tags"])]

    print(f"Benchmarks                : {len(benches)}")
    print(f"With an in-scope class    : {len(addressable)} "
          f"({len(addressable) / max(1, len(benches)):.1%})")
    print(f"Tag instances             : {report['total_tags']}")
    print(f"  addressable             : {report['in_scope']}")
    print(f"  structurally unreachable: {report['out_of_scope']}")
    print(f"\nMaximum achievable tag recall: {report['ceiling']:.1%}\n")

    print("Addressable classes:")
    for tag, n in report["covered_tags"].items():
        print(f"  {n:3}  {tag}")
    print("\nUnreachable classes:")
    for tag, n in report["uncovered_tags"].items():
        print(f"  {n:3}  {tag:24} {report['reasons'].get(tag, '')}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run CyberSwarm against the XBOW validation benchmarks.")
    parser.add_argument("--repo", required=True,
                        help="path to a validation-benchmarks checkout")
    parser.add_argument("--only", action="append", default=None,
                        help="benchmark id to run (repeatable)")
    parser.add_argument("--level", action="append", default=None,
                        help="restrict to difficulty level 1, 2 or 3")
    parser.add_argument("--variant", action="append", default=None,
                        choices=sorted(VARIANTS), help="config variant (repeatable)")
    parser.add_argument("--coverage", action="store_true",
                        help="print the ceiling analysis and exit")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"per-stage timeout in seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--limit", type=int, default=0, help="stop after N benchmarks")
    parser.add_argument("--out", default="results/benchmarks",
                        help="where to write reports")
    parser.add_argument("--keep-up", action="store_true",
                        help="leave containers running (debugging)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    benches = load_benchmarks(Path(args.repo).expanduser())
    if not benches:
        print(f"No benchmarks found under {args.repo}", file=sys.stderr)
        return 1

    if args.only:
        wanted = {b.upper() for b in args.only}
        benches = [b for b in benches if b["id"].upper() in wanted]
    if args.level:
        levels = {str(l) for l in args.level}
        benches = [b for b in benches if b["level"] in levels]
    if args.limit:
        benches = benches[:args.limit]

    if args.coverage:
        return cmd_coverage(benches)

    docker = DockerRunner()
    if not docker.available():
        print("Docker is not installed; the benchmarks cannot be started here.\n"
              "Use --coverage for the ceiling analysis, which needs no Docker.",
              file=sys.stderr)
        return 2

    out_dir = root / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    variants = args.variant or ["baseline"]
    aggregates: Dict[str, scoring.Aggregate] = {}

    for variant in variants:
        results: List[scoring.BenchmarkResult] = []
        # Resume support: skip benchmarks already scored in a previous
        # (possibly interrupted) run of this variant.
        prior = out_dir / f"{variant}.json"
        if prior.exists():
            try:
                prior_data = json.loads(prior.read_text(encoding="utf-8"))
                results = [scoring.BenchmarkResult.from_dict(r) for r in prior_data]
                done = {r.benchmark for r in results}
            except (json.JSONDecodeError, AttributeError, TypeError):
                results, done = [], set()
        else:
            done = set()
        if done:
            print(f"[resume] {variant}: {len(done)} already scored, skipping them")
        pending = [b for b in benches if b["id"] not in done]
        print(f"\n=== variant: {variant} ({len(pending)} of {len(benches)} "
              f"benchmarks to run) ===")
        for index, bench in enumerate(pending, 1):
            print(f"[{index}/{len(pending)}] {bench['id']} "
                  f"({', '.join(bench['tags']) or 'untagged'}) ... ", end="", flush=True)
            try:
                result = run_one(bench, root, docker, args.timeout, variant,
                                 args.keep_up)
            except subprocess.TimeoutExpired:
                result = scoring.score_benchmark(bench["id"], bench["tags"], [],
                                                 bench["level"], args.timeout,
                                                 error="timed out")
                docker.down(bench["path"])
            except KeyboardInterrupt:
                print("\ninterrupted; tearing down")
                docker.down(bench["path"])
                return 130
            results.append(result)
            print("ERROR" if result.error else
                  ("solved" if result.solved else
                   f"{len(result.hits)}/{len(result.expected)}"))

            # Written every iteration so an interrupted run keeps its data.
            (out_dir / f"{variant}.json").write_text(
                json.dumps([r.to_dict() for r in results], indent=2),
                encoding="utf-8")

        agg = scoring.aggregate(results)
        aggregates[variant] = agg
        report = scoring.format_report(results, agg, variant)
        (out_dir / f"{variant}.md").write_text(report, encoding="utf-8")
        print("\n" + report)

    if len(aggregates) > 1:
        table = scoring.compare(aggregates)
        (out_dir / "comparison.md").write_text(table, encoding="utf-8")
        print("\n## Variant comparison\n")
        print(table)

    print(f"\nReports written to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
