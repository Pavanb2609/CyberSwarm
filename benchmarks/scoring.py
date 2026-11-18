"""
scoring.py — detection metrics for a benchmark run.

Given a benchmark's ground-truth tags and the findings CyberSwarm reported,
produce the numbers a reviewer will ask for:

    recall       of the vulnerability classes present, how many were reported
    precision    of the classes reported, how many were actually present
    F1           harmonic mean of the two
    fp_rate      reported-but-absent classes per benchmark

Precision matters as much as recall here, and is the easier one to game: a
system that reports every class on every target scores perfect recall and is
useless. Reporting both, always, is the point.

Out-of-scope classes are excluded from the denominators and counted
separately, so the headline recall describes what the system was capable of
detecting rather than being dragged down by classes it structurally cannot
reach.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from . import taxonomy


@dataclass
class BenchmarkResult:
    """One benchmark's outcome."""

    benchmark: str
    level: str = ""
    expected: Set[str] = field(default_factory=set)      # in-scope ground truth
    skipped: Set[str] = field(default_factory=set)       # out-of-scope truth
    detected: Set[str] = field(default_factory=set)      # classes reported
    findings: int = 0
    confirmed_findings: int = 0
    duration_s: float = 0.0
    error: str = ""

    @property
    def hits(self) -> Set[str]:
        """Expected classes for which equivalent evidence was reported."""
        return {tag for tag in self.expected
                if taxonomy.family(tag) & self.detected}

    @property
    def misses(self) -> Set[str]:
        return self.expected - self.hits

    @property
    def false_positives(self) -> Set[str]:
        """Reported classes that are not in the ground truth at all.

        Out-of-scope truth tags are subtracted: if a benchmark is tagged
        ``privilege_escalation`` and the system reports something adjacent,
        that is not a clean false positive.
        """
        accounted: Set[str] = set()
        for tag in self.expected | self.skipped:
            accounted |= taxonomy.family(tag)
        return self.detected - accounted

    @property
    def solved(self) -> bool:
        """True when every in-scope class present was reported."""
        return bool(self.expected) and not self.misses

    def to_dict(self) -> Dict[str, Any]:
        return {
            "benchmark": self.benchmark, "level": self.level,
            "expected": sorted(self.expected), "skipped": sorted(self.skipped),
            "detected": sorted(self.detected), "hits": sorted(self.hits),
            "misses": sorted(self.misses),
            "false_positives": sorted(self.false_positives),
            "solved": self.solved, "findings": self.findings,
            "confirmed_findings": self.confirmed_findings,
            "duration_s": round(self.duration_s, 1), "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BenchmarkResult":
        """Rehydrate from ``to_dict`` (resume support for interrupted runs)."""
        return cls(
            benchmark=data.get("benchmark", ""),
            level=str(data.get("level", "")),
            expected=set(data.get("expected", [])),
            skipped=set(data.get("skipped", [])),
            detected=set(data.get("detected", [])),
            findings=int(data.get("findings", 0)),
            confirmed_findings=int(data.get("confirmed_findings", 0)),
            duration_s=float(data.get("duration_s", 0.0)),
            error=str(data.get("error", "")),
        )


def detections_from_findings(findings: Iterable[Any]) -> Set[str]:
    """Map a run's findings onto vulnerability classes."""
    classes: Set[str] = set()
    for finding in findings or []:
        if isinstance(finding, dict):
            name = finding.get("name", "")
            description = finding.get("description", "")
            tool = finding.get("tool", "")
            agent = finding.get("source_agent", "")
        else:
            name = getattr(finding, "name", "")
            description = getattr(finding, "description", "")
            tool = getattr(finding, "tool", "")
            agent = getattr(finding, "source_agent", "")
        classes |= taxonomy.classify_finding(name, description, tool, agent)
    return classes


def score_benchmark(name: str, tags: Sequence[str], findings: Iterable[Any],
                    level: str = "", duration_s: float = 0.0,
                    error: str = "") -> BenchmarkResult:
    """Score one benchmark from its tags and the findings produced."""
    tags = [str(t).strip().lower() for t in (tags or []) if str(t).strip()]
    expected = {t for t in tags if taxonomy.in_scope(t)}
    skipped = {t for t in tags if not taxonomy.in_scope(t)}

    materialised = list(findings or [])
    confirmed = [f for f in materialised
                 if str((f.get("verdict") if isinstance(f, dict)
                         else getattr(f, "verdict", "")) or "").upper() == "CONFIRM"]

    return BenchmarkResult(
        benchmark=name, level=str(level), expected=expected, skipped=skipped,
        detected=detections_from_findings(materialised),
        findings=len(materialised), confirmed_findings=len(confirmed),
        duration_s=duration_s, error=error)


@dataclass
class Aggregate:
    """Suite-level metrics."""

    benchmarks: int = 0
    scored: int = 0                 # had at least one in-scope class
    excluded: int = 0               # entirely out of scope
    errored: int = 0
    solved: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    per_class: Dict[str, Dict[str, int]] = field(default_factory=dict)
    total_duration_s: float = 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 3) if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 3) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 3) if (p + r) else 0.0

    @property
    def solve_rate(self) -> float:
        return round(self.solved / self.scored, 3) if self.scored else 0.0

    @property
    def fp_per_benchmark(self) -> float:
        return round(self.false_positives / self.scored, 2) if self.scored else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "benchmarks": self.benchmarks, "scored": self.scored,
            "excluded_out_of_scope": self.excluded, "errored": self.errored,
            "solved": self.solved, "solve_rate": self.solve_rate,
            "recall": self.recall, "precision": self.precision, "f1": self.f1,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "false_positives_per_benchmark": self.fp_per_benchmark,
            "total_duration_s": round(self.total_duration_s, 1),
            "per_class": self.per_class,
        }


def aggregate(results: Sequence[BenchmarkResult]) -> Aggregate:
    out = Aggregate(benchmarks=len(results))
    for result in results:
        out.total_duration_s += result.duration_s
        if result.error:
            out.errored += 1
            continue
        if not result.expected:
            # Nothing detectable was present; scoring it would only distort.
            out.excluded += 1
            continue

        out.scored += 1
        out.true_positives += len(result.hits)
        out.false_negatives += len(result.misses)
        out.false_positives += len(result.false_positives)
        if result.solved:
            out.solved += 1

        for tag in result.expected:
            entry = out.per_class.setdefault(tag, {"present": 0, "detected": 0})
            entry["present"] += 1
            if tag in result.hits:
                entry["detected"] += 1
    return out


def format_report(results: Sequence[BenchmarkResult], agg: Aggregate,
                  variant: str = "baseline") -> str:
    """Human-readable summary. Precision is printed beside recall, always."""
    lines = [
        f"# Detection benchmark — {variant}",
        "",
        "Scored on vulnerability-class detection, not flag capture. CyberSwarm",
        "has no session layer, so XBOW's own exploitation scoring does not apply.",
        "",
        f"Benchmarks run        : {agg.benchmarks}",
        f"  scored              : {agg.scored}",
        f"  excluded (no in-scope class): {agg.excluded}",
        f"  errored             : {agg.errored}",
        "",
        f"Fully detected        : {agg.solved}/{agg.scored}  ({agg.solve_rate:.1%})",
        f"Recall                : {agg.recall:.1%}",
        f"Precision             : {agg.precision:.1%}",
        f"F1                    : {agg.f1:.3f}",
        f"False positives       : {agg.false_positives} "
        f"({agg.fp_per_benchmark} per benchmark)",
        f"Total runtime         : {agg.total_duration_s / 60:.1f} min",
        "",
        "## Per class",
        "",
        "| class | present | detected | recall |",
        "|---|---|---|---|",
    ]
    for tag, entry in sorted(agg.per_class.items(),
                             key=lambda kv: -kv[1]["present"]):
        rate = entry["detected"] / entry["present"] if entry["present"] else 0.0
        lines.append(f"| {tag} | {entry['present']} | {entry['detected']} | {rate:.0%} |")

    failures = [r for r in results if r.error]
    if failures:
        lines += ["", "## Errors", ""]
        lines += [f"- {r.benchmark}: {r.error}" for r in failures[:20]]
    return "\n".join(lines)


def compare(variants: Dict[str, Aggregate]) -> str:
    """A/B table across configurations (difficulty on/off, RAG on/off ...)."""
    if not variants:
        return "(no variants)"
    lines = ["| variant | solved | recall | precision | F1 | FP/bench | runtime |",
             "|---|---|---|---|---|---|---|"]
    for name, agg in variants.items():
        lines.append(
            f"| {name} | {agg.solved}/{agg.scored} | {agg.recall:.1%} | "
            f"{agg.precision:.1%} | {agg.f1:.3f} | {agg.fp_per_benchmark} | "
            f"{agg.total_duration_s / 60:.1f} min |")
    return "\n".join(lines)
