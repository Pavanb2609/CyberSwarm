"""
verdict.py -- shared evidence-honesty helpers for active attack tools.

A finding's severity and confidence MUST be *derived* from the proof criteria
that were actually met -- never from a magic constant. A finding with zero
matched proof criteria is not a finding (each tool decides which criteria are
decisive enough to emit at all).

Every tool that uses these helpers keeps its criteria tree + weights next to
the call site so a reader can see exactly what evidence backs a verdict.
"""

FLOOR = 50
CAP = 96


def confidence_from_criteria(criteria_met, weights, floor=FLOOR, cap=CAP):
    """Confidence derived from matched proof criteria.

    Returns 0 when nothing matched (callers should treat 0 as "not a finding").
    The floor means a single weak criterion stays a low-confidence
    "possible" and only a full criteria stack approaches the cap.
    """
    met = [c for c in (criteria_met or []) if weights.get(c)]
    if not met:
        return 0
    return min(int(floor + sum(weights[c] for c in met)), cap)


def criteria_label(criteria_met, hints):
    """Human-readable list of which proof criteria a verdict rested on."""
    labels = [hints[c] for c in (criteria_met or []) if c in hints]
    return ", ".join(labels) if labels else "no proof criteria met"


# Markers re-used by several attack tools (kept in one place so the server
# fingerprints stay consistent across the codebase).
SQL_ERROR_MARKER = (
    r"SQL syntax|You have an error in your SQL|ORA-0|Mysql_|SQLiteException|"
    r"near \"[^\"]*\": syntax error|unclosed quotation|"
    r"quoted string not properly terminated|unterminated quoted string|"
    r"PG::SyntaxError|psycopg2|SQLSTATE"
)
PASSWD_ENTRIES_MARKER = r"(?m)^[A-Za-z0-9_.-]+:x:[0-9]+:[0-9]+:"
CMD_EXEC_MARKER = r"uid=\d+\(|whoami|id enabled"