#!/usr/bin/env python3
"""
rag_index.py — manage the cross-engagement RAG memory index.

    python scripts/rag_index.py                     # incremental reindex
    python scripts/rag_index.py --full              # wipe + rebuild
    python scripts/rag_index.py --list              # dump indexed documents
    python scripts/rag_index.py --list --kind tool  # filter by kind
    python scripts/rag_index.py --stats             # counts by kind/target
    python scripts/rag_index.py --query "wordpress php mysql" -k 5
    python scripts/rag_index.py --smap results/system_map/example.com.json

The last two are the useful ones when a planner run produced surprising
lessons: --query checks the retriever directly, --smap runs the exact query
the planner would build from a stored SystemMap.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import rag_memory as rag  # noqa: E402


def cmd_list(mem: rag.RagMemory, kind: str | None, limit: int) -> int:
    conn = mem.connect(create=False)
    if conn is None:
        print("No index found. Run without --list to build one.", file=sys.stderr)
        return 1
    sql = ("SELECT doc_key, kind, target, capability, tool, severity, body "
           "FROM documents")
    params: list = []
    if kind:
        sql += " WHERE kind = ?"
        params.append(kind)
    sql += " ORDER BY kind, target, doc_key LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    if not rows:
        print("(index is empty)")
        return 0
    for row in rows:
        meta = " ".join(filter(None, [
            row["target"], row["capability"], row["tool"], row["severity"]]))
        print(f"[{row['kind']:<8}] {meta}")
        print(f"           {row['body']}")
    print(f"\n{len(rows)} document(s) shown.")
    return 0


def cmd_stats(mem: rag.RagMemory) -> int:
    conn = mem.connect(create=False)
    if conn is None:
        print("No index found.", file=sys.stderr)
        return 1
    total = mem.count()
    print(f"Database: {mem.db_path}")
    print(f"Documents: {total}\n")
    for label, column in (("By kind", "kind"), ("By target", "target")):
        rows = conn.execute(
            f"SELECT {column} AS k, COUNT(*) AS n FROM documents "
            f"GROUP BY {column} ORDER BY n DESC LIMIT 25").fetchall()
        print(label + ":")
        for row in rows:
            print(f"  {row['k'] or '(none)':<40} {row['n']}")
        print()
    return 0


def cmd_query(mem: rag.RagMemory, query: str, k: int, kind: str | None) -> int:
    hits = mem.retrieve(query, k=k, kind=kind)
    print(f"Query:  {query}")
    print(f"MATCH:  {rag.fts_query(query)}\n")
    if not hits:
        print("(no hits)")
        return 0
    for i, hit in enumerate(hits, 1):
        print(f"{i}. [{hit.kind}] score={hit.score:.3f}")
        print(f"   {hit.as_line()}")
    print("\n--- as injected into the planner prompt ---")
    print(rag.format_lessons(hits, max_lines=k))
    return 0


def cmd_smap(mem: rag.RagMemory, smap_path: Path, k: int) -> int:
    try:
        smap = json.loads(smap_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read SystemMap {smap_path}: {exc}", file=sys.stderr)
        return 1
    return cmd_query(mem, rag.query_from_smap(smap), k, None)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage the CyberSwarm cross-engagement RAG index.")
    parser.add_argument("--db", default=None,
                        help="override the index path (default: config rag.db_path)")
    parser.add_argument("--results", default=None,
                        help="override the results/ directory to index")
    parser.add_argument("--full", action="store_true",
                        help="clear the index before rebuilding")
    parser.add_argument("--list", action="store_true",
                        help="print indexed documents instead of reindexing")
    parser.add_argument("--stats", action="store_true",
                        help="print document counts by kind and target")
    parser.add_argument("--query", default=None,
                        help="run a retrieval query against the index")
    parser.add_argument("--smap", default=None,
                        help="path to a SystemMap JSON; queries as the planner would")
    parser.add_argument("--kind", default=None,
                        help="filter by document kind (finding|plan|tool|recon|decision)")
    parser.add_argument("-k", type=int, default=rag.DEFAULT_TOP_K,
                        help=f"results to return (default: {rag.DEFAULT_TOP_K})")
    parser.add_argument("--limit", type=int, default=200,
                        help="max documents for --list (default: 200)")
    args = parser.parse_args()

    if not rag.fts5_available():
        print("This Python's SQLite was built without FTS5; RAG memory is "
              "unavailable.", file=sys.stderr)
        return 2

    mem = rag.get_memory(db_path=args.db, results_dir=args.results)
    try:
        if args.list:
            return cmd_list(mem, args.kind, args.limit)
        if args.stats:
            return cmd_stats(mem)
        if args.smap:
            return cmd_smap(mem, Path(args.smap), args.k)
        if args.query:
            return cmd_query(mem, args.query, args.k, args.kind)

        stats = mem.update_from_results(full=args.full)
        print(f"Indexed {stats.get('collected', 0)} document(s) from "
              f"{mem.results_dir}")
        print(f"  new:       {stats.get('added', 0)}")
        print(f"  updated:   {stats.get('updated', 0)}")
        print(f"  unchanged: {stats.get('skipped', 0)}")
        print(f"  total now: {mem.count()}")
        print(f"  database:  {mem.db_path}")
        return 0
    except sqlite3.Error as exc:
        print(f"SQLite error: {exc}", file=sys.stderr)
        return 1
    finally:
        mem.close()


if __name__ == "__main__":
    raise SystemExit(main())
