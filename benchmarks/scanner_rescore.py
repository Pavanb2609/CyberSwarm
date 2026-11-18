#!/usr/bin/env python
"""Offline rescore of a scanner_benchmark stamp from persisted raw evidence.

run_nuclei originally parsed only the -o results file, which nuclei buffers
and flushes only at clean exit — SIGKILL'd or long-lived arms lose findings.
The stdout logs capture every finding incrementally (verified: the serial
dvwa log holds 3 findings absent from the -o file), so detections for the
nuclei arms are recomputed from stdout evidence and merged into run.json.
The pre-rescore record is preserved as run_original.json.

Usage: ./venv/bin/python benchmarks/scanner_rescore.py <stamp_dir>
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import scanner_bench as sb


def nuclei_detections(run_dir: Path, name: str, out_name: str):
    det = []
    seen = set()
    sources = [run_dir / out_name]
    for app in sb.APP_PORTS:
        sources.append(run_dir / f"nuclei_{name}_output.jsonl".replace(
            ".jsonl", f".{app}.log"))
    for src in sources:
        for j in sb._parse_nuclei_findings(src):
            info = j.get("info", {})
            matched = j.get("matched-at") or j.get("host") or ""
            path = sb.urllib.parse.urlparse(matched).path or "/"
            d = {"endpoint": path, "param": None,
                 "cls": sb.nuclei_class(info.get("tags", [])),
                 "high": str(info.get("severity", "")).lower() in
                         ("high", "critical"),
                 "template": info.get("name", ""),
                 "severity": str(info.get("severity", "")),
                 "matched_at": matched}
            key = (d["endpoint"], d["template"])
            if key not in seen:
                seen.add(key)
                det.append(d)
    return det


def main(stamp_dir: str) -> int:
    run_dir = Path(stamp_dir)
    run_json = run_dir / "run.json"
    record = json.loads(run_json.read_text())
    orig = run_dir / "run_original.json"
    if not orig.exists():
        orig.write_text(json.dumps(record, indent=1))
    for tool, entry in record["tools"].items():
        if not tool.startswith("nuclei"):
            continue
        det = nuclei_detections(run_dir, tool[7:], "nuclei_%s_results.jsonl" % tool[7:])
        sc = sb.score(tool, det, run_dir)
        if "pre_rescore" not in entry:  # preserve the original record once
            entry["pre_rescore"] = {"detections": entry["detections"],
                                    "score": entry["score"]}
        entry["detections"] = det
        entry["score"] = sc
        entry["rescored"] = ("from stdout nuclei logs (buffered -o file "
                             "unreliable on unclean exit)")
        print(f"[{tool}] rescored: {len(det)} detections, TP {sc['tp']}/"
              f"{sc['instances']}, false_high {len(sc['false_high_severity'])}")
    run_json.write_text(json.dumps(record, indent=1))
    print("written:", run_json)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
