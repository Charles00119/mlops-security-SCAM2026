"""Dump unique (tool, rule_id) pairs from stage4_findings/ with counts and
one example message each. Used as input for building the static-analysis
semantic-category mapping.

Usage:
    python dump_rule_ids.py [--findings-dir stage4_findings] [--out rule_ids.csv]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--findings-dir", default="stage4_findings")
    p.add_argument("--out", default="rule_ids.csv")
    args = p.parse_args()

    counts: Counter = Counter()
    examples: dict[tuple[str, str], str] = {}
    files_scanned = 0

    for name in sorted(os.listdir(args.findings_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(args.findings_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, list):
            continue
        files_scanned += 1
        for f in data:
            tool = (f.get("tool") or "unknown").lower()
            if tool == "claude_judgment":
                continue   # skip — LLM taxonomy is built separately
            rid = f.get("rule_id") or "unknown"
            key = (tool, rid)
            counts[key] += 1
            if key not in examples:
                examples[key] = (f.get("message") or "")[:200]

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "rule_id", "count", "example_message"])
        for (tool, rid), n in counts.most_common():
            w.writerow([tool, rid, n, examples[(tool, rid)]])

    print(f"[ok] scanned {files_scanned} finding files, "
          f"{len(counts)} unique (tool, rule_id) pairs, "
          f"{sum(counts.values())} total findings (excluding claude_judgment)")
    print(f"[ok] wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
