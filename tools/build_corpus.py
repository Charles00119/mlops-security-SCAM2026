#!/usr/bin/env python3
"""
Build the final corpus files from the original scan and the extension passes.

Inputs (all optional except --original; missing files are skipped):
  --original   _archive/scan_log.csv                 the first Stage 1-3 run (18,533 rows)
  --extra      scans/scan_log_pass1_partial.csv      continuation runs, original rules; repeatable
  --extra      scans/pass1/scan_log.csv
  --pass2      scans/pass2/scan_log.csv              widened-fallback re-scan of failed repos
  --routes     scans/entry_routes.csv                output of tools/derive_entry_route.py
                                                     (entry_route for pre-extension verified repos)

Outputs (written to --out-dir, default 00_corpus/data):
  scan_log_full.csv        one row per candidate: the final outcome for every repository
                           (a pass-2 success replaces the earlier failure row; a pass-2 failure
                           keeps the earlier row but records pass2_status)
  verified_corpus.csv      every repository with all six stages reachable, with entry_route
  corpus_funnel.md         the funnel table for the README

Rules
-----
* A repo's final row is: its pass-2 row if pass 2 resolved an entry point (status ok),
  else its most recent earlier row. Pass 2 never touches repos that already resolved.
* entry_route for rows produced by the pre-extension scanner (no column) is filled from
  --routes if present, else inferred: dockerfiles_found == 0 -> fallback_root;
  dockerfiles_found > 0 -> 'dockerfile?' (unknown: Dockerfile present but the scanner
  did not record whether it resolved). Run derive_entry_route.py to settle those.
"""
from __future__ import annotations

import argparse
import csv
import os
from collections import Counter, OrderedDict

FAIL = {"no_entry", "no_dockerfile"}


def norm(u: str) -> str:
    return (u or "").strip().rstrip("/")


def key(u: str) -> str:
    return norm(u).lower()


def load(path: str) -> list[dict]:
    if not path or not os.path.isfile(path):
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if r.get("repo") and r.get("status")]


def write(path: str, rows: list[dict], fields: list[str]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--original", default="_archive/scan_log.csv")
    ap.add_argument("--extra", action="append", default=[])
    ap.add_argument("--pass2", default="scans/pass2/scan_log.csv")
    ap.add_argument("--routes", default="scans/entry_routes.csv")
    ap.add_argument("--candidates-total", type=int, default=31066)
    ap.add_argument("--out-dir", default="00_corpus/data")
    args = ap.parse_args()

    # ---- 1. baseline: original + continuation runs (original rules) ----------
    base: "OrderedDict[str, dict]" = OrderedDict()
    for p in [args.original] + args.extra:
        for r in load(p):
            r = dict(r); r["repo"] = norm(r["repo"]); r["scan_source"] = os.path.basename(os.path.dirname(p) or p)
            base.setdefault(key(r["repo"]), r)          # first occurrence wins (in order given)
    n_base = len(base)
    base_status = Counter(r["status"] for r in base.values())
    base_verified = sum(1 for r in base.values() if r.get("verified") == "True")

    # ---- 2. pass 2 overlay --------------------------------------------------
    p2 = {key(r["repo"]): r for r in load(args.pass2)}
    p2_status = Counter(r["status"] for r in p2.values())
    p2_verified = sum(1 for r in p2.values() if r.get("verified") == "True")
    replaced = 0
    for k, r2 in p2.items():
        r1 = base.get(k)
        if r1 is None:
            r2 = dict(r2); r2["repo"] = norm(r2["repo"]); r2["scan_source"] = "pass2"; base[k] = r2
            continue
        if r1["status"] in FAIL and r2["status"] == "ok":
            new = dict(r2); new["repo"] = r1["repo"]; new["scan_source"] = "pass2"
            new["pass1_status"] = r1["status"]
            base[k] = new; replaced += 1
        else:
            r1["pass2_status"] = r2["status"]

    # ---- 3. entry_route for pre-extension rows -------------------------------
    routes = {key(r["repo"]): r.get("entry_route", "") for r in load(args.routes)} if os.path.isfile(args.routes) else {}
    for k, r in base.items():
        if r.get("entry_route"):
            continue
        if k in routes and routes[k]:
            r["entry_route"] = routes[k]
        elif r.get("status") == "ok":
            if int(r.get("dockerfiles_found") or 0) == 0:
                r["entry_route"] = "fallback_root"
            else:
                r["entry_route"] = "dockerfile?"

    # ---- 4. outputs ---------------------------------------------------------
    rows = list(base.values())
    fields = list(OrderedDict.fromkeys(k for r in rows for k in r.keys()))
    for extra in ("entry_route", "scan_source", "pass1_status", "pass2_status"):
        if extra not in fields:
            fields.append(extra)
    write(os.path.join(args.out_dir, "scan_log_full.csv"), rows, fields)

    verified = [r for r in rows if r.get("verified") == "True"]
    write(os.path.join(args.out_dir, "verified_corpus.csv"), verified, fields)

    final_status = Counter(r["status"] for r in rows)
    routes_c = Counter(r.get("entry_route", "") for r in verified)
    stages_c = Counter(r.get("stages_present", "") for r in rows if r["status"] == "ok")

    lines = []
    lines.append("| Step | Repositories |")
    lines.append("|---|---:|")
    lines.append(f"| Candidate list (Idowu et al.) | {args.candidates_total:,} |")
    lines.append(f"| Scanned with the original entry-point rules | {n_base:,} |")
    lines.append(f"| ├ clone failed (repository deleted / private) | {base_status['clone_failed']:,} |")
    lines.append(f"| ├ no Dockerfile and no root entry file | {base_status['no_dockerfile']:,} |")
    lines.append(f"| ├ Dockerfile found, no resolvable Python entry point | {base_status['no_entry']:,} |")
    lines.append(f"| ├ entry point resolved | {base_status['ok']:,} |")
    lines.append(f"| └ all six stages reachable (**original rules**) | **{base_verified:,}** |")
    if p2:
        lines.append(f"| Re-scanned with widened fallback rules (pass 2) | {len(p2):,} |")
        lines.append(f"| ├ entry point newly resolved | {p2_status['ok']:,} |")
        lines.append(f"| └ all six stages reachable (**widened rules**) | **{p2_verified:,}** |")
    lines.append(f"| **Verified corpus (total)** | **{len(verified):,}** |")
    lines.append("")
    lines.append("Verified repositories by entry-point route:")
    lines.append("")
    for k2, v in sorted(routes_c.items(), key=lambda kv: -kv[1]):
        lines.append(f"- `{k2}`: {v}")
    lines.append("")
    lines.append("Stages reachable among repositories with a resolved entry point:")
    lines.append("")
    lines.append("| stages | repos |"); lines.append("|---:|---:|")
    for s in sorted(stages_c, key=lambda x: -int(x or 0)):
        lines.append(f"| {s} | {stages_c[s]:,} |")
    funnel = "\n".join(lines) + "\n"
    with open(os.path.join(args.out_dir, "corpus_funnel.md"), "w", encoding="utf-8") as fh:
        fh.write(funnel)

    print(funnel)
    print(f"final rows: {len(rows):,}  status: {dict(final_status)}")
    print(f"pass-2 successes replacing earlier failures: {replaced:,}")
    unknown = routes_c.get("dockerfile?", 0)
    if unknown:
        print(f"NOTE: {unknown} verified repos have entry_route 'dockerfile?' — run tools/derive_entry_route.py to settle them")
    print(f"wrote {args.out_dir}/scan_log_full.csv, verified_corpus.csv, corpus_funnel.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
