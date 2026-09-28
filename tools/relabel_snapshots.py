#!/usr/bin/env python3
"""
Relabel the per-repo reachability snapshots so the released artifact says
what it actually is.

Background
----------
The snapshots under 00_corpus/data/ were written by rq2_llm_defenses/code/
llm_scan.py. They contain (a) the list of files statically import-reachable
from the repository's entry point and (b) a key `stages_with_files` that, BY
DESIGN, lists the *same full file set under every present stage* — because
the RQ2 LLM audit reads all reachable code for each stage's question.

Released under the name `call_graphs/` and with that key, the artifact reads
as a call graph in which every file belongs to every stage. Neither is true.
This script:

  1. renames  00_corpus/data/call_graphs/  ->  00_corpus/data/import_graphs/
  2. in every snapshot JSON:
       - renames `stages_with_files` -> `rq2_context_files` and documents it
       - adds `entry_route`  ("dockerfile" | "fallback_entry_file")
       - adds `entry_files`  (repo-relative entry point(s))
       - adds `stages_present` and `analysis` (a plain description of what the
         file list is and is not)
     using only data already in 00_corpus/data/verified_corpus.csv.

No repository is re-cloned. Run from the repository root:

    python tools/relabel_snapshots.py --dry-run
    python tools/relabel_snapshots.py
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

OLD_DIR = os.path.join("00_corpus", "data", "call_graphs")
NEW_DIR = os.path.join("00_corpus", "data", "import_graphs")
CORPUS = os.path.join("00_corpus", "data", "verified_corpus.csv")
ROUTES = os.path.join("scans", "entry_routes.csv")   # from tools/derive_entry_route.py, if present

ANALYSIS_NOTE = (
    "Static import-reachability analysis. Starting from the entry point, "
    "in-repo `import` statements are followed breadth-first (Python `ast`); "
    "`reachable_files` is the resulting set of modules. Nodes are files and "
    "edges are imports; no caller->callee function edges are resolved, so this "
    "is NOT a call graph in the program-analysis sense, and import-reachable "
    "does not imply executed."
)
RQ2_NOTE = (
    "For RQ2 the LLM audit is given ALL reachable files for EVERY stage that "
    "Stage 3 detected as present, because a defensive control can live "
    "anywhere in the deployed code. This key therefore lists the full "
    "reachable set under each present stage; it is not a per-file stage "
    "attribution. Per-file stage evidence used by RQ1 comes from "
    "00_corpus/scanner/scanner/stage_verifier.py (StageReport.evidence_files)."
)


def repo_key(url: str) -> str:
    u = url.strip().rstrip("/")
    u = u.replace("https://github.com/", "").replace("http://github.com/", "")
    return u.replace("/", "__")


def load_corpus(path: str) -> dict[str, dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return {repo_key(r["repo"]): r for r in csv.DictReader(fh)}


def relabel(payload: dict, meta: dict | None, route: str | None = None) -> dict:
    out: dict = {"repo": payload.get("repo")}
    if meta is not None:
        if meta.get("entry_route"):                      # scanner >= extension: recorded directly
            out["entry_route"] = meta["entry_route"]
        elif route:                                      # settled by derive_entry_route.py
            out["entry_route"] = route
        elif int(meta.get("dockerfiles_found") or 0) == 0:
            out["entry_route"] = "fallback_root"         # no Dockerfile at all: unambiguous
        else:
            out["entry_route"] = "dockerfile?"           # Dockerfile present; resolution unknown
        out["entry_files"] = [p.strip().replace("\\", "/")
                              for p in (meta.get("entry_files") or "").split(";") if p.strip()]
        out["stages_present"] = int(meta.get("stages_present") or 0)
    else:
        out["entry_route"] = "unknown"
        out["entry_files"] = []
    out["analysis"] = ANALYSIS_NOTE
    out["reachable_files"] = payload.get("reachable_files", [])
    ctx = payload.get("rq2_context_files", payload.get("stages_with_files", {}))
    out["rq2_context_files_note"] = RQ2_NOTE
    out["rq2_context_files"] = ctx
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(CORPUS):
        print(f"run from the repository root (missing {CORPUS})", file=sys.stderr)
        return 2

    src = OLD_DIR if os.path.isdir(OLD_DIR) else NEW_DIR
    if not os.path.isdir(src):
        print("no snapshot directory found", file=sys.stderr)
        return 2

    corpus = load_corpus(CORPUS)
    routes: dict[str, str] = {}
    if os.path.isfile(ROUTES):
        with open(ROUTES, newline="", encoding="utf-8") as fh:
            routes = {repo_key(r["repo"]): r["entry_route"] for r in csv.DictReader(fh) if r.get("entry_route")}
    files = sorted(f for f in os.listdir(src) if f.endswith(".json"))
    print(f"{len(files)} snapshots in {src}; {len(corpus)} corpus rows; {len(routes)} settled routes")

    if args.dry_run:
        sample = files[0]
        with open(os.path.join(src, sample), encoding="utf-8") as fh:
            print(json.dumps(relabel(json.load(fh), corpus.get(sample[:-5]), routes.get(sample[:-5])), indent=1)[:900])
        print(f"\n[dry-run] would rename {src} -> {NEW_DIR} and rewrite {len(files)} files")
        return 0

    if src == OLD_DIR:
        # Prefer `git mv` so the rename is tracked; fall back to os.rename.
        rc = os.system(f'git mv "{OLD_DIR}" "{NEW_DIR}" 2>/dev/null')
        if rc != 0:
            os.rename(OLD_DIR, NEW_DIR)
        print(f"renamed {OLD_DIR} -> {NEW_DIR}")

    missing_meta, route_counts = [], {}
    for fn in files:
        p = os.path.join(NEW_DIR, fn)
        with open(p, encoding="utf-8") as fh:
            payload = json.load(fh)
        meta = corpus.get(fn[:-5])
        if meta is None:
            missing_meta.append(fn)
        new = relabel(payload, meta, routes.get(fn[:-5]))
        route_counts[new["entry_route"]] = route_counts.get(new["entry_route"], 0) + 1
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(new, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    print(f"rewrote {len(files)} snapshots; entry routes: {route_counts}")
    if missing_meta:
        print(f"WARNING: {len(missing_meta)} snapshots had no corpus row: {missing_meta[:5]}")
    absent = sorted(set(corpus) - {f[:-5] for f in files})
    if absent:
        print(f"NOTE: {len(absent)} corpus repos have no snapshot: {absent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
