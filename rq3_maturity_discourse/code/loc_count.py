"""Count reachable lines of code per repo, for vulnerability-density analysis.

For each repo in verified_corpus.csv:
    1. Read 00_corpus/data/import_graphs/{owner}__{repo}.json -> reachable_files list
    2. Shallow-clone the repo (depth 1) to a temp dir
    3. Count lines in each reachable file
    4. Write one row to loc.csv

Output columns:
    repo, repo_key, n_reachable_files, n_files_found, loc_reachable, clone_ok

n_files_found can be < n_reachable_files if the repo changed since the scan
(files renamed/deleted). loc_reachable counts only the files found.

Usage:
    python -m stage4.loc_count                     # full corpus (~408 clones)
    python -m stage4.loc_count --limit 5           # smoke test on 5 repos
    python -m stage4.loc_count --resume            # skip repos already in loc.csv

Notes:
    - Requires git on PATH.
    - Shallow clones keep bandwidth modest, but 408 repos still takes a while
      (rough ballpark 30-60+ min depending on network). --resume lets you stop
      and continue.
    - Repos that fail to clone (deleted, renamed, private) get clone_ok=False
      and loc_reachable=0; handle them as missing data in the correlation, not
      as zero-LOC repos.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile


def repo_key_from_url(url: str) -> str:
    parts = url.rstrip("/").split("/")
    if len(parts) < 2:
        return url.replace("/", "__")
    return f"{parts[-2]}__{parts[-1]}"


def load_corpus(path: str) -> list[str]:
    repos: list[str] = []
    with open(path, "r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        field = "repo" if reader.fieldnames and "repo" in reader.fieldnames \
            else (reader.fieldnames[0] if reader.fieldnames else None)
        if field is None:
            raise ValueError(f"{path}: no columns")
        for row in reader:
            url = (row.get(field) or "").strip()
            if url:
                repos.append(url)
    return repos


def reachable_files(call_graphs_dir: str, key: str) -> list[str]:
    path = os.path.join(call_graphs_dir, f"{key}.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    return (data or {}).get("reachable_files", []) or []


def shallow_clone(url: str, dest: str, timeout: int = 180) -> bool:
    try:
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, dest],
            capture_output=True, timeout=timeout, text=True,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def count_lines(path: str) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def already_done(out_path: str) -> set[str]:
    if not os.path.isfile(out_path):
        return set()
    done = set()
    with open(out_path, "r", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            done.add(row["repo_key"])
    return done


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--corpus",          default="verified_corpus.csv")
    p.add_argument("--call-graphs-dir", default="00_corpus/data/import_graphs")
    p.add_argument("--out",             default="loc.csv")
    p.add_argument("--limit", type=int, default=0,
                   help="only process the first N repos (0 = all)")
    p.add_argument("--resume", action="store_true",
                   help="skip repos already present in the output CSV")
    args = p.parse_args()

    repos = load_corpus(args.corpus)
    if args.limit:
        repos = repos[: args.limit]

    done = already_done(args.out) if args.resume else set()
    mode = "a" if (args.resume and done) else "w"

    with open(args.out, mode, newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if mode == "w":
            w.writerow(["repo", "repo_key", "n_reachable_files",
                        "n_files_found", "loc_reachable", "clone_ok"])

        for i, url in enumerate(repos, 1):
            key = repo_key_from_url(url)
            if key in done:
                continue
            files = reachable_files(args.call_graphs_dir, key)
            tmp = tempfile.mkdtemp(prefix="loc_")
            try:
                ok = shallow_clone(url, tmp)
                n_found = 0
                loc = 0
                if ok:
                    for rel in files:
                        fp = os.path.join(tmp, rel.replace("/", os.sep))
                        if os.path.isfile(fp):
                            n_found += 1
                            loc += count_lines(fp)
                w.writerow([url, key, len(files), n_found, loc, ok])
                fh.flush()
                print(f"[{i}/{len(repos)}] {key}: "
                      f"{'OK' if ok else 'CLONE-FAILED'} "
                      f"files={n_found}/{len(files)} loc={loc}")
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

    print(f"[ok] wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
