#!/usr/bin/env python3
"""
Settle `entry_route` for verified repositories scanned before the column
existed. Only repos with dockerfiles_found > 0 are ambiguous (a Dockerfile
that exists but whose CMD/ENTRYPOINT did not resolve still fell back to a
root entry file); repos with dockerfiles_found == 0 are fallback_root by
definition and are not re-cloned.

Re-clones each ambiguous repo (shallow), runs Stage 1 only, and records the
route of the resolved entry point(s). No Stage 2/3 re-analysis is done, so
existing results are unaffected.

    python tools/derive_entry_route.py \
        --corpus 00_corpus/data/verified_corpus.csv \
        --out scans/entry_routes.csv [--tmp D:/scan_tmp]

Set GITHUB_TOKEN to avoid anonymous-clone throttling.
"""
from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "00_corpus", "scanner"))
from scanner.dockerfile_parser import get_entry_points  # noqa: E402


def clone(url: str, dest: str, token: str | None, timeout: int = 300) -> bool:
    u = url
    if token and url.startswith("https://github.com/"):
        u = url.replace("https://github.com/", f"https://{token}@github.com/", 1)
    try:
        p = subprocess.run(["git", "clone", "--depth", "1", "--quiet", u, dest],
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="00_corpus/data/verified_corpus.csv")
    ap.add_argument("--out", default="scans/entry_routes.csv")
    ap.add_argument("--tmp")
    ap.add_argument("--all", action="store_true", help="re-derive for every verified repo, not just ambiguous ones")
    args = ap.parse_args()
    token = os.environ.get("GITHUB_TOKEN") or None

    with open(args.corpus, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    todo = [r for r in rows if args.all or (not r.get("entry_route") or r.get("entry_route") == "dockerfile?")]
    todo = [r for r in todo if args.all or int(r.get("dockerfiles_found") or 0) > 0]
    print(f"{len(todo)} repositories to re-check (of {len(rows)})")

    done = {}
    if os.path.isfile(args.out):
        with open(args.out, newline="", encoding="utf-8") as fh:
            done = {r["repo"]: r for r in csv.DictReader(fh)}

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    fields = ["repo", "entry_route", "entry_files", "notes"]
    with open(args.out, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if not done:
            w.writeheader()
        for i, r in enumerate(todo, 1):
            url = r["repo"].strip().rstrip("/")
            if url in done:
                continue
            tmp = tempfile.mkdtemp(prefix="route_", dir=args.tmp)
            dest = os.path.join(tmp, "repo")
            try:
                if not clone(url, dest, token):
                    rec = {"repo": url, "entry_route": "unavailable", "entry_files": "", "notes": "clone failed"}
                else:
                    eps = [ep for ep in get_entry_points(dest) if ep.resolved]
                    routes = sorted({ep.route for ep in eps})
                    files = ";".join(os.path.relpath(ep.entry_file, dest).replace(os.sep, "/") for ep in eps if ep.entry_file)
                    rec = {"repo": url, "entry_route": "+".join(routes) or "unresolved",
                           "entry_files": files, "notes": " | ".join(n for ep in eps for n in ep.notes)[:300]}
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            w.writerow(rec); fh.flush()
            print(f"[{i:>4}/{len(todo)}] {url.split('github.com/')[-1]:<50} {rec['entry_route']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
