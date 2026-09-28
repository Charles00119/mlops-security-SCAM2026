#!/usr/bin/env python3
"""
Run the Stage 1-3 corpus scanner (00_corpus/scanner/scanner/orchestrator.py)
over a candidate list with N parallel workers, resuming from existing logs.

Two passes are supported:

  pass1   scan every candidate not yet present in the given --done logs,
          using the scanner's normal rules.
  pass2   re-scan every repo that ended as `no_entry` or `no_dockerfile` in
          the given --done logs. Only useful with the widened fallback rules
          (dockerfile_parser._fallback_entry, routes fallback_nested /
          fallback_console_script); repos that already resolved are skipped.
  retry   re-scan the repos whose row in --workdir/scan_log.csv is a
          clone_failed with a recoverable reason (disk full, timeout, path
          error, LFS) into --retry-workdir. Repos that are gone ("Password",
          "not found", "denied") are not retried.

Each worker writes its own log; when all workers exit the logs are merged
into --out-log (and verified rows into --out-verified). Re-running the same
command resumes: anything already in the worker logs or --done logs is
skipped, so an interrupted run loses at most N in-flight repositories.

Examples (run from the repository root; set GITHUB_TOKEN first):

  # pass 1: the candidates the original scan never reached
  python tools/scan_parallel.py pass1 \
      --candidates 00_corpus/data/list_of_repositories.xlsx \
      --done _archive/scan_log.csv --done scans/scan_log_pass1_partial.csv \
      --workdir scans/pass1 --workers 6 --tmp D:/scan_tmp

  # pass 2: widened fallback over everything that failed in pass 1 + original
  python tools/scan_parallel.py pass2 \
      --done _archive/scan_log.csv --done scans/pass1/scan_log.csv \
      --workdir scans/pass2 --workers 6 --tmp D:/scan_tmp

  # retry recoverable clone failures of pass 2
  python tools/scan_parallel.py retry \
      --workdir scans/pass2 --retry-workdir scans/pass2_retry --workers 6 --tmp D:/scan_tmp

Windows: run `git config --global core.longpaths true` once beforehand.
"""
from __future__ import annotations

import argparse
import csv
import glob
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORCH = os.path.join(ROOT, "00_corpus", "scanner", "scanner", "orchestrator.py")
FAIL_STATUSES = {"no_entry", "no_dockerfile"}
GONE_MARKERS = ("Password", "not found", "denied", "does not exist")   # clone failures that are not worth retrying


def norm(u: str) -> str:
    return (u or "").strip().rstrip("/")


def load_candidates(path: str) -> list[str]:
    if path.endswith(".xlsx"):
        import openpyxl  # noqa: PLC0415
        ws = openpyxl.load_workbook(path, read_only=True).worksheets[0]
        rows = ws.iter_rows(values_only=True)
        hdr = [str(c).lower() if c is not None else "" for c in next(rows)]
        col = next(hdr.index(c) for c in ("html_url", "gh_html_url", "url", "repo", "repository") if c in hdr)
        return [norm(str(r[col])) for r in rows if r[col]]
    if path.endswith(".csv"):
        with open(path, newline="", encoding="utf-8") as fh:
            rd = csv.DictReader(fh)
            col = next(c for c in ("html_url", "url", "repo", "repository") if c in rd.fieldnames)
            return [norm(r[col]) for r in rd if r.get(col)]
    with open(path, encoding="utf-8") as fh:
        return [norm(l) for l in fh if l.strip()]


def load_log(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if r.get("repo") and r.get("status")]


def merge_logs(paths: list[str], out: str) -> list[dict]:
    rows, seen, fields = [], set(), None
    for p in paths:
        for r in load_log(p):
            if fields is None:
                fields = list(r.keys())
            if r["repo"] not in seen:
                seen.add(r["repo"]); rows.append(r)
    if rows:
        # newer scanner versions add columns (entry_route); union the headers
        allf = list(dict.fromkeys(k for r in rows for k in r.keys()))
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=allf); w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, "") for k in allf})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["pass1", "pass2", "retry"])
    ap.add_argument("--candidates", help="pass1: .xlsx/.csv/.txt of candidate repos")
    ap.add_argument("--done", action="append", default=[],
                    help="existing scan log(s); repeatable. pass1 skips these, pass2 selects failures from them")
    ap.add_argument("--workdir", required=True, help="where shard lists, worker logs and merged output go "
                                                        "(retry: the workdir whose clone failures to retry)")
    ap.add_argument("--retry-workdir", help="retry: where the retry run's shards/logs go (default <workdir>_retry)")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--tmp", help="directory for temporary clones (fast local disk recommended)")
    ap.add_argument("--merge-only", action="store_true", help="skip scanning; just merge existing worker logs")
    args = ap.parse_args()

    if not os.environ.get("GITHUB_TOKEN"):
        print("WARNING: GITHUB_TOKEN not set; anonymous clones may be throttled.", file=sys.stderr)

    os.makedirs(args.workdir, exist_ok=True)
    done_rows = [r for p in args.done for r in load_log(p)]
    done_keys = {norm(r["repo"]).lower() for r in done_rows}

    if args.mode == "retry":
        src_log = os.path.join(args.workdir, "scan_log.csv")
        if not os.path.isfile(src_log):
            ap.error(f"retry: {src_log} not found (run the pass to completion first; it writes the merged log)")
        failed = [r for r in load_log(src_log) if r["status"] == "clone_failed"
                  and not any(m in r.get("detail", "") for m in GONE_MARKERS)]
        gone = sum(1 for r in load_log(src_log) if r["status"] == "clone_failed") - len(failed)
        todo = [norm(r["repo"]) for r in failed]
        print(f"[retry] {len(todo)} recoverable clone failures in {src_log} ({gone} skipped as repository gone)")
        args.workdir = args.retry_workdir or (args.workdir.rstrip("/\\") + "_retry")
        os.makedirs(args.workdir, exist_ok=True)
    elif args.mode == "pass1":
        if not args.candidates:
            ap.error("pass1 needs --candidates")
        todo = [u for u in load_candidates(args.candidates) if u.lower() not in done_keys]
    else:
        seen, todo = set(), []
        for r in done_rows:
            u = norm(r["repo"])
            if r["status"] in FAIL_STATUSES and u.lower() not in seen:
                seen.add(u.lower()); todo.append(u)

    # also skip anything a previous (interrupted) run of THIS workdir already logged
    prior = {norm(r["repo"]).lower() for p in glob.glob(os.path.join(args.workdir, "log*.csv")) for r in load_log(p)}
    todo = [u for u in todo if u.lower() not in prior]
    print(f"[{args.mode}] {len(todo)} repositories to scan "
          f"({len(prior)} already logged in {args.workdir}, {len(done_keys)} in --done logs)")

    if todo and not args.merge_only:
        env = dict(os.environ)
        # Never let a worker block on an interactive credential prompt: a repo
        # that has gone private/deleted must fail fast and be logged, not pop
        # up Git Credential Manager's sign-in dialog (observed on Windows).
        env.setdefault("GIT_TERMINAL_PROMPT", "0")
        env.setdefault("GCM_INTERACTIVE", "Never")
        env.setdefault("GIT_ASKPASS", "")
        if args.tmp:
            os.makedirs(args.tmp, exist_ok=True)
            env["TMPDIR"] = env["TMP"] = env["TEMP"] = os.path.abspath(args.tmp)
        procs = []
        for k in range(args.workers):
            shard = todo[k::args.workers]
            if not shard:
                continue
            sp = os.path.join(args.workdir, f"shard{k}.txt")
            with open(sp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(shard) + "\n")
            log = os.path.join(args.workdir, f"log{k}.csv")
            ver = os.path.join(args.workdir, f"verified{k}.csv")
            out = open(os.path.join(args.workdir, f"worker{k}.out"), "a", encoding="utf-8")
            procs.append(subprocess.Popen([sys.executable, ORCH, sp, log, ver], env=env, stdout=out, stderr=subprocess.STDOUT))
        print(f"launched {len(procs)} workers; progress: watch {args.workdir}/log*.csv")
        t0 = time.time()
        try:
            while any(p.poll() is None for p in procs):
                time.sleep(30)
                n = sum(len(load_log(p)) for p in glob.glob(os.path.join(args.workdir, "log*.csv")))
                el = (time.time() - t0) / 60
                rate = (n - len(prior)) / el if el > 0 else 0
                eta = (len(todo) - (n - len(prior))) / rate if rate > 0 else float("inf")
                print(f"  {n - len(prior):>6}/{len(todo)} done  {rate:5.0f}/min  ETA {eta:5.0f} min", flush=True)
        except KeyboardInterrupt:
            print("\ninterrupted — terminating workers (re-run the same command to resume)")
            for p in procs:
                p.terminate()
            return 130

    rows = merge_logs(sorted(glob.glob(os.path.join(args.workdir, "log*.csv"))), os.path.join(args.workdir, "scan_log.csv"))
    ver = [r for r in rows if r.get("verified") == "True"]
    with open(os.path.join(args.workdir, "verified.csv"), "w", newline="", encoding="utf-8") as fh:
        if ver:
            allf = list(dict.fromkeys(k for r in ver for k in r.keys()))
            w = csv.DictWriter(fh, fieldnames=allf); w.writeheader()
            for r in ver:
                w.writerow({k: r.get(k, "") for k in allf})
    from collections import Counter
    print(f"merged {len(rows)} rows -> {args.workdir}/scan_log.csv ; verified: {len(ver)} -> {args.workdir}/verified.csv")
    print("status:", dict(Counter(r["status"] for r in rows)))
    if ver:
        print("entry routes of verified:", dict(Counter(r.get("entry_route", "") for r in ver)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
