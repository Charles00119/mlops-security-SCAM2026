"""Stage 4 orchestrator.

Usage:
    python -m stage4.orchestrator verified_corpus.csv \\
        --log stage4_log.csv \\
        --findings-dir stage4_findings \\
        --summary stage4_summary.csv

For each verified repo:
  1. Shallow clone into a temp directory
  2. Re-run Stages 1-3 to rebuild the call graph and stage mapping
  3. Run every available tool from tools.TOOLS
  4. Annotate each finding with its stage
  5. Write per-repo JSON to findings-dir, append summary row to summary CSV
  6. Delete the clone

Supports resume — repos already present in stage4_log.csv are skipped.
"""
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import tempfile
import time
import shutil
import traceback
from collections import Counter
from dataclasses import dataclass

from .findings import Finding, dump_findings_json
from .stage_mapping import annotate_findings, build_file_to_stages
from .tools import TOOLS


STAGES = ("data_acquisition", "data_preparation", "modeling",
          "training", "evaluation", "inference")
SEVERITIES = ("high", "medium", "low", "info", "unknown")

LOG_COLUMNS = [
    "repo", "status", "duration_s", "tools_run", "tools_failed",
    "total_findings", "high_findings", "medium_findings",
    "reachable_findings", "unreachable_findings", "detail",
]
SUMMARY_COLUMNS = (
    ["repo", "total_findings", "high", "medium", "low", "info", "unknown"]
    + [f"{s}_count" for s in STAGES]
    + ["dependencies_count", "reachable_unmapped_count", "unreachable_count", "unknown_count"]
    + [f"{name}_count" for name, _ in TOOLS]
    + [f"{name}_error" for name, _ in TOOLS]
)


@dataclass
class RepoResult:
    repo: str
    status: str
    duration_s: float
    findings: list[Finding]
    tool_errors: dict[str, str]
    stage_warnings: list[str]
    detail: str = ""


def shallow_clone(url: str, dest: str, *, timeout: int = 300,
                  token: str | None = None) -> tuple[bool, str]:
    """Clone url --depth 1 into dest. Returns (ok, error)."""
    clone_url = url
    if token and url.startswith("https://github.com/"):
        clone_url = url.replace("https://", f"https://x-access-token:{token}@", 1)
    cmd = [
        "git", "-c", "core.longpaths=true",
        "-c", "credential.helper=",
        "clone", "--depth", "1", "--quiet", clone_url, dest,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return False, f"clone timeout after {timeout}s"
    except Exception as exc:
        return False, f"clone exception: {type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        last = err[-1] if err else "unknown clone error"
        return False, f"git rc={proc.returncode}: {last[:200]}"
    return True, ""


def scan_one_repo(url: str, *, token: str | None = None,
                  per_tool_timeout: int = 600) -> RepoResult:
    """Clone, scan with all tools, return result. Cleans up its own temp dir."""
    t0 = time.monotonic()
    tmp = tempfile.mkdtemp(prefix="stage4_")
    repo_dir = os.path.join(tmp, "repo")

    try:
        ok, err = shallow_clone(url, repo_dir, token=token)
        if not ok:
            return RepoResult(repo=url, status="clone_failed",
                              duration_s=time.monotonic() - t0,
                              findings=[], tool_errors={}, stage_warnings=[],
                              detail=err)

        # Build the stage mapping ONCE, before running tools.
        file_to_stages, reachable, stage_warnings = build_file_to_stages(repo_dir)

        all_findings: list[Finding] = []
        tool_errors: dict[str, str] = {}
        for name, mod in TOOLS:
            try:
                if not mod.available():
                    tool_errors[name] = "not installed"
                    continue
                findings, err = mod.run(repo_dir, timeout=per_tool_timeout)
                if err:
                    tool_errors[name] = err[:200]
                all_findings.extend(findings)
            except Exception as exc:  # never let a tool wrapper crash the run
                tool_errors[name] = f"crash: {type(exc).__name__}: {exc}"[:200]

        annotate_findings(all_findings, file_to_stages, reachable)

        return RepoResult(repo=url, status="ok",
                          duration_s=time.monotonic() - t0,
                          findings=all_findings,
                          tool_errors=tool_errors,
                          stage_warnings=stage_warnings)

    except Exception as exc:
        return RepoResult(repo=url, status="error",
                          duration_s=time.monotonic() - t0,
                          findings=[], tool_errors={}, stage_warnings=[],
                          detail=f"{type(exc).__name__}: {exc}\n"
                                 f"{traceback.format_exc()[:500]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def already_done(log_path: str) -> set[str]:
    """Read log_path and return set of repo URLs already processed."""
    done: set[str] = set()
    if not os.path.isfile(log_path):
        return done
    try:
        with open(log_path, "r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                if row.get("repo"):
                    done.add(row["repo"].strip())
    except Exception:
        pass
    return done


def write_log_row(log_path: str, result: RepoResult) -> None:
    new_file = not os.path.isfile(log_path)
    sev_counts = Counter(f.severity for f in result.findings)
    location_counts = Counter("unreachable" if f.stage == "unreachable" else "reachable"
                              for f in result.findings)
    with open(log_path, "a", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=LOG_COLUMNS)
        if new_file:
            w.writeheader()
        w.writerow({
            "repo": result.repo,
            "status": result.status,
            "duration_s": f"{result.duration_s:.1f}",
            "tools_run": ";".join(name for name, _ in TOOLS
                                   if name not in result.tool_errors),
            "tools_failed": ";".join(
                f"{n}:{e}" for n, e in result.tool_errors.items()
                if e != "not installed"
            ),
            "total_findings": len(result.findings),
            "high_findings": sev_counts.get("high", 0),
            "medium_findings": sev_counts.get("medium", 0),
            "reachable_findings": location_counts.get("reachable", 0),
            "unreachable_findings": location_counts.get("unreachable", 0),
            "detail": result.detail[:300] if result.detail else "",
        })


def write_summary_row(summary_path: str, result: RepoResult) -> None:
    new_file = not os.path.isfile(summary_path)
    sev = Counter(f.severity for f in result.findings)
    tool = Counter(f.tool for f in result.findings)
    stage = Counter()
    for f in result.findings:
        # split compound stages like "training+evaluation" so each contributes
        if f.stage and f.stage not in (
            "dependencies", "reachable_unmapped", "unreachable", "unknown"
        ):
            for s in f.stage.split("+"):
                stage[s] += 1
        else:
            stage[f.stage or "unknown"] += 1

    row = {
        "repo": result.repo,
        "total_findings": len(result.findings),
        "high": sev.get("high", 0),
        "medium": sev.get("medium", 0),
        "low": sev.get("low", 0),
        "info": sev.get("info", 0),
        "unknown": sev.get("unknown", 0),
    }
    for s in STAGES:
        row[f"{s}_count"] = stage.get(s, 0)
    row["dependencies_count"] = stage.get("dependencies", 0)
    row["reachable_unmapped_count"] = stage.get("reachable_unmapped", 0)
    row["unreachable_count"] = stage.get("unreachable", 0)
    row["unknown_count"] = stage.get("unknown", 0)
    for name, _ in TOOLS:
        row[f"{name}_count"] = tool.get(name, 0)
        row[f"{name}_error"] = result.tool_errors.get(name, "")

    with open(summary_path, "a", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=SUMMARY_COLUMNS)
        if new_file:
            w.writeheader()
        w.writerow(row)


def repo_url_to_filename(url: str) -> str:
    """Convert https://github.com/owner/repo to owner__repo.json."""
    parts = url.rstrip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}__{parts[-1]}.json"
    return url.replace("/", "__").replace(":", "_") + ".json"


def run(verified_csv: str, log_path: str, summary_path: str,
        findings_dir: str, token: str | None = None,
        per_tool_timeout: int = 600) -> None:
    os.makedirs(findings_dir, exist_ok=True)

    with open(verified_csv, "r", encoding="utf-8", newline="") as fh:
        repos = [row["repo"].strip() for row in csv.DictReader(fh) if row.get("repo")]

    done = already_done(log_path)
    todo = [u for u in repos if u not in done]
    print(f"Stage 4: {len(repos)} verified, {len(done)} already done, "
          f"{len(todo)} to scan.", flush=True)

    for i, url in enumerate(todo, start=1):
        owner_repo = "/".join(url.rstrip("/").split("/")[-2:])
        result = scan_one_repo(url, token=token,
                               per_tool_timeout=per_tool_timeout)
        write_log_row(log_path, result)
        write_summary_row(summary_path, result)

        if result.status == "ok":
            fpath = os.path.join(findings_dir, repo_url_to_filename(url))
            dump_findings_json(fpath, result.findings)

        marker = {"ok": "[ok ]", "clone_failed": "[clf]", "error": "[err]"}.get(
            result.status, "[?  ]")
        warn_note = ""
        if result.stage_warnings:
            warn_note = f"  ⚠ {result.stage_warnings[0][:80]}"
        print(f"  [{i:5d}/{len(todo)}] {marker} {owner_repo[:60]:60} "
              f"findings={len(result.findings):4d}  "
              f"t={result.duration_s:5.1f}s{warn_note}", flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("verified_csv",
                    help="Path to verified_corpus.csv from Stage 3")
    ap.add_argument("--log", default="stage4_log.csv",
                    help="Per-repo log (used for resume); default stage4_log.csv")
    ap.add_argument("--summary", default="stage4_summary.csv",
                    help="Aggregated per-repo summary CSV")
    ap.add_argument("--findings-dir", default="stage4_findings",
                    help="Directory to write per-repo JSON findings files")
    ap.add_argument("--tool-timeout", type=int, default=600,
                    help="Per-tool timeout in seconds (default 600)")
    args = ap.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN") or None
    if token:
        print("Using GITHUB_TOKEN for authenticated clones.", flush=True)
    else:
        print("No GITHUB_TOKEN set; clones will be unauthenticated.", flush=True)

    run(args.verified_csv, args.log, args.summary,
        args.findings_dir, token=token,
        per_tool_timeout=args.tool_timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
