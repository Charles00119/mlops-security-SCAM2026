"""
Orchestrator — clone-one-at-a-time scanner loop.

For each repository in the input list:
    1. shallow-clone it to a temp dir
    2. run Stage 1 (Dockerfile entry point, or a conventional root entry file
       such as main.py when no Dockerfile resolves) + Stage 2 (AST import-
       reachability graph; see ast_callgraph.py for what that is and is not)
    3. [Stage 3 + 4 plug in here — vulnerability judgment, not yet built]
    4. append a result row to the output CSV
    5. delete the clone
    6. continue

Survival features (carried over from the old scanner):
    - incremental CSV writes: a crash never loses completed work
    - resume support: re-reading the CSV on startup skips done repos
    - per-repo cleanup in a finally block: a clone is removed even on error
    - per-repo timeout on git clone so one bad repo can't hang the run

Requires `git` on PATH. A GitHub token is optional but strongly recommended —
anonymous clones are rate-limited. Set it via the GITHUB_TOKEN env var.
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import asdict, dataclass, field

# Stage 1 + 2 + 3 — must sit alongside this file.
from dockerfile_parser import get_entry_points
from ast_callgraph import build_call_graph, notebook_to_module
from stage_verifier import verify_stages, STAGE_SIGNALS


# ---------------------------------------------------------------------------
# Result model — one row per repo in scan_log.csv
# ---------------------------------------------------------------------------

_STAGES = list(STAGE_SIGNALS.keys())  # data_acquisition, data_preparation, ...


@dataclass
class RepoResult:
    """One row in scan_log.csv — every repo, included or not, with full evidence."""
    repo: str
    status: str                       # 'ok' | 'no_dockerfile' | 'no_entry' | 'clone_failed' | 'error'
    verified: bool = False            # passes strict-corpus filter (all 6 stages present)
    stages_present: int = 0           # count of stages found (0..6)
    dockerfiles_found: int = 0
    entry_points_resolved: int = 0
    entry_files: str = ""             # ';'-joined list (multi-Dockerfile repos)
    reachable_files: int = 0
    total_functions: int = 0
    max_depth: int = 0
    parse_errors: int = 0
    dynamic_imports: int = 0
    # Stage presence + evidence (one column per stage, plus its evidence cell).
    data_acquisition: bool = False
    data_acquisition_evidence: str = ""
    data_preparation: bool = False
    data_preparation_evidence: str = ""
    modeling: bool = False
    modeling_evidence: str = ""
    training: bool = False
    training_evidence: str = ""
    evaluation: bool = False
    evaluation_evidence: str = ""
    inference: bool = False
    inference_evidence: str = ""
    detail: str = ""                  # free-text: error message or notes


CSV_FIELDS = list(RepoResult.__dataclass_fields__.keys())


# ---------------------------------------------------------------------------
# Resume support
# ---------------------------------------------------------------------------

def load_done_repos(csv_path: str) -> set[str]:
    """Return the set of repos already in the output CSV, so we can skip them."""
    if not os.path.isfile(csv_path):
        return set()
    done: set[str] = set()
    with open(csv_path, "r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("repo"):
                done.add(row["repo"])
    return done


def append_result(csv_path: str, result: RepoResult) -> None:
    """Append one result row, writing the header if the file is new."""
    new_file = not os.path.isfile(csv_path)
    with open(csv_path, "a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(asdict(result))


# ---------------------------------------------------------------------------
# Clone
# ---------------------------------------------------------------------------

class CloneError(Exception):
    """A clone failed — carries a single clean reason string."""


def clone_repo(repo_url: str, dest: str, token: str | None, timeout: int = 300) -> None:
    """Shallow-clone one repo. Raises CloneError(reason) or TimeoutExpired."""
    url = repo_url
    if token and url.startswith("https://github.com/"):
        # Authenticated clone — much higher rate limit.
        url = url.replace("https://github.com/", f"https://{token}@github.com/")

    proc = subprocess.run(
        ["git", "-c", "core.longpaths=true",   # Windows: tolerate >260-char paths
         "clone", "--depth", "1", "--quiet", url, dest],
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        # Pick the most informative line of git's output as the reason.
        err = (proc.stderr or proc.stdout or "").strip()
        reason = "git clone failed"
        for line in err.splitlines():
            low = line.lower()
            if any(k in low for k in ("fatal:", "error:", "not found",
                                      "could not", "denied", "rate limit")):
                reason = line.strip()
                break
        # Strip the token out of any echoed URL before logging.
        if token:
            reason = reason.replace(token, "***")
        raise CloneError(reason[:300])


# ---------------------------------------------------------------------------
# The per-repo scan  (Stage 1 + 2 today; Stage 3 + 4 plug in here later)
# ---------------------------------------------------------------------------

def analyze_repo(repo_url: str, repo_dir: str) -> RepoResult:
    """Run Stage 1 + 2 over a cloned repo and summarize.

    STAGE 3 + 4 SEAM: once the stage classifier and sink/guard + LLM detector
    exist, call them here on `graph` and extend RepoResult with their output.
    """
    result = RepoResult(repo=repo_url, status="ok")

    entry_points = get_entry_points(repo_dir)
    result.dockerfiles_found = sum(1 for ep in entry_points if ep.dockerfile_path != "(fallback)")
    resolved = [ep for ep in entry_points if ep.resolved]
    result.entry_points_resolved = len(resolved)

    if not entry_points:
        result.status = "no_dockerfile"
        result.detail = "no Dockerfile and no fallback entry point found"
        return result
    if not resolved:
        result.status = "no_entry"
        result.detail = "Dockerfile(s) found but no Python entry point could be resolved"
        return result

    # Build a call graph for every resolved entry point — a repo with multiple
    # Dockerfiles (train + serve) gets each pipeline traced and unioned.
    call_graphs = []
    entry_files: list[str] = []
    parse_err = 0
    dyn_imports = 0
    max_depth = 0

    for ep in resolved:
        entry_file = ep.entry_file
        if entry_file and entry_file.endswith(".ipynb"):
            synthetic = os.path.join(repo_dir, "_entry_from_notebook.py")
            entry_file = notebook_to_module(entry_file, synthetic)
        if not entry_file:
            continue

        graph = build_call_graph(entry_file, repo_dir)
        call_graphs.append(graph)
        s = graph.summary()
        entry_files.append(os.path.relpath(entry_file, repo_dir))
        parse_err += len(s["parse_errors"])
        dyn_imports += len(s["dynamic_import_sites"])
        max_depth = max(max_depth, s["max_depth"])

    if not call_graphs:
        result.status = "no_entry"
        result.detail = "no resolved entry point yielded a usable call graph"
        return result

    # Union of all reachable files across this repo's pipelines.
    reachable_paths: set[str] = set()
    total_functions = 0
    for cg in call_graphs:
        for path, mod in cg.modules.items():
            if path not in reachable_paths:
                reachable_paths.add(path)
                total_functions += len(mod.functions)

    result.entry_files = ";".join(entry_files)
    result.reachable_files = len(reachable_paths)
    result.total_functions = total_functions
    result.max_depth = max_depth
    result.parse_errors = parse_err
    result.dynamic_imports = dyn_imports

    # ----- Stage 3: verify pipeline stages in the unioned reachable code -----
    report = verify_stages(call_graphs, repo_dir)
    result.stages_present = report.present_count
    result.verified = report.all_six_present

    for stage in _STAGES:
        setattr(result, stage, report.present.get(stage, False))
        ev = report.evidence.get(stage)
        if ev is not None:
            setattr(result, f"{stage}_evidence",
                    f"{ev.rel_path}:{ev.line} {ev.call_name} [matched {ev.matched_signal}]")

    if result.verified:
        result.status = "ok"
        result.detail = f"verified: all 6 stages present"
    else:
        result.status = "ok"  # the scan itself succeeded
        missing = [s for s in _STAGES if not report.present.get(s)]
        result.detail = f"unverified: missing stages: {', '.join(missing)}"
    return result


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(repo_list: list[str], log_path: str, verified_path: str, token: str | None) -> None:
    """Main scan loop: every repo to log_path, verified-passes to verified_path."""
    done = load_done_repos(log_path)
    if done:
        print(f"Resuming — {len(done)} repos already scanned, will be skipped.")

    total = len(repo_list)
    # Running tallies for the live progress line.
    counts = {"ok": 0, "verified": 0, "no_dockerfile": 0, "no_entry": 0,
              "clone_failed": 0, "error": 0}

    for i, repo_url in enumerate(repo_list, 1):
        if repo_url in done:
            continue

        tmp = tempfile.mkdtemp(prefix="scan_")
        repo_dir = os.path.join(tmp, "repo")
        result: RepoResult

        try:
            try:
                clone_repo(repo_url, repo_dir, token)
            except subprocess.TimeoutExpired:
                result = RepoResult(repo=repo_url, status="clone_failed", detail="clone timed out")
            except CloneError as exc:
                result = RepoResult(repo=repo_url, status="clone_failed", detail=str(exc))
            else:
                try:
                    result = analyze_repo(repo_url, repo_dir)
                except Exception as exc:  # noqa: BLE001 — one bad repo must not kill the run
                    result = RepoResult(
                        repo=repo_url, status="error",
                        detail=f"{type(exc).__name__}: {exc}".replace("\n", " ")[:300],
                    )
                    traceback.print_exc()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        # Log every repo, always.
        append_result(log_path, result)
        # Strict-corpus output: only the verified passes.
        if result.verified:
            append_result(verified_path, result)

        # Update tallies + a compact, scrollback-friendly progress line.
        counts[result.status if result.status in counts else "error"] = \
            counts.get(result.status, 0) + 1
        if result.verified:
            counts["verified"] += 1
        flag = "✓" if result.verified else " "
        short = repo_url.split("github.com/")[-1][:42]
        print(f"[{i:>5}/{total}] {flag} {short:<44} "
              f"{result.status:<14} stages={result.stages_present}/6  "
              f"files={result.reachable_files}")

        time.sleep(0.3)  # gentle pacing for the GitHub side

    # ---- final summary ----
    print()
    print("=" * 60)
    print("SCAN COMPLETE")
    print(f"  Total repos scanned : {total}")
    print(f"  Verified (all 6)    : {counts['verified']}")
    print(f"  Scanned ok          : {counts['ok']}")
    print(f"  No Dockerfile       : {counts['no_dockerfile']}")
    print(f"  No entry point      : {counts['no_entry']}")
    print(f"  Clone failed        : {counts['clone_failed']}")
    print(f"  Errors              : {counts['error']}")
    print()
    print(f"  Full log     -> {log_path}")
    print(f"  Verified set -> {verified_path}")


# ---------------------------------------------------------------------------
# Repo-list loading + CLI
# ---------------------------------------------------------------------------

_URL_COLS = ("html_url", "gh_html_url", "url", "repo", "repository")


def _norm(val: str) -> str:
    """Normalize a cell to a full https github URL."""
    val = (val or "").strip()
    if not val:
        return ""
    return val if val.startswith("http") else f"https://github.com/{val}"


def load_repo_list(path: str) -> list[str]:
    """Load repo URLs from a .txt (one per line), .csv, or .xlsx.

    For .csv / .xlsx the file must have one of these columns: html_url,
    gh_html_url, url, repo, repository.
    """
    repos: list[str] = []

    if path.endswith(".xlsx"):
        try:
            import openpyxl  # noqa: PLC0415
        except ImportError:
            raise SystemExit("Reading .xlsx needs openpyxl:  pip install openpyxl")
        wb = openpyxl.load_workbook(path, read_only=True)
        ws = wb.active
        rows = list(ws.iter_rows(values_only=True))
        if not rows:
            raise SystemExit("Spreadsheet is empty.")
        header = [str(c).lower() if c is not None else "" for c in rows[0]]
        col = next((header.index(c) for c in _URL_COLS if c in header), None)
        if col is None:
            raise SystemExit(f"Spreadsheet needs one of these columns: {_URL_COLS}")
        for row in rows[1:]:
            if col < len(row):
                url = _norm(str(row[col]) if row[col] is not None else "")
                if url:
                    repos.append(url)

    elif path.endswith(".csv"):
        with open(path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            url_col = next((c for c in (reader.fieldnames or [])
                            if c.lower() in _URL_COLS), None)
            if url_col is None:
                raise SystemExit(f"CSV needs one of these columns: {_URL_COLS}")
            for row in reader:
                url = _norm(row.get(url_col, ""))
                if url:
                    repos.append(url)

    else:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                val = line.strip()
                if val and not val.startswith("#"):
                    repos.append(_norm(val))

    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique = [r for r in repos if not (r in seen or seen.add(r))]
    return unique


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python orchestrator.py <repo-list> [scan_log.csv] [verified_corpus.csv]")
        print("       repo-list may be .xlsx / .csv / .txt")
        print("env  : GITHUB_TOKEN  (optional, recommended)")
        raise SystemExit(1)

    repo_list = load_repo_list(sys.argv[1])
    log_csv = sys.argv[2] if len(sys.argv) > 2 else "scan_log.csv"
    verified_csv = sys.argv[3] if len(sys.argv) > 3 else "verified_corpus.csv"
    gh_token = os.environ.get("GITHUB_TOKEN") or None
    if not gh_token:
        print("WARNING: no GITHUB_TOKEN set — anonymous clones are rate-limited.")

    print(f"Loaded {len(repo_list)} repositories.")
    print(f"  Full scan log    -> {log_csv}")
    print(f"  Verified corpus  -> {verified_csv}\n")
    run(repo_list, log_csv, verified_csv, gh_token)
