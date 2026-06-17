#!/usr/bin/env python3
"""
Reorganize the MLOps-security repo by research question.

Run from the repository root (the folder containing scanner/, stage4/,
verified_corpus.csv, .git/, etc.):

    python reorganize_repo.py --dry-run   # show what WOULD happen (no changes)
    python reorganize_repo.py             # do it

Uses `git mv` so moves are tracked as renames. Shared scripts that serve
multiple RQs are COPIED into each RQ folder, canonical copy kept in shared/.
Files listed but absent are reported and skipped. Tailored to the actual
file tree from `git ls-files`.
"""
import argparse, os, shutil, subprocess, sys

DIRS = [
    "00_corpus/scanner", "00_corpus/data",
    "rq1_static_taxonomy/code/tools", "rq1_static_taxonomy/data", "rq1_static_taxonomy/figures",
    "rq2_llm_defenses/code", "rq2_llm_defenses/data", "rq2_llm_defenses/figures",
    "rq3_maturity_discourse/code", "rq3_maturity_discourse/data", "rq3_maturity_discourse/figures",
    "shared", "_archive",
]

# (source, destination). Directories move whole.
MOVES = [
    # ---- 00_corpus ----
    ("scanner", "00_corpus/scanner"),
    ("verified_corpus.csv", "00_corpus/data/verified_corpus.csv"),
    ("corpus_metrics.csv", "00_corpus/data/corpus_metrics.csv"),
    ("call_graphs", "00_corpus/data/call_graphs"),
    ("list_of_repositories.xlsx", "00_corpus/data/list_of_repositories.xlsx"),

    # ---- shared (canonical) ----
    ("stage4/stage_mapping.py", "shared/stage_mapping.py"),
    ("stage4/findings.py", "shared/findings.py"),
    ("stage4/master_table.py", "shared/master_table.py"),
    ("stage4/__init__.py", "shared/__init__.py"),
    ("master_findings.csv", "shared/master_findings.csv"),

    # ---- rq1: static taxonomy ----
    ("stage4/tools/__init__.py", "rq1_static_taxonomy/code/tools/__init__.py"),
    ("stage4/tools/bandit_tool.py", "rq1_static_taxonomy/code/tools/bandit_tool.py"),
    ("stage4/tools/semgrep_tool.py", "rq1_static_taxonomy/code/tools/semgrep_tool.py"),
    ("stage4/tools/pip_audit_tool.py", "rq1_static_taxonomy/code/tools/pip_audit_tool.py"),
    ("stage4/tools/modelscan_tool.py", "rq1_static_taxonomy/code/tools/modelscan_tool.py"),
    ("stage4/tools/gitleaks_tool.py", "rq1_static_taxonomy/code/tools/gitleaks_tool.py"),
    ("stage4/tools/nbdefense_tool.py", "rq1_static_taxonomy/code/tools/nbdefense_tool.py"),
    ("stage4/orchestrator.py", "rq1_static_taxonomy/code/orchestrator.py"),
    ("stage4/runner.py", "rq1_static_taxonomy/code/runner.py"),
    ("stage4/taxonomy.py", "rq1_static_taxonomy/code/taxonomy.py"),
    ("stage4/dump_rule_ids.py", "rq1_static_taxonomy/code/dump_rule_ids.py"),
    ("stage4_findings", "rq1_static_taxonomy/data/stage4_findings"),
    ("taxonomy_static_matrix.csv", "rq1_static_taxonomy/data/taxonomy_static_matrix.csv"),
    ("taxonomy_static_rules.csv", "rq1_static_taxonomy/data/taxonomy_static_rules.csv"),
    ("stage_summary.csv", "rq1_static_taxonomy/data/stage_summary.csv"),
    ("rule_ids.csv", "rq1_static_taxonomy/data/rule_ids.csv"),
    ("pipeline_figure.png", "rq1_static_taxonomy/figures/pipeline_figure.png"),
    ("pipeline_figure.svg", "rq1_static_taxonomy/figures/pipeline_figure.svg"),

    # ---- rq2: LLM defenses ----
    ("stage4/llm_scan.py", "rq2_llm_defenses/code/llm_scan.py"),
    ("stage4/crossval.py", "rq2_llm_defenses/code/crossval.py"),
    ("llm_findings", "rq2_llm_defenses/data/llm_findings"),
    ("taxonomy_llm_matrix.csv", "rq2_llm_defenses/data/taxonomy_llm_matrix.csv"),
    ("llm_scan_log.csv", "rq2_llm_defenses/data/llm_scan_log.csv"),
    ("crossval_log.csv", "rq2_llm_defenses/data/crossval_log.csv"),
    ("crossval_summary.csv", "rq2_llm_defenses/data/crossval_summary.csv"),
    ("crossval_sample.csv", "rq2_llm_defenses/data/crossval_sample.csv"),

    # ---- rq3: maturity + discourse ----
    ("stage4/loc_count.py", "rq3_maturity_discourse/code/loc_count.py"),
    ("stage4/fetch_github_extras.py", "rq3_maturity_discourse/code/fetch_github_extras.py"),
    ("stage4/correlate.py", "rq3_maturity_discourse/code/correlate.py"),
    ("fetch_repo_metrics.py", "rq3_maturity_discourse/code/fetch_repo_metrics.py"),
    ("loc.csv", "rq3_maturity_discourse/data/loc.csv"),
    ("github_repo_extras.csv", "rq3_maturity_discourse/data/github_repo_extras.csv"),
    ("correlation_data.csv", "rq3_maturity_discourse/data/correlation_data.csv"),
    ("correlation_table.csv", "rq3_maturity_discourse/data/correlation_table.csv"),
    ("closed_issues.csv", "rq3_maturity_discourse/data/closed_issues.csv"),
    ("correlation_plots.png", "rq3_maturity_discourse/figures/correlation_plots.png"),

    # ---- _archive: superseded / scratch (kept, not deleted) ----
    ("mlops_security_findings.csv", "_archive/mlops_security_findings.csv"),
    ("sample.csv", "_archive/sample.csv"),
    ("scan_log.csv", "_archive/scan_log.csv"),
    ("stage4_log.csv", "_archive/stage4_log.csv"),
    ("stage4_summary.csv", "_archive/stage4_summary.csv"),
    ("stage4/img.png", "_archive/img.png"),
]

# Copies: shared scripts duplicated into RQ folders (run AFTER moves).
COPIES = [
    ("shared/stage_mapping.py", "rq1_static_taxonomy/code/stage_mapping.py"),
    ("shared/master_table.py",  "rq1_static_taxonomy/code/master_table.py"),
    ("shared/findings.py",      "rq1_static_taxonomy/code/findings.py"),
    ("shared/stage_mapping.py", "rq2_llm_defenses/code/stage_mapping.py"),
    ("shared/findings.py",      "rq2_llm_defenses/code/findings.py"),
    ("rq1_static_taxonomy/code/taxonomy.py", "rq2_llm_defenses/code/taxonomy.py"),
]

def sh(cmd, dry):
    print("  $", " ".join(cmd))
    if not dry:
        subprocess.run(cmd, check=False)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(); dry = args.dry_run
    if not os.path.isdir(".git"):
        print("ERROR: run from the repo root (no .git/ here)."); sys.exit(1)

    print("== creating folders ==")
    for d in DIRS:
        print("  mkdir", d)
        if not dry:
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, ".gitkeep"), "a").close()

    print("\n== moving files (git mv) ==")
    moved, missing = 0, []
    for src, dst in MOVES:
        if os.path.exists(src):
            if not dry: os.makedirs(os.path.dirname(dst), exist_ok=True)
            sh(["git", "mv", src, dst], dry); moved += 1
        else:
            missing.append(src)

    print("\n== copying shared scripts into RQ folders ==")
    for src, dst in COPIES:
        if dry:
            print(f"  cp {src} -> {dst}  (after moves)"); continue
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst); subprocess.run(["git","add",dst], check=False)
            print(f"  cp {src} -> {dst}")
        else:
            missing.append(src + " (for copy)")

    print("\n== summary ==")
    print(f"  moved/queued: {moved}")
    if missing:
        print(f"  NOT FOUND (skipped): {len(missing)}")
        for m in missing: print("    -", m)
    print("\nNext: 1) check imports  2) git status  3) git commit  4) git push")
    if dry: print("\n(DRY RUN — nothing changed.)")

if __name__ == "__main__":
    main()
