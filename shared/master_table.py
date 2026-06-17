"""Emit the master per-finding table: ONE ROW PER FINDING, each mapped to
pipeline stage(s), semantic category, and severity with its source.

This is the artifact that demonstrates "every finding is linked to the
pipeline": all static-tool findings and all LLM absent-control findings in a
single flat CSV.

Reads:  stage4_findings/*.json, llm_findings/*.json, verified_corpus.csv
Writes: master_findings.csv with columns:
    repo, tool, rule_id, semantic_category, severity, severity_source,
    file_path, line, stage_raw, stages, n_stages, scope

  stage_raw    the original stage label from stage_mapping (may be 'a+b')
  stages       ';'-joined pipeline stages the finding is attributed to
  scope        'pipeline' | 'dependencies' | 'out_of_scope'
  severity_source  who assigned the severity:
      'bandit_rule'   fixed per-rule severity from Bandit maintainers
      'semgrep_rule'  severity metadata from the Semgrep rule author
      'pip_audit'     wrapper-assigned for dependency advisories
      'policy'        project policy in llm_scan.py (medium default;
                      high for backdoor / prompt-injection / data-poisoning)

Usage:
    python -m stage4.master_table
"""
from __future__ import annotations

import argparse
import csv
import os
import sys

# Reuse the locked mappings and helpers from the taxonomy script so the two
# artifacts can never drift apart.
from stage4.taxonomy import (
    PIPELINE_STAGES, STATIC_RULE_MAP, DROPPED_RULES,
    categorize_static, categorize_llm, load_corpus, load_json_list,
    repo_key_from_url,
)

SEVERITY_SOURCE = {
    "bandit": "bandit_rule",
    "semgrep": "semgrep_rule",
    "pip_audit": "pip_audit",
    "pip-audit": "pip_audit",
    "modelscan": "modelscan_rule",
    "claude_judgment": "policy",
}


def stage_fields(stage_raw: str | None) -> tuple[str, int, str]:
    """Return (stages_joined, n_stages, scope) for a raw stage label."""
    if not stage_raw:
        return "", 0, "out_of_scope"
    if stage_raw == "dependencies":
        return "", 0, "dependencies"
    if stage_raw in ("reachable_unmapped", "unreachable", "unknown"):
        return "", 0, "out_of_scope"
    stages = [p.strip() for p in stage_raw.split("+") if p.strip() in PIPELINE_STAGES]
    if not stages:
        return "", 0, "out_of_scope"
    return ";".join(stages), len(stages), "pipeline"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--findings-dir", default="stage4_findings")
    p.add_argument("--llm-dir",      default="llm_findings")
    p.add_argument("--corpus",       default="verified_corpus.csv")
    p.add_argument("--out",          default="master_findings.csv")
    args = p.parse_args()

    repos = load_corpus(args.corpus)
    n_rows = 0
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["repo", "tool", "rule_id", "semantic_category", "severity",
                    "severity_source", "file_path", "line", "stage_raw",
                    "stages", "n_stages", "scope"])
        for url in repos:
            key = repo_key_from_url(url)
            # Static findings
            for f in load_json_list(os.path.join(args.findings_dir, f"{key}.json")):
                tool = (f.get("tool") or "").lower()
                if tool == "claude_judgment":
                    continue
                rid = f.get("rule_id") or ""
                cat = categorize_static(tool, rid)
                if cat is None:
                    cat = "(dropped)" if (tool, rid) in DROPPED_RULES else "(unmapped)"
                stages, n, scope = stage_fields(f.get("stage"))
                w.writerow([url, tool, rid, cat, f.get("severity") or "",
                            SEVERITY_SOURCE.get(tool, tool),
                            f.get("file_path") or "", f.get("line") or 0,
                            f.get("stage") or "", stages, n, scope])
                n_rows += 1
            # LLM findings
            for f in load_json_list(os.path.join(args.llm_dir, f"{key}.json")):
                if (f.get("tool") or "").lower() != "claude_judgment":
                    continue
                rid = f.get("rule_id") or ""
                cat = categorize_llm(rid) or "(unmapped)"
                stages, n, scope = stage_fields(f.get("stage"))
                w.writerow([url, "claude_judgment", rid, cat,
                            f.get("severity") or "", "policy",
                            f.get("file_path") or "", f.get("line") or 0,
                            f.get("stage") or "", stages, n, scope])
                n_rows += 1

    print(f"[ok] wrote {n_rows} findings to {args.out}")
    print("     every row carries: semantic category + pipeline stage(s) + "
          "severity with its source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
