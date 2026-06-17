"""Map each finding to one or more pipeline stages.

Strategy: re-run Stages 1-3 on the cloned repo to get the call graph and stage
evidence. For each finding, check which file it's in and which stages have
evidence in that file.

Stage values produced:
  '<stage>'                 — file contributes evidence to that stage
  '<a>+<b>'                 — file contributes to multiple stages
  'reachable_unmapped'      — file is reachable but no stage evidence
  'dependencies'            — finding is in a dependency declaration file
                              (requirements.txt, pyproject.toml, etc.) — these
                              affect the whole environment, not a single stage
  'unreachable'             — file is in repo but not on call graph and not
                              a recognized dependency manifest
  'unknown'                 — finding has no usable file path
"""
from __future__ import annotations

import os
import sys
import traceback
from typing import Iterable

from .findings import Finding

# Make the sibling 'scanner' package importable.
SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)


# File patterns that declare dependencies. Findings in these files are
# environment-level concerns, not stage-specific code issues.
_DEPENDENCY_FILES = (
    "requirements.txt",
    "requirements-dev.txt",
    "dev-requirements.txt",
    "test-requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "setup.py",
    "setup.cfg",
    "environment.yml",
    "environment.yaml",
    "conda.yaml",
    "conda.yml",
)


def _is_dependency_file(rel_path: str) -> bool:
    """True if the path looks like a dependency declaration file."""
    base = os.path.basename(rel_path).lower()
    # match common requirement file names exactly
    if base in (n.lower() for n in _DEPENDENCY_FILES):
        return True
    # match requirements/*.txt (a common organization pattern)
    parts = rel_path.replace("\\", "/").split("/")
    if "requirements" in parts and base.endswith(".txt"):
        return True
    # match *-requirements.txt and requirements-*.txt patterns
    if base.endswith("-requirements.txt") or base.startswith("requirements-"):
        return True
    return False


def build_file_to_stages(repo_root: str) -> tuple[dict[str, set[str]], set[str], list[str]]:
    """Build (file_to_stages, reachable_files_rel, warnings).

    file_to_stages: relative posix path -> set of stages with evidence in that file
    reachable_files_rel: every file on the call graph (regardless of stage)
    warnings: human-readable problems encountered (collected, not printed)
    """
    warnings: list[str] = []
    file_to_stages: dict[str, set[str]] = {}
    reachable_rel: set[str] = set()

    try:
        from scanner.dockerfile_parser import get_entry_points
        from scanner.ast_callgraph import build_call_graph
        from scanner.stage_verifier import verify_stages
    except ImportError as exc:
        warnings.append(f"could not import Stages 1-3: {exc}")
        return file_to_stages, reachable_rel, warnings

    try:
        entry_points = get_entry_points(repo_root)
    except Exception as exc:
        warnings.append(f"get_entry_points failed: {exc}")
        return file_to_stages, reachable_rel, warnings

    if not entry_points:
        warnings.append("no entry points found at stage-mapping time")
        return file_to_stages, reachable_rel, warnings

    call_graphs = []
    for ep in entry_points:
        entry_file = getattr(ep, "entry_file", None) or getattr(ep, "resolved_path", None)
        if not entry_file:
            continue
        try:
            cg = build_call_graph(entry_file, repo_root)
            call_graphs.append(cg)
        except Exception as exc:
            warnings.append(f"build_call_graph failed for {entry_file}: {exc}")

    if not call_graphs:
        warnings.append("no call graphs built")
        return file_to_stages, reachable_rel, warnings

    for cg in call_graphs:
        modules = getattr(cg, "modules", None) or {}
        for abs_path in modules:
            rel = os.path.relpath(abs_path, repo_root).replace(os.sep, "/")
            reachable_rel.add(rel)

    try:
        report = verify_stages(call_graphs, repo_root)
    except Exception as exc:
        warnings.append(f"verify_stages failed: {exc}\n{traceback.format_exc()[:400]}")
        return file_to_stages, reachable_rel, warnings

    for stage_name, files in (getattr(report, "evidence_files", None) or {}).items():
        for rel in files:
            if not rel:
                continue
            rel = rel.replace(os.sep, "/")
            file_to_stages.setdefault(rel, set()).add(stage_name)

    return file_to_stages, reachable_rel, warnings


def annotate_findings(
    findings: Iterable[Finding],
    file_to_stages: dict[str, set[str]],
    reachable_files: set[str],
) -> None:
    """Set finding.stage in place. See module docstring for the value vocabulary."""
    for f in findings:
        rel = (f.file_path or "").replace(os.sep, "/").lstrip("./")
        if not rel:
            f.stage = "unknown"
            continue
        # Stage 1: pipeline-stage attribution if the file has stage evidence.
        if rel in file_to_stages:
            f.stage = "+".join(sorted(file_to_stages[rel]))
            continue
        # Stage 2: dependency files get their own bucket (environment concern).
        if _is_dependency_file(rel):
            f.stage = "dependencies"
            continue
        # Stage 3: file reachable from entry point but no stage signals matched.
        if rel in reachable_files:
            f.stage = "reachable_unmapped"
            continue
        # Stage 4: file exists in repo but not on call graph and not a dep manifest.
        f.stage = "unreachable"
