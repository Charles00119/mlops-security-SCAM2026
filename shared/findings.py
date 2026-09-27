"""Shared data structures for Stage 4 scanner output.

Every tool wrapper returns list[Finding]. The orchestrator collects them,
maps each finding to a pipeline stage using the import-reachability graph from Stages 1-3,
and writes both detailed JSON (per repo) and summary CSV (across repos).
"""
from __future__ import annotations

import dataclasses
import json
import os
from typing import Any


@dataclasses.dataclass
class Finding:
    """One finding from any tool. Universal schema across the suite."""
    tool: str                 # 'bandit', 'semgrep', 'pip_audit', ...
    severity: str             # 'high' | 'medium' | 'low' | 'info' | 'unknown'
    rule_id: str              # CWE-XXX, B301, etc. — tool-native id
    file_path: str            # relative to repo root, posix-style
    line: int                 # 0 if unknown / not applicable
    message: str              # short human-readable description
    snippet: str = ""         # offending code line(s), best-effort
    stage: str = ""           # filled in by orchestrator after stage mapping

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def normalize_severity(value: Any) -> str:
    """Coerce a tool-specific severity into the common vocabulary."""
    if value is None:
        return "unknown"
    s = str(value).strip().lower()
    if s in {"critical", "very high", "veryhigh"}:
        return "high"
    if s in {"high", "error"}:
        return "high"
    if s in {"medium", "moderate", "warning", "med"}:
        return "medium"
    if s in {"low", "info", "informational", "note"}:
        return "low" if s == "low" else "info"
    return s or "unknown"


def to_relative(repo_root: str, file_path: str) -> str:
    """Best-effort conversion of an absolute path to repo-relative posix."""
    if not file_path:
        return ""
    try:
        rel = os.path.relpath(file_path, repo_root)
    except (ValueError, TypeError):
        rel = file_path
    return rel.replace(os.sep, "/")


def dump_findings_json(path: str, findings: list[Finding]) -> None:
    """Write findings to a JSON file as a list of dicts."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([f.as_dict() for f in findings], fh, indent=2, ensure_ascii=False)
