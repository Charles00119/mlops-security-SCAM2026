"""Bandit wrapper. Runs Bandit recursively on the repo, parses JSON output.

We only keep findings of medium or high severity to cut Bandit's notorious
low-severity noise (asserts, hardcoded TLS verify, etc.). The threshold is
documented in the methodology — adjust here if the paper needs it.
"""
from __future__ import annotations

import json

from ..findings import Finding, normalize_severity, to_relative
from ..runner import ToolResult, is_installed, run_tool


_SEVERITY_FLOOR = {"medium", "high"}


def available() -> bool:
    return is_installed("bandit")


def run(repo_root: str, timeout: int = 300) -> tuple[list[Finding], str]:
    """Return (findings, error). error is '' on success."""
    if not available():
        return [], "bandit not installed"

    cmd = [
        "bandit",
        "-r", repo_root,
        "-f", "json",
        "-q",                          # quiet: suppress progress
        "--exit-zero",                 # never exit nonzero just because findings exist
    ]
    res: ToolResult = run_tool(cmd, timeout=timeout, allowed_returncodes=(0, 1))
    if not res.ok:
        return [], res.error or "bandit invocation failed"

    try:
        data = json.loads(res.stdout) if res.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        return [], f"bandit JSON parse: {exc}"

    findings: list[Finding] = []
    for r in data.get("results", []) or []:
        sev = normalize_severity(r.get("issue_severity"))
        if sev not in _SEVERITY_FLOOR:
            continue
        findings.append(Finding(
            tool="bandit",
            severity=sev,
            rule_id=str(r.get("test_id") or ""),
            file_path=to_relative(repo_root, r.get("filename", "")),
            line=int(r.get("line_number") or 0),
            message=str(r.get("issue_text") or "").strip(),
            snippet=str(r.get("code") or "").strip()[:400],
        ))
    return findings, ""
