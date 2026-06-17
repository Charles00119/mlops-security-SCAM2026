"""NBDefense wrapper. Scans Jupyter notebooks for security issues.

Only runs if the repo contains .ipynb files. NBDefense has its own scan
command and JSON output format.
"""
from __future__ import annotations

import json
import os

from ..findings import Finding, normalize_severity, to_relative
from ..runner import ToolResult, is_installed, run_tool


def available() -> bool:
    return is_installed("nbdefense")


def _has_notebooks(repo_root: str) -> bool:
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in (
            ".git", "node_modules", "__pycache__", ".ipynb_checkpoints"
        )]
        for fn in files:
            if fn.endswith(".ipynb"):
                return True
    return False


def run(repo_root: str, timeout: int = 600) -> tuple[list[Finding], str]:
    if not available():
        return [], "nbdefense not installed"
    if not _has_notebooks(repo_root):
        return [], ""  # nothing to scan, not an error

    cmd = ["nbdefense", "scan", repo_root, "--output-format", "json", "--quiet"]
    res: ToolResult = run_tool(cmd, timeout=timeout, allowed_returncodes=(0, 1, 2))
    if not res.ok:
        return [], res.error or "nbdefense invocation failed"

    try:
        data = json.loads(res.stdout) if res.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        return [], f"nbdefense JSON parse: {exc}"

    findings: list[Finding] = []
    # nbdefense json shape varies by version; defensively try both common shapes
    issues = data.get("findings") or data.get("issues") or data.get("results") or []
    for r in issues:
        sev = normalize_severity(r.get("severity"))
        findings.append(Finding(
            tool="nbdefense",
            severity=sev,
            rule_id=str(r.get("rule_id") or r.get("id") or "nb")[:60],
            file_path=to_relative(repo_root, r.get("file") or r.get("path") or ""),
            line=int(r.get("line") or r.get("cell") or 0),
            message=str(r.get("message") or r.get("description") or "").strip()[:300],
            snippet=str(r.get("snippet") or r.get("code") or "")[:400],
        ))
    return findings, ""
