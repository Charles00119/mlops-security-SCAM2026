"""Semgrep wrapper. Uses the published p/python and p/security-audit rule packs.

Semgrep exit codes: 0 = clean, 1 = findings present (not an error), >=2 = error.
We allow {0,1}. If --config isn't reachable due to no network, the tool will
fail cleanly and the orchestrator records that without crashing.
"""
from __future__ import annotations

import json

from ..findings import Finding, normalize_severity, to_relative
from ..runner import ToolResult, is_installed, run_tool


_CONFIGS = ["p/python", "p/security-audit"]


def available() -> bool:
    return is_installed("semgrep")


def run(repo_root: str, timeout: int = 600) -> tuple[list[Finding], str]:
    if not available():
        return [], "semgrep not installed"

    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off"]
    for cfg in _CONFIGS:
        cmd += ["--config", cfg]
    cmd.append(repo_root)

    res: ToolResult = run_tool(cmd, timeout=timeout, allowed_returncodes=(0, 1))
    if not res.ok:
        return [], res.error or "semgrep invocation failed"

    try:
        data = json.loads(res.stdout) if res.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        return [], f"semgrep JSON parse: {exc}"

    findings: list[Finding] = []
    for r in data.get("results", []) or []:
        extra = r.get("extra") or {}
        sev = normalize_severity(extra.get("severity"))
        findings.append(Finding(
            tool="semgrep",
            severity=sev,
            rule_id=str(r.get("check_id") or ""),
            file_path=to_relative(repo_root, r.get("path", "")),
            line=int((r.get("start") or {}).get("line") or 0),
            message=str(extra.get("message") or "").strip(),
            snippet=str(extra.get("lines") or "").strip()[:400],
        ))
    return findings, ""
