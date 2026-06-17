"""Gitleaks wrapper. Scans the repo working tree for committed secrets.

Gitleaks exit codes: 0 = clean, 1 = leaks found, others = error.
We use `--no-git` because we're cloning with --depth 1 and don't have full
history; gitleaks would otherwise complain about the missing git log.
"""
from __future__ import annotations

import json
import os
import tempfile

from ..findings import Finding, to_relative
from ..runner import ToolResult, is_installed, run_tool


def available() -> bool:
    return is_installed("gitleaks")


def run(repo_root: str, timeout: int = 300) -> tuple[list[Finding], str]:
    if not available():
        return [], "gitleaks not installed"

    # gitleaks writes findings to a JSON file via -r
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
        report_path = tf.name

    try:
        cmd = [
            "gitleaks", "detect",
            "--source", repo_root,
            "--report-format", "json",
            "--report-path", report_path,
            "--no-git",
            "--no-banner",
            "--exit-code", "0",  # don't error just because leaks exist
        ]
        res: ToolResult = run_tool(cmd, timeout=timeout, allowed_returncodes=(0, 1))
        if not res.ok:
            return [], res.error or "gitleaks invocation failed"

        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return [], ""  # no report file = no leaks, common case

        findings: list[Finding] = []
        for leak in data or []:
            findings.append(Finding(
                tool="gitleaks",
                severity="high",  # leaked secrets are always high impact
                rule_id=str(leak.get("RuleID") or ""),
                file_path=to_relative(repo_root, leak.get("File", "")),
                line=int(leak.get("StartLine") or 0),
                message=str(leak.get("Description") or "leaked secret").strip(),
                snippet=str(leak.get("Match") or "")[:200],
            ))
        return findings, ""
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass
