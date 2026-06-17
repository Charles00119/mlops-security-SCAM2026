"""ModelScan wrapper. Scans serialized model files for unsafe operations.

Searches the repo for files with extensions modelscan supports (.pkl, .pt, .h5,
.bin, .pb, .keras, .joblib, .pickle, .dill), runs modelscan on each, parses JSON.
"""
from __future__ import annotations

import json
import os

from ..findings import Finding, normalize_severity, to_relative
from ..runner import ToolResult, is_installed, run_tool


_MODEL_EXTS = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".h5", ".keras",
               ".pb", ".joblib", ".dill")


def available() -> bool:
    return is_installed("modelscan")


def _find_model_files(repo_root: str, cap: int = 50) -> list[str]:
    """Find candidate model files. Capped to avoid pathological repos."""
    out: list[str] = []
    for root, dirs, files in os.walk(repo_root):
        # skip common non-model dirs to save time
        dirs[:] = [d for d in dirs if d not in (
            ".git", "node_modules", "__pycache__", ".venv", "venv", "env"
        )]
        for fn in files:
            if fn.lower().endswith(_MODEL_EXTS):
                out.append(os.path.join(root, fn))
                if len(out) >= cap:
                    return out
    return out


def run(repo_root: str, timeout: int = 120) -> tuple[list[Finding], str]:
    if not available():
        return [], "modelscan not installed"

    model_files = _find_model_files(repo_root)
    if not model_files:
        return [], ""  # nothing to scan, not an error

    findings: list[Finding] = []
    for mf in model_files:
        rel = to_relative(repo_root, mf)
        cmd = ["modelscan", "-p", mf, "-r", "json"]
        res: ToolResult = run_tool(cmd, timeout=timeout,
                                   allowed_returncodes=(0, 1, 2, 3))
        if not res.ok:
            continue
        try:
            data = json.loads(res.stdout) if res.stdout.strip() else {}
        except json.JSONDecodeError:
            continue

        for issue in (data.get("issues") or []):
            sev = normalize_severity(issue.get("severity"))
            findings.append(Finding(
                tool="modelscan",
                severity=sev,
                rule_id=str(issue.get("description") or "unsafe_op")[:60],
                file_path=rel,
                line=0,
                message=str(issue.get("description") or "unsafe model op")[:300],
                snippet=str(issue.get("operator") or "")[:100],
            ))
    return findings, ""
