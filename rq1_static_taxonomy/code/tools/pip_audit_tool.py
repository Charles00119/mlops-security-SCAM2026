"""pip-audit wrapper. Scans requirements files for vulnerable dependencies.

We look for the common requirement-file shapes (requirements.txt, dev-requirements,
pyproject.toml). If none exist we return no findings without erroring — many repos
don't pin dependencies in scannable formats and that's a separate observation,
not a tool failure.
"""
from __future__ import annotations

import json
import os

from ..findings import Finding
from ..runner import ToolResult, is_installed, run_tool


_REQ_PATTERNS = (
    "requirements.txt",
    "requirements-dev.txt",
    "dev-requirements.txt",
    "requirements/base.txt",
    "requirements/prod.txt",
    "requirements/production.txt",
)


def available() -> bool:
    return is_installed("pip-audit")


def _find_requirement_files(repo_root: str) -> list[str]:
    """Find scannable requirements.txt-style files (best-effort, top 2 levels)."""
    found: list[str] = []
    for pat in _REQ_PATTERNS:
        full = os.path.join(repo_root, pat)
        if os.path.isfile(full):
            found.append(full)
    # also check requirements/*.txt
    req_dir = os.path.join(repo_root, "requirements")
    if os.path.isdir(req_dir):
        for fn in os.listdir(req_dir):
            if fn.endswith(".txt"):
                full = os.path.join(req_dir, fn)
                if full not in found:
                    found.append(full)
    return found


def run(repo_root: str, timeout: int = 180) -> tuple[list[Finding], str]:
    if not available():
        return [], "pip-audit not installed"

    req_files = _find_requirement_files(repo_root)
    pyproject = os.path.join(repo_root, "pyproject.toml")
    has_pyproject = os.path.isfile(pyproject)

    if not req_files and not has_pyproject:
        return [], ""  # not an error, just nothing to scan

    findings: list[Finding] = []
    for req in req_files:
        rel = os.path.relpath(req, repo_root).replace(os.sep, "/")
        cmd = ["pip-audit", "-r", req, "-f", "json", "--progress-spinner=off"]
        res: ToolResult = run_tool(cmd, cwd=repo_root, timeout=timeout,
                                   allowed_returncodes=(0, 1))
        if not res.ok:
            continue  # skip this file, keep going with others
        try:
            data = json.loads(res.stdout) if res.stdout.strip() else {}
        except json.JSONDecodeError:
            continue
        for dep in (data.get("dependencies") or []):
            pkg = dep.get("name", "?")
            version = dep.get("version", "?")
            for vuln in (dep.get("vulns") or []):
                vid = vuln.get("id", "unknown")
                desc = (vuln.get("description") or "").strip()
                fix = ", ".join(vuln.get("fix_versions") or []) or "no fix listed"
                findings.append(Finding(
                    tool="pip_audit",
                    severity="medium",         # pip-audit doesn't classify
                    rule_id=vid,
                    file_path=rel,
                    line=0,
                    message=f"{pkg} {version}: {desc[:200]} (fix: {fix})",
                    snippet=f"{pkg}=={version}",
                ))
    return findings, ""
