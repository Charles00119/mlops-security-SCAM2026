"""Stage 4 tool wrappers. Each module exposes available() and run(repo_root)."""
from . import bandit_tool, semgrep_tool, pip_audit_tool, gitleaks_tool
from . import modelscan_tool, nbdefense_tool

# Registry the orchestrator iterates over. Order is informational only —
# tools run independently and can be added/removed without touching orchestrator.
TOOLS = [
    ("bandit", bandit_tool),
    ("semgrep", semgrep_tool),
    ("pip_audit", pip_audit_tool),
    ("gitleaks", gitleaks_tool),
    ("modelscan", modelscan_tool),
    ("nbdefense", nbdefense_tool),
]
