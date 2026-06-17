"""Stage 4: scanner suite for verified MLOps pipelines.

Runs Bandit, Semgrep, pip-audit, Gitleaks, ModelScan, and NBDefense on each
verified repository, maps findings to pipeline stages using the Stage 2 call
graph, and aggregates per-repo and per-stage statistics for the paper.
"""
