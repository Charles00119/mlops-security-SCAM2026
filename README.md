# Security Threats in MLOps Pipelines

Replication package for the ISSRE 2026 paper *"Security Threats in MLOps
Pipelines: An Empirical Study"* (C. Wehbe, J. Elia; supervisor: Prof. Barrak).

We study the software-security posture of 408 open-source MLOps pipelines,
verified end-to-end by Dockerfile-rooted call-graph analysis, across three
research questions: a static threat taxonomy (RQ1), an LLM-based audit of
ML-specific defensive controls (RQ2), and a maturity/discourse analysis
(RQ3).

## Repository layout

```
scanner/            Stages 1-3: Dockerfile parsing, AST call graph, stage verification
stage4/             Stage 4 + analysis:
  tools/              per-tool wrappers (Bandit, Semgrep, pip-audit, ModelScan)
  llm_scan.py         LLM defensive-control audit (RQ2)
  crossval.py         GPT-4o cross-validation
  stage_mapping.py    maps findings to pipeline stages via the call graph
  taxonomy.py         builds the stage x category matrices + figure (RQ1)
  master_table.py     emits master_findings.csv (every finding, fully attributed)
  loc_count.py        reachable lines of code per repo (RQ3 denominator)
  fetch_github_extras.py  GitHub metrics + closed-issue retrieval (RQ3)
  correlate.py        maturity vs. vulnerability-density correlations (RQ3)
data/               released artifacts (see below)
paper/              LaTeX source
```

## Released data artifacts

| File | Contents |
|------|----------|
| `verified_corpus.csv` | the 408 verified repositories |
| `stage4_findings/` | per-repo static-tool findings (one JSON per repo) |
| `llm_findings/` | per-repo LLM absent-control findings |
| `call_graphs/` | per-repo call-graph file lists (reproducibility) |
| `master_findings.csv` | all 11,389 findings, one row each, with stage/category/severity |
| `taxonomy_static_matrix.csv` | stage x 15 threat categories |
| `taxonomy_llm_matrix.csv` | stage x 13 defensive controls |
| `taxonomy_static_rules.csv` | rule_id -> category audit trail |
| `correlation_data.csv` | per-repo maturity metrics + finding counts + density |
| `closed_issues.csv` | closed issues from the 20 most-discussed repos |

## Reproducing the analysis

Findings are already released, so the taxonomy and figures can be rebuilt
without re-scanning:

```bash
pip install -r requirements.txt
python -m stage4.taxonomy        # RQ1 matrices + pipeline figure
python -m stage4.master_table    # master_findings.csv
python -m stage4.correlate       # RQ3 correlations + plots
```

Steps that hit the network (optional; require a GitHub token):

```bash
export GITHUB_TOKEN=...           # public-repo read scope is enough
python -m stage4.loc_count
python -m stage4.fetch_github_extras --mode metrics
python -m stage4.fetch_github_extras --mode issues --top 20
```

## Citation

```bibtex
@inproceedings{wehbe2026mlops,
  title     = {Security Threats in MLOps Pipelines: An Empirical Study},
  author    = {Wehbe, Charles and Elia, Justin and Barrak, Amine},
  booktitle = {Proc. IEEE Int. Symp. Software Reliability Engineering (ISSRE)},
  year      = {2026}
}
```
