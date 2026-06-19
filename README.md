# Security Threats and Missing Defenses in Open Source MLOps Pipelines

Replication package for the **SCAM 2026** paper
*"Security Threats and Missing Defenses in Open Source MLOps Pipelines:
A Large-Scale Empirical Study of Deployed Machine Learning Repositories"*
(C. Wehbe, A. Barrak, E. Ksontini).

We study the software-security posture of **408 open-source MLOps
pipelines**, verified end-to-end by Dockerfile-rooted call-graph analysis,
across three research questions:

- **RQ1** — a static threat taxonomy over the deployed code.
- **RQ2** — an LLM-based audit of ML-specific defensive controls.
- **RQ3** — a project maturity and developer-discourse analysis.

## Repository layout

```
00_corpus/
  scanner/scanner/        Stages 1-3: Dockerfile parsing, AST call graph, stage verification
    dockerfile_parser.py    extracts the container entry point
    ast_callgraph.py        builds the static call graph from the entry point
    stage_verifier.py       checks that all six pipeline stages are reachable
    orchestrator.py         runs the full corpus-construction pipeline
  data/                   verified_corpus.csv, corpus_metrics.csv, call_graphs/

rq1_static_taxonomy/      RQ1: static threat taxonomy
  code/
    tools/                  per-tool wrappers (Bandit, Semgrep, pip-audit, ModelScan, ...)
    runner.py, orchestrator.py   run the static tools across the corpus
    stage_mapping.py        maps findings to pipeline stages via the call graph
    taxonomy.py             builds the stage x category matrices + headline figure
  data/                   stage4_findings/, taxonomy_static_matrix.csv, taxonomy_static_rules.csv, ...
  figures/                pipeline_figure.{png,svg}

rq2_llm_defenses/         RQ2: LLM defensive-control audit
  code/
    llm_scan.py             Claude-based absent-control audit
    crossval.py             GPT-4o cross-validation
    taxonomy.py             stage x control matrix
  data/                   llm_findings/, taxonomy_llm_matrix.csv, crossval_summary.csv, ...

rq3_maturity_discourse/   RQ3: maturity vs. security + issue discourse
  code/
    loc_count.py            reachable lines of code per repo (density denominator)
    fetch_github_extras.py  GitHub metrics + closed-issue retrieval
    correlate.py            maturity vs. vulnerability-density correlations
  data/                   correlation_data.csv, loc.csv, closed_issues.csv, ...
  figures/                correlation_plots.png

shared/                   cross-RQ helpers + master_findings.csv
_archive/                 earlier intermediate outputs (not used by the paper)
```

## Released data artifacts

| File | Contents |
|------|----------|
| `00_corpus/data/verified_corpus.csv` | the 408 verified repositories |
| `00_corpus/data/corpus_metrics.csv` | per-repo maturity metrics (stars, forks, contributors, closed PRs, age) |
| `00_corpus/data/call_graphs/` | per-repo call-graph file lists (reproducibility) |
| `rq1_static_taxonomy/data/stage4_findings/` | per-repo static-tool findings (one JSON per repo) |
| `rq1_static_taxonomy/data/taxonomy_static_matrix.csv` | stage x 15 threat categories |
| `rq1_static_taxonomy/data/taxonomy_static_rules.csv` | rule_id -> category audit trail |
| `rq1_static_taxonomy/data/stage_summary.csv` | per-stage figure inputs |
| `rq2_llm_defenses/data/llm_findings/` | per-repo LLM absent-control findings |
| `rq2_llm_defenses/data/taxonomy_llm_matrix.csv` | stage x 13 defensive controls |
| `rq2_llm_defenses/data/crossval_summary.csv` | GPT-4o cross-validation summary |
| `rq3_maturity_discourse/data/correlation_data.csv` | per-repo maturity metrics + finding counts + density |
| `rq3_maturity_discourse/data/correlation_table.csv` | Spearman correlations (predictor x outcome) |
| `rq3_maturity_discourse/data/loc.csv` | reachable lines of code per repo |
| `rq3_maturity_discourse/data/closed_issues.csv` | 2,122 closed issues from the 20 most-discussed repos |
| `shared/master_findings.csv` | every finding (11,389 rows), one per row, with stage, category, severity, and scope |

Headline figures: `rq1_static_taxonomy/figures/pipeline_figure.{png,svg}` and
`rq3_maturity_discourse/figures/correlation_plots.png`.

## Reproducing the analysis

The findings are already released, so the taxonomy, correlations, and figures
can be rebuilt without re-scanning. The analysis scripts use only the Python
standard library plus `matplotlib`, and read/write the released CSVs via
command-line flags (run any script with `-h` for the full list).

```bash
pip install -r requirements.txt

# RQ1: rebuild the stage x category matrices and the headline figure
python rq1_static_taxonomy/code/taxonomy.py \
  --findings-dir rq1_static_taxonomy/data/stage4_findings \
  --llm-dir      rq2_llm_defenses/data/llm_findings \
  --corpus       00_corpus/data/verified_corpus.csv \
  --out-dir      rq1_static_taxonomy/data

# RQ3: rebuild the maturity vs. vulnerability-density correlations and plots
python rq3_maturity_discourse/code/correlate.py \
  --corpus       00_corpus/data/verified_corpus.csv \
  --metrics      00_corpus/data/corpus_metrics.csv \
  --loc          rq3_maturity_discourse/data/loc.csv \
  --extras       rq3_maturity_discourse/data/github_repo_extras.csv \
  --findings-dir rq1_static_taxonomy/data/stage4_findings \
  --out-dir      rq3_maturity_discourse/data
```

Steps that hit the network (optional; require a GitHub token):

```bash
export GITHUB_TOKEN=...   # public-repo read scope is enough
python rq3_maturity_discourse/code/loc_count.py \
  --corpus 00_corpus/data/verified_corpus.csv \
  --call-graphs-dir 00_corpus/data/call_graphs \
  --out rq3_maturity_discourse/data/loc.csv
python rq3_maturity_discourse/code/fetch_github_extras.py --mode metrics
python rq3_maturity_discourse/code/fetch_github_extras.py --mode issues --top 20
```

> Note: a few scripts still carry default paths and module names from before
> the repository was reorganized into the `00_corpus / rqN_* / shared` layout
> (e.g., `shared/master_table.py` imports `stage4.taxonomy`). Pass the explicit
> `--` paths shown above, and update those legacy imports, before re-running
> from scratch.

## Static-analysis tools (RQ1)

| Tool | Role |
|------|------|
| Bandit | Python security linter |
| Semgrep | pattern-based scanning with the community security rule packs |
| pip-audit | known-vulnerability advisories for declared dependencies |

## License

MIT (see `LICENSE`).

## Citation

```bibtex
@misc{wehbe2026mlops,
  title  = {Security Threats and Missing Defenses in Open Source MLOps Pipelines:
            A Large-Scale Empirical Study of Deployed Machine Learning Repositories},
  author = {Wehbe, Charles and Barrak, Amine and Ksontini, Emna},
  year   = {2026},
  note   = {Manuscript submitted for publication}
}
```
