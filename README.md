# Security Threats and Missing Defenses in Open Source MLOps Pipelines

Replication package for the **SCAM 2026** paper
*"Security Threats and Missing Defenses in Open Source MLOps Pipelines:
A Large-Scale Empirical Study of Deployed Machine Learning Repositories"*
(C. Wehbe, A. Barrak, E. Ksontini).

We study the software-security posture of **408 open-source MLOps
pipelines**. Each repository is verified end-to-end by a **static
import-reachability analysis** rooted at its pipeline entry point (the
Dockerfile `CMD`/`ENTRYPOINT` where one resolves, a conventional root entry
file such as `main.py` otherwise), and is kept only if all six pipeline stages
are detectable in the reachable code. We then ask three research questions:

- **RQ1** — a static threat taxonomy over the reachable code.
- **RQ2** — an LLM-based audit of ML-specific defensive controls.
- **RQ3** — a project maturity and developer-discourse analysis.

## How reachability is computed (read this first)

The analysis in `00_corpus/scanner/` has three stages. Because the wording
matters for interpreting every downstream number, here is exactly what each
one does and does not do.

**Stage 1 — entry point** (`dockerfile_parser.py`). Every Dockerfile in the
repository is located and its `ENTRYPOINT`/`CMD` (exec or shell form, with
`WORKDIR`, `python -m module`, and shell-script indirection) is resolved to a
Python file. If no Dockerfile yields a resolvable Python entry point, the
scanner falls back to the first of `main.py`, `run.py`, `app.py`, `train.py`,
`__main__.py` found at the repository root. A Dockerfile that exists but whose
command cannot be resolved (e.g. it runs a shell script or a non-Python
program) also ends on the fallback. In the 408-repository corpus, **25
repositories are Dockerfile-rooted and 383 use the fallback entry file** (79
have a Dockerfile, but only 25 of those resolve through it). The route is
recorded per repository as `entry_route` in `verified_corpus.csv`, in each
snapshot under `import_graphs/`, and in `scans/entry_routes.csv` (produced by
`tools/derive_entry_route.py` for repositories scanned before the scanner
recorded the route).

**Stage 2 — import-reachability graph** (`ast_callgraph.py`). Starting from
the entry file, in-repo `import` statements are followed breadth-first using
Python's `ast`. Nodes are **files** and edges are **imports**. Function
definitions and call-site names are collected per file so that Stage 3 can
match stage signals, but **no caller→callee edges are resolved**. This is
therefore a file-level *import-reachability* graph, **not a call graph** in
the program-analysis sense; the `CallGraph`/`build_call_graph` identifiers in
the code are historical. "Reachable" is a static over-approximation of
"executed": a module that is imported but whose functions are never invoked
still counts as reachable. Dynamic imports (`importlib`, `__import__`) are
flagged but not followed.

**Stage 3 — stage verification** (`stage_verifier.py`). Each of the six
pipeline stages (data acquisition, data preparation, modeling, training,
evaluation, inference) is declared present if at least one of its signal
calls (e.g. `pd.read_csv`, `train_test_split`, `model.fit`, `flask.Flask`)
appears in a reachable file. Every hit is recorded with file and line. The
per-file map of which stage(s) each file evidences (`StageReport.evidence_files`)
is what RQ1 uses to attribute findings to stages.

**About the released snapshots.** `00_corpus/data/import_graphs/*.json`
contain each repository's `reachable_files` plus `rq2_context_files`. The
latter lists the **same full reachable set under every present stage**, by
design: the RQ2 LLM audit reads all reachable code for each stage's question,
because a defensive control can live anywhere in the pipeline. It is *not* a
per-file stage attribution. (These files were previously released under the
name `call_graphs/` with the key `stages_with_files`; they were relabelled by
`tools/relabel_snapshots.py` without re-cloning any repository.) The snapshots
do not currently include the import edges themselves; only the resulting file
set is released.

## Corpus construction

The candidate list is the 31,066 ML repositories curated by Idowu et al.
(`00_corpus/data/list_of_repositories.xlsx`). Because the 2022 metadata in
that list (Dockerfile presence, stage labels) had drifted, every repository
was re-cloned and re-verified rather than pre-filtered on the spreadsheet
columns. The Stage 1–3 run processed the list in order and **covered the
first 18,533 candidates**; the remaining 12,533 were not scanned in this
version of the corpus (see *Known limitations*). The full per-repository log
is `_archive/scan_log.csv`.

| Step | Repositories |
|---|---:|
| Candidate list (Idowu et al.) | 31,066 |
| Scanned (Stages 1–3) | 18,533 |
| ├ clone failed (mostly repository deleted) | 1,676 |
| ├ no Dockerfile and no fallback entry file | 11,234 |
| ├ Dockerfile found, no resolvable Python entry point | 2,654 |
| ├ entry point resolved, fewer than 6 stages reachable | 2,561 |
| └ **all 6 stages reachable → verified corpus** | **408** |

Of the 408: 25 Dockerfile-rooted, 383 fallback-entry-file; 6,121 of the
31,066 candidates carry a Dockerfile according to the source list, 3,587 of
which fell inside the scanned range.

The scan is being extended to the full candidate list, with a widened fallback
rule (`src/`, `app/`, top-level package, `console_scripts`) applied to
repositories that failed under the original rule; see `scans/RUN_LOCALLY.md`
and `tools/build_corpus.py`. Numbers above describe the 408-repository corpus
used by the current version of the paper.

## Repository layout

```
00_corpus/
  scanner/scanner/        Stages 1-3: entry-point resolution, import-reachability walk, stage verification
    dockerfile_parser.py    resolves the Dockerfile CMD/ENTRYPOINT (or root fallback file) to a Python entry
    ast_callgraph.py        walks in-repo imports from the entry file (file-level reachability; see above)
    stage_verifier.py       checks that all six pipeline stages have signal calls in reachable files
    orchestrator.py         runs the full corpus-construction pipeline (clone -> Stages 1-3 -> log row)
  data/                   verified_corpus.csv, corpus_metrics.csv, list_of_repositories.xlsx, import_graphs/

rq1_static_taxonomy/      RQ1: static threat taxonomy
  code/
    tools/                  per-tool wrappers (Bandit, Semgrep, pip-audit, ModelScan, ...)
    runner.py, orchestrator.py   run the static tools across the corpus
    stage_mapping.py        maps findings to pipeline stages via per-file stage evidence + reachability
    taxonomy.py             builds the stage x category matrices + headline figure
  data/                   stage4_findings/, taxonomy_static_matrix.csv, taxonomy_static_rules.csv, ...
  figures/                pipeline_figure.{png,svg}

rq2_llm_defenses/         RQ2: LLM defensive-control audit
  code/
    llm_scan.py             Claude-based absent-control audit (also writes the import_graphs/ snapshots)
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
tools/                    relabel_snapshots.py, scan_parallel.py, derive_entry_route.py, build_corpus.py
scans/                    corpus-extension runs: RUN_LOCALLY.md, pass logs, entry_routes.csv
_archive/                 scan_log.csv (full Stage 1-3 log) and earlier intermediate outputs
```

## Released data artifacts

| File | Contents |
|------|----------|
| `00_corpus/data/list_of_repositories.xlsx` | the 31,066 candidate repositories (Idowu et al.) |
| `00_corpus/data/verified_corpus.csv` | the 408 verified repositories, with entry file(s), Dockerfile count, per-stage evidence |
| `00_corpus/data/corpus_metrics.csv` | per-repo maturity metrics (stars, forks, contributors, closed PRs, age) |
| `00_corpus/data/import_graphs/` | per-repo reachability snapshots: `entry_route`, `entry_files`, `reachable_files`, `rq2_context_files` (407 files; see note below) |
| `scans/entry_routes.csv` | settled `entry_route` for the 79 pre-extension repos that carry a Dockerfile (25 resolve through it) |
| `_archive/scan_log.csv` | Stage 1–3 outcome for every one of the 18,533 scanned candidates |
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

> `import_graphs/`, `stage4_findings/` and `llm_findings/` each contain 407
> files for a 408-repository corpus: `indobenchmark/indonlu` has no snapshot
> or findings file in this release.

## Reproducing the analysis

The findings are already released, so the taxonomy, correlations, and figures
can be rebuilt without re-scanning. The analysis scripts use only the Python
standard library plus `matplotlib`, and read/write the released CSVs via
command-line flags (run any script with `-h` for the full list). Run all
commands from the repository root.

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

# Master per-finding table
python shared/master_table.py \
  --findings-dir rq1_static_taxonomy/data/stage4_findings \
  --llm-dir      rq2_llm_defenses/data/llm_findings \
  --corpus       00_corpus/data/verified_corpus.csv \
  --out          shared/master_findings.csv
```

Both `taxonomy.py` and `correlate.py` regenerate the released
`taxonomy_static_matrix.csv` and `correlation_table.csv` byte-for-byte
(modulo line endings).

Steps that hit the network (optional; require a GitHub token):

```bash
export GITHUB_TOKEN=...   # public-repo read scope is enough

# Stage 1-3 corpus construction over a candidate list (.xlsx / .csv / .txt)
python 00_corpus/scanner/scanner/orchestrator.py \
  00_corpus/data/list_of_repositories.xlsx scan_log.csv verified_corpus.csv

# RQ1 static tools (needs bandit / semgrep / pip-audit / modelscan installed)
python -m rq1_static_taxonomy.code.orchestrator -h

# RQ3 network steps
python rq3_maturity_discourse/code/loc_count.py \
  --corpus 00_corpus/data/verified_corpus.csv \
  --call-graphs-dir 00_corpus/data/import_graphs \
  --out rq3_maturity_discourse/data/loc.csv
python rq3_maturity_discourse/code/fetch_github_extras.py --mode metrics
python rq3_maturity_discourse/code/fetch_github_extras.py --mode issues --top 20
```

## Static-analysis tools (RQ1)

| Tool | Role |
|------|------|
| Bandit | Python security linter |
| Semgrep | pattern-based scanning with the community security rule packs |
| pip-audit | known-vulnerability advisories for declared dependencies |
| ModelScan | unsafe model-serialization formats |

## Known limitations

- **Partial coverage of the candidate list.** Only the first 18,533 of the
  31,066 candidates were scanned. The list is not randomly ordered: the
  unscanned tail has a higher mean star count (102 vs 46) and holds 2,534 of
  the 6,121 Dockerfile-bearing candidates. The 408-repository corpus is
  therefore skewed toward smaller projects, which bears on RQ3.
- **Entry-point route.** 383 of 408 repositories are rooted at a conventional
  root entry file rather than a Dockerfile command (54 of them have a
  Dockerfile whose command did not resolve to Python). The original fallback
  only inspected the repository root, so projects with `src/`-style layouts
  and no Dockerfile were excluded; the widened rule addresses this in the
  extended corpus. All results can be split by `entry_route`.
- **Reachability is static and file-level.** See *How reachability is
  computed*. Import-reachable code is not necessarily executed, and
  function-level reachability is not modelled.
- **Snapshot age.** The candidate list is a 2022 snapshot; 959 repositories
  had been deleted by scan time.

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
