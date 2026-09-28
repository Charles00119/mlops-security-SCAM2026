# Re-running RQ1–RQ3 on the extended corpus

Goal: bring the 278 repositories added by the corpus extension through the
same pipeline that produced the released 408-repository results, then
regenerate every table and figure for all 686. **No analysis script is
changed**; each one already skips repositories present in its log, so only
the new repositories are processed and the 408 existing per-repo results are
reused as they are.

Run everything from the repository root in the PyCharm Terminal (PowerShell).
Order matters: RQ1 → RQ2 → RQ3 → aggregate.

## 0. Preserve the 408-repository results and set keys

```powershell
git tag -a v1.0-corpus408 -m "Results as released for the 408-repository corpus"
git push origin v1.0-corpus408
```

Keys, as environment variables in this shell only (never in files):

```powershell
$env:GITHUB_TOKEN     = "github_pat_..."   # public read-only; clones + REST API
$env:ANTHROPIC_API_KEY = "sk-ant-..."      # RQ2 audit (claude-sonnet-4-6)
$env:OPENAI_API_KEY    = "sk-..."          # RQ2 cross-validation (gpt-4o)
$env:GIT_TERMINAL_PROMPT = "0"; $env:GCM_INTERACTIVE = "Never"
```

Static tools (same four as the original run; gitleaks and nbdefense were not
used and stay off):

```powershell
pip install bandit semgrep pip-audit modelscan
bandit --version; semgrep --version; pip-audit --version; modelscan --version
```

## 1. RQ1 — static tools on the new repositories (~1–3 h)

Resume log is the original `stage4_log.csv`; move it next to the findings:

```powershell
git mv _archive/stage4_log.csv rq1_static_taxonomy/data/stage4_log.csv
python -m rq1_static_taxonomy.code.orchestrator 00_corpus/data/verified_corpus_extended.csv `
  --log rq1_static_taxonomy/data/stage4_log.csv `
  --summary rq1_static_taxonomy/data/stage4_summary.csv `
  --findings-dir rq1_static_taxonomy/data/stage4_findings
```

Expect `Stage 4: 686 verified, 408 already done, 278 to scan`. Each repo is
cloned, scanned by the four tools, mapped to stages via the import graph,
and written as one JSON in `stage4_findings/`.

## 2. RQ2 — LLM defensive-control audit on the new repositories

**Model must stay `claude-sonnet-4-6`** (`MODEL` in `llm_scan.py`) so the new
audits are comparable with the 408. If the API rejects it as retired, stop
and decide: either re-audit all 686 with one current model, or report the
extension with a model caveat. Do not mix silently.

```powershell
python rq2_llm_defenses/code/llm_scan.py 00_corpus/data/verified_corpus_extended.csv `
  --log rq2_llm_defenses/data/llm_scan_log.csv `
  --findings-dir rq2_llm_defenses/data/llm_findings `
  --snapshot-dir 00_corpus/data/import_graphs
```

Cost: up to 6 prompts per repo, each carrying the repo's reachable code;
rough budget for 278 repos is tens of dollars, low hundreds at most. The
run also writes the reachability snapshot for each new repo; afterwards
relabel them so they carry `entry_route`:

```powershell
python tools/relabel_snapshots.py --corpus 00_corpus/data/verified_corpus_extended.csv
```

Cross-validation is re-drawn over all 686 (150 stratified findings, seed 42;
~150 GPT-4o calls, a few dollars). It overwrites the sample/log/summary — the
408-corpus versions are kept by the tag:

```powershell
python rq2_llm_defenses/code/crossval.py 00_corpus/data/verified_corpus_extended.csv `
  --llm-findings-dir rq2_llm_defenses/data/llm_findings `
  --call-graphs-dir 00_corpus/data/import_graphs `
  --log rq2_llm_defenses/data/crossval_log.csv `
  --summary rq2_llm_defenses/data/crossval_summary.csv `
  --sample rq2_llm_defenses/data/crossval_sample.csv --n 150 --seed 42
```

## 3. RQ3 — maturity metrics, reachable LOC, issues (~1 h, mostly API waits)

```powershell
# per-repo GitHub metrics (resumes from the existing file)
python rq3_maturity_discourse/code/fetch_repo_metrics.py 00_corpus/data/verified_corpus_extended.csv 00_corpus/data/corpus_metrics.csv

# reachable lines of code (clones each new repo; resumes)
python rq3_maturity_discourse/code/loc_count.py `
  --corpus 00_corpus/data/verified_corpus_extended.csv `
  --call-graphs-dir 00_corpus/data/import_graphs `
  --out rq3_maturity_discourse/data/loc.csv --resume

# extra metrics (closed PRs, commit counts...) and closed issues of the 20 most-discussed repos
python rq3_maturity_discourse/code/fetch_github_extras.py --mode metrics `
  --corpus 00_corpus/data/verified_corpus_extended.csv `
  --metrics-csv 00_corpus/data/corpus_metrics.csv `
  --out rq3_maturity_discourse/data/github_repo_extras.csv --resume
python rq3_maturity_discourse/code/fetch_github_extras.py --mode issues --top 20 `
  --corpus 00_corpus/data/verified_corpus_extended.csv `
  --metrics-csv 00_corpus/data/corpus_metrics.csv `
  --out rq3_maturity_discourse/data/closed_issues.csv
```

The top-20 set is recomputed over 686 repositories, so the issues file is
rebuilt in full (it is small). `pipeline_relevance` / `matched_keywords`
are keyword flags computed by the script, the same as before.

## 4. Aggregate — regenerate every table and figure for 686

```powershell
python rq1_static_taxonomy/code/taxonomy.py `
  --findings-dir rq1_static_taxonomy/data/stage4_findings `
  --llm-dir      rq2_llm_defenses/data/llm_findings `
  --corpus       00_corpus/data/verified_corpus_extended.csv `
  --out-dir      rq1_static_taxonomy/data
Move-Item -Force rq1_static_taxonomy/data/taxonomy_llm_matrix.csv rq2_llm_defenses/data/taxonomy_llm_matrix.csv
Move-Item -Force rq1_static_taxonomy/data/pipeline_figure.png rq1_static_taxonomy/figures/pipeline_figure.png
Move-Item -Force rq1_static_taxonomy/data/pipeline_figure.svg rq1_static_taxonomy/figures/pipeline_figure.svg

python shared/master_table.py `
  --findings-dir rq1_static_taxonomy/data/stage4_findings `
  --llm-dir      rq2_llm_defenses/data/llm_findings `
  --corpus       00_corpus/data/verified_corpus_extended.csv `
  --out          shared/master_findings.csv

python rq3_maturity_discourse/code/correlate.py `
  --corpus       00_corpus/data/verified_corpus_extended.csv `
  --metrics      00_corpus/data/corpus_metrics.csv `
  --loc          rq3_maturity_discourse/data/loc.csv `
  --extras       rq3_maturity_discourse/data/github_repo_extras.csv `
  --findings-dir rq1_static_taxonomy/data/stage4_findings `
  --out-dir      rq3_maturity_discourse/data
Move-Item -Force rq3_maturity_discourse/data/correlation_plots.png rq3_maturity_discourse/figures/correlation_plots.png
```

`taxonomy.py` and `correlate.py` print the headline numbers (per-stage
finding shares, control-absence rates, Spearman ρ per maturity indicator).
Keep that output: it is what the paper's results section is rewritten from.

## 5. Commit

Commit the new per-repo findings, snapshots, the regenerated tables/figures,
`stage4_log.csv`, `llm_scan_log.csv`, the RQ3 CSVs, and `master_findings.csv`.
From this commit on, `verified_corpus_extended.csv` is the corpus behind the
released tables; update the README's *Released data artifacts* and *Corpus
construction* wording accordingly (the 408 numbers stay reachable via the
`v1.0-corpus408` tag).

## Sanity checks before rewriting the paper

- `rq1_static_taxonomy/data/stage4_findings/` and `rq2_llm_defenses/data/llm_findings/`
  should each contain 686 files (or 685 if `indobenchmark/indonlu` still fails).
- In `stage4_log.csv`, the 278 new rows should list the same `tools_run`
  (`bandit;semgrep;pip_audit;modelscan`) as the old rows.
- Split every headline number by `entry_route` (the master table carries
  `repo`; join on `verified_corpus_extended.csv`). If the Dockerfile-rooted,
  root-fallback and nested-fallback groups tell the same story, say so in the
  paper; if they don't, that is a finding, not a problem to hide.
