# Changelog

## Unreleased — terminology and replication-package fixes

Motivated by reviewer feedback that "AST-based static call graph" was unclear
and that the released package appeared to contradict it. No repository was
re-cloned and no result changed; `taxonomy.py`, `correlate.py` and
`master_table.py` regenerate the released tables byte-for-byte.

### Terminology
- The Stage 2 analysis is now described everywhere as a **static
  import-reachability graph** (file-level; nodes are modules, edges are
  imports; no caller→callee edges). The `CallGraph` / `build_call_graph`
  identifiers are kept for API stability and documented as historical.
- The corpus is no longer described as "Dockerfile-rooted": 79 repositories
  are rooted at a Dockerfile command, 329 at a conventional root entry file.
  The route is now stated in the README and recorded per repository.

### Data artifacts
- `00_corpus/data/call_graphs/` → `00_corpus/data/import_graphs/`.
- In every snapshot JSON: `stages_with_files` → `rq2_context_files`, with an
  inline note explaining that it lists the full reachable set under every
  present stage by design (RQ2 context), not a per-file stage attribution;
  added `entry_route`, `entry_files`, `stages_present`, `analysis`.
  Relabelling script: `tools/relabel_snapshots.py`.
- Removed duplicate `rq3_maturity_discourse/data/correlation_plots.png`
  (canonical copy is under `figures/`).

### Code
- Fixed imports left over from the pre-reorganization layout so the README
  commands run from the repository root: `stage4.taxonomy` / `stage4.findings`
  → sibling modules; `scanner.*` now resolved from `00_corpus/scanner`.
- Added `__init__.py` to `rq*/` and `rq*/code/` so scripts with relative
  imports run via `python -m rq1_static_taxonomy.code.orchestrator`.
- `crossval.py` and `loc_count.py` default to the new snapshot directory and
  read both the new and legacy snapshot keys.

### README
- New sections: *How reachability is computed*, *Corpus construction* (full
  funnel from 31,066 candidates, including the 18,533-of-31,066 scan cutoff),
  *Known limitations*.
- Documents the 407-vs-408 gap (`indobenchmark/indonlu` has no snapshot or
  findings file).
