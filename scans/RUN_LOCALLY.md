# Extending the corpus scan — local run instructions

Everything below runs from the repository root in the PyCharm Terminal
(PowerShell). Total wall-clock on a fast connection with 6 workers: roughly
1.5–2 h for pass 1 and 3–4 h for pass 2. Both passes resume if interrupted:
re-run the same command and already-logged repositories are skipped.

## 0. One-time setup

```powershell
git config --global core.longpaths true          # some repos have paths > 260 chars
pip install openpyxl                             # to read list_of_repositories.xlsx
$env:GITHUB_TOKEN = "ghp_..."                    # your token; env var only, never in a file
mkdir D:\scan_tmp                                # temp clones — put this on an SSD
```

`GITHUB_TOKEN` needs no scopes (public-repo read). It only raises the
anonymous-clone throttle; it is never written to disk by the scripts.

## 1. Pass 1 — the 10,235 candidates the original scan never reached

The original scan stopped at row 18,533 of 31,066. A partial continuation
(2,298 repos, 13 verified) is already in `scans/scan_log_pass1_partial.csv`
and is used as a resume seed.

```powershell
python tools/scan_parallel.py pass1 `
  --candidates 00_corpus/data/list_of_repositories.xlsx `
  --done _archive/scan_log.csv `
  --done scans/scan_log_pass1_partial.csv `
  --workdir scans/pass1 --workers 6 --tmp D:\scan_tmp
```

Progress prints every 30 s. Output: `scans/pass1/scan_log.csv` (one row per
repo) and `scans/pass1/verified.csv`.

## 2. Pass 2 — widened fallback over every `no_entry` / `no_dockerfile` repo

Uses the new fallback rules (`src/`, `app/`, top-level package,
`console_scripts`). Re-clones only repos that failed in the original scan,
the partial continuation, or pass 1. Repos that already resolved are never
touched, so the existing 408 are unaffected.

```powershell
python tools/scan_parallel.py pass2 `
  --done _archive/scan_log.csv `
  --done scans/scan_log_pass1_partial.csv `
  --done scans/pass1/scan_log.csv `
  --workdir scans/pass2 --workers 6 --tmp D:\scan_tmp
```

Output: `scans/pass2/scan_log.csv` and `scans/pass2/verified.csv`. Every
verified row carries `entry_route` = `fallback_nested` or
`fallback_console_script`.

## 2b. Retry recoverable clone failures

Check the pass's merged log for `clone_failed` rows whose reason is not
"repository gone" (disk full, timeout, path error). The first pass-2 run hit
a full `D:` because the pre-fix orchestrator could not delete Git's read-only
pack files on Windows; that is fixed, but always empty the temp folder first:

```powershell
Remove-Item D:\scan_tmp\* -Recurse -Force
python tools/scan_parallel.py retry `
  --workdir scans/pass2 --retry-workdir scans/pass2_retry --workers 6 --tmp D:\scan_tmp
```

Output: `scans/pass2_retry/scan_log.csv` and `verified.csv`. Pass both pass-2
logs to `build_corpus.py` (later `--pass2` files override earlier
`clone_failed` rows).

## 3. When both are done — build the corpus files

```powershell
python tools/build_corpus.py `
  --original _archive/scan_log.csv `
  --extra scans/scan_log_pass1_partial.csv `
  --extra scans/pass1/scan_log.csv `
  --pass2 scans/pass2/scan_log.csv `
  --pass2 scans/pass2_retry/scan_log.csv `
  --routes scans/entry_routes.csv `
  --out-dir 00_corpus/data
```

This writes `00_corpus/data/scan_log_full.csv` (final outcome for every one of
the 31,066 candidates), `00_corpus/data/verified_corpus.csv` (the extended
corpus, every row with `entry_route`) and `00_corpus/data/corpus_funnel.md`
(the table for the README), and prints the funnel.

`scans/entry_routes.csv` settles the route for repos scanned before the
scanner recorded it (79 original repos with a Dockerfile: only 25 resolve
through it). If `build_corpus.py` reports rows still marked `dockerfile?`,
settle them (a handful of clones) and rebuild:

```powershell
python tools/derive_entry_route.py --corpus 00_corpus/data/verified_corpus.csv --out scans/entry_routes.csv --tmp D:\scan_tmp
```

Then re-run `python tools/relabel_snapshots.py` so the snapshots' `entry_route`
matches, and commit `00_corpus/data/*`, `scans/pass1/{scan_log,verified}.csv`
and `scans/pass2/{scan_log,verified}.csv`. The per-worker `log*.csv`,
`verified*.csv`, `shard*.txt` and `worker*.out` files are intermediate.

## If something goes wrong

- **Interrupted / machine slept**: re-run the same command. Nothing is lost
  except the ≤6 repos that were mid-clone.
- **`clone_failed` rows with "rate limit"**: `GITHUB_TOKEN` is not set in
  that shell, or reduce `--workers`.
- **Worker crashes on one repo**: the orchestrator logs it as `error` and
  continues; nothing to do.
- **Disk fills**: temp clones are deleted per repo; if `D:\scan_tmp` grows,
  a worker died mid-clone — delete its contents and re-run.
