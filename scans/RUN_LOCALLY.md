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

## 3. When both are done

Send back (or commit) these four files:

- `scans/pass1/scan_log.csv`
- `scans/pass1/verified.csv`
- `scans/pass2/scan_log.csv`
- `scans/pass2/verified.csv`

From them the final `verified_corpus.csv`, the merged 31,066-row
`scan_log.csv`, the funnel table and the README numbers are generated; the
original 408 also get their `entry_route` re-derived (a 3-minute re-clone of
the 79 Dockerfile-bearing repos).

## If something goes wrong

- **Interrupted / machine slept**: re-run the same command. Nothing is lost
  except the ≤6 repos that were mid-clone.
- **`clone_failed` rows with "rate limit"**: `GITHUB_TOKEN` is not set in
  that shell, or reduce `--workers`.
- **Worker crashes on one repo**: the orchestrator logs it as `error` and
  continues; nothing to do.
- **Disk fills**: temp clones are deleted per repo; if `D:\scan_tmp` grows,
  a worker died mid-clone — delete its contents and re-run.
