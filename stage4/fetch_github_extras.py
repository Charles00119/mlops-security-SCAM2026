"""Fetch GitHub extras: closed-issue text + extra repo metrics, via the API.

Two modes (run either or both):

  python -m stage4.fetch_github_extras --mode metrics
      For ALL repos in verified_corpus.csv, fetch:
        - commit count (default-branch history length)
        - repo size in KB (GitHub's `size` field)
        - language byte breakdown (python_bytes, total_code_bytes)
      Writes: github_repo_extras.csv

  python -m stage4.fetch_github_extras --mode issues --top 20
      For the TOP-N repos by closed_issues in corpus_metrics.csv, fetch all
      closed issues (title, body, labels, dates, comment count; PRs excluded).
      Adds a keyword-based `pipeline_relevance` column flagging issues whose
      title/body mention MLOps-pipeline terms — a triage aid, not a verdict.
      Writes: closed_issues.csv

Auth: set the GITHUB_TOKEN environment variable before running.
    PowerShell:  $env:GITHUB_TOKEN = "ghp_..."
    cmd:         set GITHUB_TOKEN=ghp_...
Unauthenticated requests are limited to 60/hour — not enough. With a token
you get 5,000/hour, which covers everything here in one run.

Rate math: metrics mode = 3 requests/repo x 408 repos = ~1,224 requests.
Issues mode = 1 request per 100 issues per repo; top-20 with ~2,000 closed
issues total = ~40 requests. Both fit comfortably in one token-hour.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API = "https://api.github.com"

# Keyword triage for issue text. Deliberately broad: catching too much is
# fine (a human reviews the flagged set); missing things is worse.
PIPELINE_KEYWORDS = [
    # data acquisition / preparation
    "dataset", "data loading", "dataloader", "download", "preprocess",
    "augmentation", "label", "annotation", "corrupt",
    # modeling / training
    "checkpoint", "pretrained", "pre-trained", "weights", "training",
    "fine-tun", "finetun", "hyperparameter", "cuda", "gpu", "memory",
    "convergence", "loss",
    # evaluation / inference
    "evaluation", "inference", "predict", "deploy", "serving", "api",
    "docker", "container",
    # security-adjacent
    "security", "vulnerab", "pickle", "deserial", "injection", "secret",
    "credential", "token", "dependency", "requirements", "version conflict",
    "pip", "upgrade",
]
_KEYWORD_RE = re.compile("|".join(re.escape(k) for k in PIPELINE_KEYWORDS),
                         re.IGNORECASE)


def gh_get(url: str, token: str | None, *, retries: int = 3) -> tuple[Any, dict]:
    """GET a GitHub API URL, return (parsed_json, response_headers)."""
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "mlops-security-paper-script")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8")), dict(resp.headers)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                body = e.read().decode("utf-8", "ignore").lower()
                if "rate limit" in body or not token:
                    if not token:
                        raise SystemExit(
                            "[fatal] GitHub returned 403 and no GITHUB_TOKEN is "
                            "set. Set the token and re-run:\n"
                            "  PowerShell:  $env:GITHUB_TOKEN = \"ghp_...\"\n"
                            "  cmd:         set GITHUB_TOKEN=ghp_...")
                    reset = e.headers.get("X-RateLimit-Reset")
                    wait = max(5, int(reset) - int(time.time())) if reset else 60
                    print(f"[rate-limit] sleeping {wait}s", file=sys.stderr)
                    time.sleep(min(wait, 300))
                    continue
            if e.code in (404, 451):   # gone / DMCA
                return None, dict(e.headers or {})
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)
    return None, {}


def owner_repo(url: str) -> tuple[str, str] | None:
    parts = url.rstrip("/").split("/")
    if len(parts) < 2:
        return None
    return parts[-2], parts[-1]


def load_corpus(path: str) -> list[str]:
    out = []
    with open(path, newline="", encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        field = "repo" if "repo" in (r.fieldnames or []) else (r.fieldnames or [None])[0]
        for row in r:
            u = (row.get(field) or "").strip()
            if u:
                out.append(u)
    return out


# ---------------------------------------------------------------- metrics --

def commit_count(owner: str, repo: str, token: str | None) -> int | None:
    """Count commits on the default branch via the Link header trick:
    per_page=1 makes the last page number equal the commit count."""
    url = f"{API}/repos/{owner}/{repo}/commits?per_page=1"
    data, headers = gh_get(url, token)
    if data is None:
        return None
    link = headers.get("Link", "")
    m = re.search(r'page=(\d+)>; rel="last"', link)
    if m:
        return int(m.group(1))
    # No Link header = single page = count of returned commits (0 or 1).
    return len(data) if isinstance(data, list) else None


def fetch_metrics(repos: list[str], token: str | None, out_path: str,
                  resume: bool) -> None:
    done: set[str] = set()
    if resume and os.path.isfile(out_path):
        with open(out_path, newline="", encoding="utf-8") as fh:
            done = {row["repo"] for row in csv.DictReader(fh)}
    mode = "a" if done else "w"
    with open(out_path, mode, newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if mode == "w":
            w.writerow(["repo", "commit_count", "size_kb",
                        "python_bytes", "total_code_bytes", "fetch_ok"])
        for i, url in enumerate(repos, 1):
            if url in done:
                continue
            parsed = owner_repo(url)
            if not parsed:
                w.writerow([url, "", "", "", "", False]); continue
            o, r = parsed
            try:
                meta, _ = gh_get(f"{API}/repos/{o}/{r}", token)
                langs, _ = gh_get(f"{API}/repos/{o}/{r}/languages", token)
                commits = commit_count(o, r, token)
                if meta is None:
                    w.writerow([url, "", "", "", "", False])
                else:
                    py = (langs or {}).get("Python", 0)
                    total = sum((langs or {}).values())
                    w.writerow([url, commits if commits is not None else "",
                                meta.get("size", ""), py, total, True])
                fh.flush()
                print(f"[{i}/{len(repos)}] {o}/{r}: "
                      f"commits={commits} size_kb={meta.get('size') if meta else '?'}")
            except Exception as exc:
                w.writerow([url, "", "", "", "", False])
                fh.flush()
                print(f"[{i}/{len(repos)}] {o}/{r}: FAILED ({exc})", file=sys.stderr)


# ---------------------------------------------------------------- issues ---

def top_repos_by_closed_issues(metrics_csv: str, n: int) -> list[str]:
    rows = []
    with open(metrics_csv, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                c = int(row.get("closed_issues") or 0)
            except ValueError:
                c = 0
            if c > 0:
                rows.append((c, row["repo"]))
    rows.sort(reverse=True)
    return [u for _, u in rows[:n]]


def fetch_issues(repos: list[str], token: str | None, out_path: str,
                 max_pages: int) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["repo", "issue_number", "title", "labels", "created_at",
                    "closed_at", "comments", "pipeline_relevance",
                    "matched_keywords", "body_excerpt"])
        for url in repos:
            parsed = owner_repo(url)
            if not parsed:
                continue
            o, r = parsed
            page = 1
            n_fetched = 0
            while page <= max_pages:
                api_url = (f"{API}/repos/{o}/{r}/issues"
                           f"?state=closed&per_page=100&page={page}")
                data, _ = gh_get(api_url, token)
                if not data:
                    break
                for it in data:
                    if "pull_request" in it:     # issues endpoint includes PRs
                        continue
                    title = it.get("title") or ""
                    body = it.get("body") or ""
                    text = f"{title}\n{body}"
                    matches = sorted({m.group(0).lower()
                                      for m in _KEYWORD_RE.finditer(text)})
                    labels = ";".join(l["name"] for l in it.get("labels", []))
                    w.writerow([
                        f"{o}/{r}", it.get("number"), title[:200], labels,
                        it.get("created_at"), it.get("closed_at"),
                        it.get("comments"),
                        "yes" if matches else "no",
                        ";".join(matches)[:200],
                        body.replace("\r", " ").replace("\n", " ")[:400],
                    ])
                    n_fetched += 1
                if len(data) < 100:
                    break
                page += 1
            fh.flush()
            print(f"{o}/{r}: {n_fetched} closed issues fetched")
    print(f"[ok] wrote {out_path}")


# ------------------------------------------------------------------ main ---

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["metrics", "issues"], required=True)
    p.add_argument("--corpus",      default="verified_corpus.csv")
    p.add_argument("--metrics-csv", default="corpus_metrics.csv",
                   help="(issues mode) source of closed_issues counts")
    p.add_argument("--top", type=int, default=20,
                   help="(issues mode) how many repos, by closed-issue count")
    p.add_argument("--max-pages", type=int, default=10,
                   help="(issues mode) max pages of 100 issues per repo")
    p.add_argument("--out", default="",
                   help="output CSV (defaults per mode)")
    p.add_argument("--resume", action="store_true",
                   help="(metrics mode) skip repos already in the output CSV")
    p.add_argument("--limit", type=int, default=0,
                   help="only first N repos (smoke testing)")
    args = p.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[warn] GITHUB_TOKEN not set — unauthenticated (60 req/hr). "
              "Fine for a smoke test, not for a full run.", file=sys.stderr)

    if args.mode == "metrics":
        repos = load_corpus(args.corpus)
        if args.limit:
            repos = repos[: args.limit]
        fetch_metrics(repos, token, args.out or "github_repo_extras.csv",
                      args.resume)
    else:
        repos = top_repos_by_closed_issues(args.metrics_csv, args.top)
        if args.limit:
            repos = repos[: args.limit]
        print(f"[info] top {len(repos)} repos by closed issues:")
        for u in repos:
            print(f"   {u}")
        fetch_issues(repos, token, args.out or "closed_issues.csv",
                     args.max_pages)
    return 0


if __name__ == "__main__":
    sys.exit(main())
