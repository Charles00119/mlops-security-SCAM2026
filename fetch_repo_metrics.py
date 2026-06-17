"""Fetch GitHub repository metrics for every repo in verified_corpus.csv.

Reads:    verified_corpus.csv (or any CSV with a 'repo' column)
Writes:   corpus_metrics.csv with one row per repo and the columns listed
          in METRICS_COLUMNS below.

For each repo we hit /repos/{owner}/{repo} (one call) plus a handful of
search-API calls for open/closed issue and PR counts that the basic endpoint
doesn't separate properly. Contributors come from /repos/.../contributors
with a Link-header trick to get the total without paginating.

If the basic endpoint 404s (repo deleted, made private, owner renamed),
currently_reachable=False and the rest of the columns are blank.

Usage:
    python fetch_repo_metrics.py verified_corpus.csv corpus_metrics.csv

GITHUB_TOKEN environment variable is required (gives 5000 calls/hr instead
of 60 unauth, which would take 50+ hours for 408 repos with 4 calls each).
"""
from __future__ import annotations

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


METRICS_COLUMNS = [
    "repo",
    "repo_name",
    "visibility",
    "currently_reachable",
    "stars",
    "watchers",
    "forks",
    "open_issues",
    "closed_issues",
    "open_prs",
    "closed_prs",
    "contributors",
    "created_at",
    "updated_at",
    "pushed_at",
    "topics",
    "has_issues",
    "has_wiki",
    "has_discussions",
]

GITHUB_API = "https://api.github.com"


def parse_repo_url(url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL. Returns None if not parseable."""
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/?$", url)
    if not m:
        return None
    return m.group(1), m.group(2)


def api_get(path: str, token: str, *, params: dict | None = None,
            retries: int = 3) -> tuple[int, dict | list | None, dict[str, str]]:
    """GET an API endpoint. Returns (status_code, parsed_body_or_None, response_headers).

    Handles 403 rate-limit responses by sleeping until reset. Retries on transient errors.
    """
    url = GITHUB_API + path
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "verified-corpus-metrics-fetch",
    }

    last_err: str = ""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
                try:
                    data = json.loads(body) if body else None
                except json.JSONDecodeError:
                    data = None
                return resp.status, data, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            # 404 = repo doesn't exist; not retried
            if exc.code == 404:
                return 404, None, dict(exc.headers or {})
            # 403 = rate limit or abuse detection; check headers for reset time
            if exc.code == 403:
                hdrs = dict(exc.headers or {})
                remaining = hdrs.get("X-RateLimit-Remaining", "?")
                reset = hdrs.get("X-RateLimit-Reset")
                if reset and remaining == "0":
                    wait = max(0, int(reset) - int(time.time())) + 5
                    print(f"    rate-limited, sleeping {wait}s...", flush=True)
                    time.sleep(min(wait, 3600))
                    continue
                # otherwise: secondary rate limit (abuse). Brief backoff and retry.
                time.sleep(2 ** attempt * 5)
                continue
            # 422 etc — return as-is so caller can decide
            return exc.code, None, dict(exc.headers or {})
        except (urllib.error.URLError, TimeoutError) as exc:
            last_err = f"network: {exc}"
            time.sleep(2 ** attempt)
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            time.sleep(2 ** attempt)
    print(f"    gave up after {retries} retries: {last_err}", flush=True)
    return -1, None, {}


def get_contributors_count(owner: str, repo: str, token: str) -> int | None:
    """Total contributor count via Link-header trick: ask for 1 per page, read 'last' page number."""
    status, _, headers = api_get(
        f"/repos/{owner}/{repo}/contributors",
        token, params={"per_page": "1", "anon": "true"},
    )
    if status != 200:
        return None
    link = headers.get("Link") or headers.get("link") or ""
    # Link looks like: <...&page=42>; rel="last", ...
    m = re.search(r'<[^>]+[?&]page=(\d+)[^>]*>;\s*rel="last"', link)
    if m:
        return int(m.group(1))
    # No Link header => 0 or 1 contributors. Re-query to check.
    status2, body, _ = api_get(
        f"/repos/{owner}/{repo}/contributors",
        token, params={"per_page": "1", "anon": "true"},
    )
    if status2 != 200 or not isinstance(body, list):
        return None
    return len(body)


def search_count(query: str, token: str) -> int | None:
    """Use /search/issues to count issues/PRs matching a query. Returns total_count or None."""
    status, body, _ = api_get("/search/issues", token, params={"q": query, "per_page": "1"})
    if status != 200 or not isinstance(body, dict):
        return None
    return int(body.get("total_count", 0))


def fetch_metrics_for_repo(url: str, token: str) -> dict[str, Any]:
    """Fetch all 17 columns for one repo. Returns dict matching METRICS_COLUMNS."""
    out: dict[str, Any] = {col: "" for col in METRICS_COLUMNS}
    out["repo"] = url

    parsed = parse_repo_url(url)
    if not parsed:
        out["currently_reachable"] = False
        return out
    owner, repo = parsed
    out["repo_name"] = f"{owner}/{repo}"

    status, repo_data, _ = api_get(f"/repos/{owner}/{repo}", token)
    if status == 404 or repo_data is None or not isinstance(repo_data, dict):
        out["currently_reachable"] = False
        return out
    if status != 200:
        out["currently_reachable"] = False
        return out

    out["currently_reachable"] = True
    out["visibility"] = repo_data.get("visibility", "")
    out["stars"] = repo_data.get("stargazers_count", "")
    out["watchers"] = repo_data.get("subscribers_count", "")
    out["forks"] = repo_data.get("forks_count", "")
    out["created_at"] = repo_data.get("created_at", "")
    out["updated_at"] = repo_data.get("updated_at", "")
    out["pushed_at"] = repo_data.get("pushed_at", "")
    topics = repo_data.get("topics") or []
    out["topics"] = ";".join(topics) if topics else ""
    out["has_issues"] = repo_data.get("has_issues", "")
    out["has_wiki"] = repo_data.get("has_wiki", "")
    out["has_discussions"] = repo_data.get("has_discussions", "")

    # Issue + PR split via search API (counts only, no body fetch).
    full = f"{owner}/{repo}"
    out["open_issues"] = search_count(
        f"repo:{full} is:issue is:open", token)
    out["closed_issues"] = search_count(
        f"repo:{full} is:issue is:closed", token)
    out["open_prs"] = search_count(
        f"repo:{full} is:pr is:open", token)
    out["closed_prs"] = search_count(
        f"repo:{full} is:pr is:closed", token)

    out["contributors"] = get_contributors_count(owner, repo, token)
    return out


def load_done(out_path: str) -> set[str]:
    """Read existing output CSV (if any) and return the set of already-processed repos."""
    if not os.path.isfile(out_path):
        return set()
    done: set[str] = set()
    try:
        with open(out_path, "r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                if row.get("repo"):
                    done.add(row["repo"].strip())
    except Exception:
        pass
    return done


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2

    in_csv = argv[1]
    out_csv = argv[2] if len(argv) > 2 else "corpus_metrics.csv"

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print("ERROR: GITHUB_TOKEN environment variable is required.", file=sys.stderr)
        print("Without it the API limit is 60/hr; 408 repos x 6 calls would take ~40hr.",
              file=sys.stderr)
        return 1

    with open(in_csv, "r", encoding="utf-8", newline="") as fh:
        repos = [r["repo"].strip() for r in csv.DictReader(fh) if r.get("repo")]
    print(f"Loaded {len(repos)} repos from {in_csv}", flush=True)

    done = load_done(out_csv)
    todo = [r for r in repos if r not in done]
    print(f"{len(done)} already processed, {len(todo)} to fetch.", flush=True)

    new_file = not os.path.isfile(out_csv)
    with open(out_csv, "a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=METRICS_COLUMNS)
        if new_file:
            writer.writeheader()

        for i, url in enumerate(todo, start=1):
            t0 = time.monotonic()
            try:
                row = fetch_metrics_for_repo(url, token)
            except Exception as exc:
                # Never let one bad repo kill the run.
                row = {col: "" for col in METRICS_COLUMNS}
                row["repo"] = url
                row["currently_reachable"] = False
                print(f"  [{i:4d}/{len(todo)}] ERROR {url}: "
                      f"{type(exc).__name__}: {exc}", flush=True)

            writer.writerow(row)
            fh.flush()  # so resume works even if killed mid-run

            reachable_mark = "✓" if row.get("currently_reachable") else "✗"
            owner_repo = row.get("repo_name") or url[-50:]
            stars = row.get("stars", "")
            dt = time.monotonic() - t0
            print(f"  [{i:4d}/{len(todo)}] {reachable_mark} {owner_repo[:50]:50s} "
                  f"stars={stars}  t={dt:.1f}s", flush=True)

    print(f"\nDone. Output: {out_csv}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
