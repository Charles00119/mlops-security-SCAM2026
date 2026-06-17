"""Correlate project maturity with vulnerability counts/density.

Joins, per repo:
    corpus_metrics.csv          stars, forks, contributors, closed_prs, age
    loc.csv          (optional) reachable LOC  -> enables density analysis
    github_repo_extras.csv (optional) commit_count, size_kb
    stage4_findings/*.json      vulnerability counts (total + pipeline-only)

Outputs:
    correlation_table.csv   Spearman rho for every (predictor, outcome) pair,
                            with n (repos with both values present)
    correlation_data.csv    the joined per-repo table (for inspection / reuse)
    correlation_plots.png   scatter grid: predictors vs vulnerability density
                            (falls back to raw counts if loc.csv is absent)

Spearman is computed from scratch (rank + Pearson on ranks) — no scipy needed.

Usage:
    python -m stage4.correlate
    python -m stage4.correlate --no-loc          # before loc.csv exists
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
from datetime import datetime, timezone
from typing import Any


# ----------------------------- tiny stats ---------------------------------

def rank(values: list[float]) -> list[float]:
    """Average ranks (ties share the mean of their rank positions)."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def pearson(x: list[float], y: list[float]) -> float:
    n = len(x)
    if n < 3:
        return float("nan")
    mx, my = sum(x) / n, sum(y) / n
    sxx = sum((a - mx) ** 2 for a in x)
    syy = sum((b - my) ** 2 for b in y)
    sxy = sum((a - mx) * (b - my) for a, b in zip(x, y))
    if sxx == 0 or syy == 0:
        return float("nan")
    return sxy / math.sqrt(sxx * syy)


def spearman(x: list[float], y: list[float]) -> float:
    return pearson(rank(x), rank(y))


# ----------------------------- loading ------------------------------------

def repo_key_from_url(url: str) -> str:
    parts = url.rstrip("/").split("/")
    return f"{parts[-2]}__{parts[-1]}" if len(parts) >= 2 else url


def parse_dt(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def load_metrics(path: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            url = row["repo"]
            created = parse_dt(row.get("created_at", ""))
            pushed  = parse_dt(row.get("pushed_at", ""))
            age_days = ((pushed - created).days
                        if created and pushed else None)
            def _int(field: str) -> int | None:
                v = (row.get(field) or "").strip()
                return int(v) if v.isdigit() else None
            out[url] = {
                "stars":        _int("stars"),
                "forks":        _int("forks"),
                "contributors": _int("contributors"),
                "closed_prs":   _int("closed_prs"),
                "closed_issues": _int("closed_issues"),
                "age_days":     age_days,
            }
    return out


def load_loc(path: str) -> dict[str, int]:
    out: dict[str, int] = {}
    if not os.path.isfile(path):
        return out
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("clone_ok") == "True":
                try:
                    out[row["repo"]] = int(row["loc_reachable"])
                except (ValueError, KeyError):
                    pass
    return out


def load_extras(path: str) -> dict[str, dict[str, int | None]]:
    out: dict[str, dict[str, int | None]] = {}
    if not os.path.isfile(path):
        return out
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("fetch_ok") != "True":
                continue
            def _int(field: str) -> int | None:
                v = (row.get(field) or "").strip()
                return int(v) if v.isdigit() else None
            out[row["repo"]] = {
                "commit_count": _int("commit_count"),
                "size_kb":      _int("size_kb"),
                "python_bytes": _int("python_bytes"),
            }
    return out


PIPELINE_STAGES = {"data_acquisition", "data_preparation", "modeling",
                   "training", "evaluation", "inference"}


def count_findings(findings_dir: str, url: str) -> tuple[int, int]:
    """(total static findings, pipeline-stage-attributed findings)."""
    key = repo_key_from_url(url)
    path = os.path.join(findings_dir, f"{key}.json")
    if not os.path.isfile(path):
        return 0, 0
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return 0, 0
    if not isinstance(data, list):
        return 0, 0
    total = pipe = 0
    for f in data:
        if (f.get("tool") or "").lower() == "claude_judgment":
            continue
        total += 1
        stage = f.get("stage") or ""
        if any(p in PIPELINE_STAGES for p in stage.split("+")):
            pipe += 1
    return total, pipe


# ----------------------------- analysis -----------------------------------

PREDICTORS = ["loc_reachable", "commit_count", "size_kb", "contributors",
              "stars", "forks", "closed_prs", "age_days"]
OUTCOMES = ["findings_total", "findings_pipeline",
            "density_total", "density_pipeline"]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--corpus",       default="verified_corpus.csv")
    p.add_argument("--metrics",      default="corpus_metrics.csv")
    p.add_argument("--loc",          default="loc.csv")
    p.add_argument("--extras",       default="github_repo_extras.csv")
    p.add_argument("--findings-dir", default="stage4_findings")
    p.add_argument("--out-dir",      default=".")
    p.add_argument("--no-loc", action="store_true",
                   help="run before loc.csv exists (skips density outcomes)")
    args = p.parse_args()

    metrics = load_metrics(args.metrics)
    loc     = {} if args.no_loc else load_loc(args.loc)
    extras  = load_extras(args.extras)

    # Build the joined per-repo table.
    table: list[dict[str, Any]] = []
    for url, m in metrics.items():
        total, pipe = count_findings(args.findings_dir, url)
        row: dict[str, Any] = {"repo": url,
                               "findings_total": total,
                               "findings_pipeline": pipe}
        row.update(m)
        row.update(extras.get(url, {}))
        l = loc.get(url)
        row["loc_reachable"] = l
        if l and l > 0:
            row["density_total"]    = 1000.0 * total / l
            row["density_pipeline"] = 1000.0 * pipe / l
        else:
            row["density_total"] = row["density_pipeline"] = None
        table.append(row)

    os.makedirs(args.out_dir, exist_ok=True)

    # Per-repo joined data.
    all_fields = (["repo"] + PREDICTORS + OUTCOMES)
    with open(os.path.join(args.out_dir, "correlation_data.csv"), "w",
              newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=all_fields, extrasaction="ignore")
        w.writeheader()
        for row in table:
            w.writerow({k: (round(v, 3) if isinstance(v, float) else v)
                        for k, v in row.items() if k in all_fields} | {"repo": row["repo"]})

    # Correlation table.
    results = []
    for pred in PREDICTORS:
        for out in OUTCOMES:
            pairs = [(r[pred], r[out]) for r in table
                     if isinstance(r.get(pred), (int, float))
                     and isinstance(r.get(out), (int, float))]
            if len(pairs) < 10:
                results.append((pred, out, len(pairs), None))
                continue
            xs = [float(a) for a, _ in pairs]
            ys = [float(b) for _, b in pairs]
            rho = spearman(xs, ys)
            results.append((pred, out, len(pairs),
                            None if math.isnan(rho) else round(rho, 3)))

    with open(os.path.join(args.out_dir, "correlation_table.csv"), "w",
              newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["predictor", "outcome", "n_repos", "spearman_rho"])
        w.writerows(results)

    # Scatter grid.
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    y_field = "density_pipeline" if (loc and not args.no_loc) else "findings_pipeline"
    y_label = ("pipeline findings / 1k LOC" if y_field == "density_pipeline"
               else "pipeline findings (raw count)")
    preds_avail = [pr for pr in PREDICTORS
                   if pr != "loc_reachable"
                   and sum(1 for r in table
                           if isinstance(r.get(pr), (int, float))
                           and isinstance(r.get(y_field), (int, float))) >= 10]
    if preds_avail:
        ncols = 3
        nrows = (len(preds_avail) + ncols - 1) // ncols
        fig, axes = plt.subplots(nrows, ncols,
                                 figsize=(4.2 * ncols, 3.4 * nrows),
                                 squeeze=False)
        for idx, pr in enumerate(preds_avail):
            ax = axes[idx // ncols][idx % ncols]
            xs, ys = [], []
            for r in table:
                if isinstance(r.get(pr), (int, float)) and \
                   isinstance(r.get(y_field), (int, float)):
                    xs.append(r[pr]); ys.append(r[y_field])
            ax.scatter(xs, ys, s=12, alpha=0.5, color="#37474f",
                       edgecolors="none")
            if any(x > 0 for x in xs) and max(xs) / max(1, min(x for x in xs if x > 0) or 1) > 100:
                ax.set_xscale("symlog")
            rho = next((r4 for p4, o4, _, r4 in results
                        if p4 == pr and o4 == y_field), None)
            ax.set_title(f"{pr}  (rho={rho if rho is not None else 'n/a'})",
                         fontsize=10)
            ax.set_xlabel(pr, fontsize=9)
            ax.set_ylabel(y_label, fontsize=9)
            ax.tick_params(labelsize=8)
        for idx in range(len(preds_avail), nrows * ncols):
            axes[idx // ncols][idx % ncols].axis("off")
        fig.tight_layout()
        fig.savefig(os.path.join(args.out_dir, "correlation_plots.png"),
                    dpi=200, bbox_inches="tight")
        plt.close(fig)

    # Console summary.
    print()
    print(f" Spearman correlations vs {y_field}:")
    print(f"   {'predictor':<16} {'n':>5} {'rho':>8}")
    for pr, out, n, rho in results:
        if out == y_field:
            print(f"   {pr:<16} {n:>5} {str(rho):>8}")
    print()
    print(f"[ok] wrote correlation_table.csv, correlation_data.csv, "
          f"correlation_plots.png to {args.out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
