"""Stage 5: Taxonomy aggregation + headline figure for the paper.

One pass over the existing finding artifacts produces:
    1. taxonomy_static_matrix.csv   — 8 stage rows × 15 category cols (+ totals)
    2. taxonomy_llm_matrix.csv      — 6 stage rows × 13 category cols (+ totals)
    3. taxonomy_static_rules.csv    — audit trail: every (tool, rule_id) -> category
    4. stage_summary.csv            — per-stage figure inputs
    5. pipeline_figure.{png,svg}    — the headline figure

Inputs (read-only, walked from project root by default):
    stage4_findings/*.json    static-analysis findings (Bandit / Semgrep / pip-audit)
    llm_findings/*.json       Claude absent-control findings
    verified_corpus.csv       gives the 408-repo denominator

Usage:
    python -m stage4.taxonomy

Design notes:

- The static rule_id -> category mapping below was hand-curated against the
  unique rule_ids that actually appear in stage4_findings/ (see rule_ids.csv
  produced by dump_rule_ids.py). Edit the dicts to adjust.

- 4 categories of minor findings are dropped per agreed scope:
  Paramiko auto-trust (bandit B507), bidi control chars (bandit B613),
  Docker root user (semgrep last-user-is-root), and NaN injection
  (semgrep nan-injection). They are logged in the audit-trail CSV with
  assigned_category="(dropped)" so the decision is transparent.

- Multi-stage findings (stage="a+b") are attributed to their first listed
  stage so per-stage totals sum to the unique-finding count (6,295). The
  count of multi-stage findings is reported on stdout for transparency.

- Findings in dependency manifests (stage="dependencies") get their own
  matrix row. Off-pipeline findings (stage in reachable_unmapped /
  unreachable / unknown) collapse into "out_of_scope".

- The headline figure's six boxes represent the six pipeline stages only.
  Its denominator is pipeline-stage findings (excludes dependencies and
  out_of_scope) so the six percentages sum to ~100%. Dependency and
  out-of-scope counts are reported separately in stage_summary.csv and on
  stdout for the paper's accompanying text.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from typing import Any


# ============================================================================
# Configuration: stages, categories, and the rule_id -> category mapping.
# ============================================================================

PIPELINE_STAGES: list[str] = [
    "data_acquisition",
    "data_preparation",
    "modeling",
    "training",
    "evaluation",
    "inference",
]

# Extra rows in the static matrix only.
EXTRA_STATIC_ROWS: list[str] = ["dependencies", "out_of_scope"]

# Stage labels for the figure (display names; 'inference' shown as 'Prediction'
# to match the professor's reference figure exactly).
STAGE_DISPLAY: dict[str, str] = {
    "data_acquisition": "Data\nAcquisition",
    "data_preparation": "Data\nPreparation",
    "modeling":         "Modeling",
    "training":         "Training",
    "evaluation":       "Evaluation",
    "inference":        "Prediction",
}

# Muted, non-severity-coded box colors (no greens, no reds).
STAGE_COLORS: dict[str, str] = {
    "data_acquisition": "#b3e5fc",   # light blue
    "data_preparation": "#c5cae9",   # light indigo
    "modeling":         "#d1c4e9",   # light purple
    "training":         "#d7ccc8",   # light tan
    "evaluation":       "#cfd8dc",   # light blue-grey
    "inference":        "#b0bec5",   # medium grey
}

# 15 static categories in count-desc order (column order for the matrix CSV).
STATIC_CATEGORIES: list[str] = [
    "insecure_deserialization",
    "untrusted_model_download",
    "code_injection",
    "command_injection",
    "vulnerable_dependency",
    "sql_injection",
    "network_security",
    "xss_template_injection",
    "url_scheme_ssrf",
    "flask_django_misconfig",
    "xxe_xml",
    "tempfile_and_perms",
    "weak_crypto",
    "path_traversal",
    "hardcoded_secret",
]

# 13 LLM categories in the order they appear across the six stages.
LLM_CATEGORIES: list[str] = [
    "input_validation",                # data_acquisition
    "untrusted_source_handling",       # data_acquisition
    "label_flipping_detection",        # data_preparation
    "data_poisoning_defenses",         # data_preparation
    "model_integrity_verification",    # modeling
    "label_distribution_validation",   # training
    "backdoor_or_trigger_detection",   # training
    "differential_privacy",            # training
    "adversarial_robustness_testing",  # evaluation
    "metric_tampering_protection",     # evaluation
    "input_sanitization",              # inference
    "output_bounds_checks",            # inference
    "prompt_injection_defenses",       # inference
]

# Bandit + Semgrep rule_id -> category. pip_audit is handled separately
# (every pip_audit finding -> vulnerable_dependency) since 169 unique CVE
# IDs are not worth enumerating.
STATIC_RULE_MAP: dict[tuple[str, str], str] = {
    # ---- insecure_deserialization ----
    ("bandit",  "B301"): "insecure_deserialization",  # pickle
    ("bandit",  "B302"): "insecure_deserialization",  # marshal
    ("bandit",  "B506"): "insecure_deserialization",  # yaml.unsafe_load
    ("bandit",  "B614"): "insecure_deserialization",  # torch.load
    ("semgrep", "python.lang.security.deserialization.pickle.avoid-pickle"):              "insecure_deserialization",
    ("semgrep", "python.lang.security.deserialization.pickle.avoid-cPickle"):             "insecure_deserialization",
    ("semgrep", "python.lang.security.deserialization.pickle.avoid-shelve"):              "insecure_deserialization",
    ("semgrep", "python.lang.security.deserialization.pickle.avoid-dill"):                "insecure_deserialization",
    ("semgrep", "python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load"): "insecure_deserialization",
    ("semgrep", "python.flask.security.insecure-deserialization.insecure-deserialization"): "insecure_deserialization",
    ("semgrep", "python.lang.security.audit.marshal.marshal-usage"):                      "insecure_deserialization",

    # ---- untrusted_model_download ----
    ("bandit",  "B615"): "untrusted_model_download",  # HF from_pretrained no revision

    # ---- code_injection ----
    ("bandit",  "B102"): "code_injection",  # exec
    ("bandit",  "B307"): "code_injection",  # eval
    ("semgrep", "python.lang.security.audit.eval-detected.eval-detected"):    "code_injection",
    ("semgrep", "python.lang.security.audit.exec-detected.exec-detected"):    "code_injection",
    ("semgrep", "python.django.security.injection.code.user-exec.user-exec"): "code_injection",
    ("semgrep", "python.flask.security.injection.user-exec.exec-injection"):  "code_injection",

    # ---- command_injection ----
    ("bandit",  "B601"): "command_injection",  # Paramiko shell injection
    ("bandit",  "B602"): "command_injection",  # subprocess shell=True
    ("bandit",  "B605"): "command_injection",  # process with shell
    ("semgrep", "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"):                     "command_injection",
    ("semgrep", "python.lang.security.audit.dangerous-system-call-tainted-env-args.dangerous-system-call-tainted-env-args"): "command_injection",
    ("semgrep", "python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args"): "command_injection",
    ("semgrep", "python.lang.security.audit.dangerous-os-exec-tainted-env-args.dangerous-os-exec-tainted-env-args"): "command_injection",

    # ---- sql_injection ----
    ("bandit",  "B608"): "sql_injection",
    ("semgrep", "python.flask.security.injection.tainted-sql-string.tainted-sql-string"): "sql_injection",

    # ---- network_security ----
    ("bandit",  "B113"): "network_security",  # requests w/o timeout
    ("bandit",  "B501"): "network_security",  # verify=False
    ("bandit",  "B321"): "network_security",  # ftplib call (cleartext)
    ("bandit",  "B402"): "network_security",  # ftplib import (cleartext)
    ("bandit",  "B323"): "network_security",  # unverified SSL context
    ("semgrep", "python.lang.security.audit.insecure-transport.requests.request-with-http.request-with-http"): "network_security",
    ("semgrep", "python.requests.security.disabled-cert-validation.disabled-cert-validation"):                 "network_security",
    ("semgrep", "python.lang.security.audit.ssl-wrap-socket-is-deprecated.ssl-wrap-socket-is-deprecated"):     "network_security",
    ("semgrep", "typescript.react.security.react-insecure-request.react-insecure-request"):                    "network_security",
    ("semgrep", "python.lang.security.audit.httpsconnection-detected.httpsconnection-detected"):               "network_security",
    ("semgrep", "python.lang.security.unverified-ssl-context.unverified-ssl-context"):                         "network_security",

    # ---- xss_template_injection ----
    ("bandit",  "B701"): "xss_template_injection",  # jinja2 autoescape=False
    ("bandit",  "B704"): "xss_template_injection",  # markupsafe.Markup on untrusted
    ("semgrep", "python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe"): "xss_template_injection",
    ("semgrep", "generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var"):             "xss_template_injection",
    ("semgrep", "generic.html-templates.security.var-in-script-tag.var-in-script-tag"):                       "xss_template_injection",
    ("semgrep", "generic.html-templates.security.var-in-href.var-in-href"):                                   "xss_template_injection",
    ("semgrep", "python.flask.security.injection.raw-html-concat.raw-html-format"):                           "xss_template_injection",
    ("semgrep", "python.jinja2.security.audit.missing-autoescape-disabled.missing-autoescape-disabled"):      "xss_template_injection",
    ("semgrep", "python.flask.security.injection.csv-writer-injection.csv-writer-injection"):                 "xss_template_injection",
    ("semgrep", "python.flask.security.audit.directly-returned-format-string.directly-returned-format-string"): "xss_template_injection",
    ("semgrep", "python.flask.security.unescaped-template-extension.unescaped-template-extension"):           "xss_template_injection",
    ("semgrep", "python.flask.security.xss.audit.template-autoescape-off.template-autoescape-off"):           "xss_template_injection",

    # ---- url_scheme_ssrf ----
    ("bandit",  "B310"): "url_scheme_ssrf",  # urlopen permitted schemes
    ("semgrep", "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected"): "url_scheme_ssrf",
    ("semgrep", "python.flask.security.open-redirect.open-redirect"):                                  "url_scheme_ssrf",
    ("semgrep", "python.flask.security.injection.ssrf-requests.ssrf-requests"):                        "url_scheme_ssrf",

    # ---- flask_django_misconfig ----
    ("bandit",  "B104"): "flask_django_misconfig",  # bind 0.0.0.0
    ("bandit",  "B201"): "flask_django_misconfig",  # Flask debug=True
    ("semgrep", "python.flask.security.audit.debug-enabled.debug-enabled"):                       "flask_django_misconfig",
    ("semgrep", "python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host"):  "flask_django_misconfig",
    ("semgrep", "python.flask.security.audit.app-run-security-config.avoid_using_app_run_directly"): "flask_django_misconfig",
    ("semgrep", "python.fastapi.security.wildcard-cors.wildcard-cors"):                           "flask_django_misconfig",
    ("semgrep", "python.django.security.audit.csrf-exempt.no-csrf-exempt"):                       "flask_django_misconfig",
    ("semgrep", "python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_DEBUG"):     "flask_django_misconfig",
    ("semgrep", "python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_SECRET_KEY"): "flask_django_misconfig",
    ("semgrep", "python.django.security.audit.unvalidated-password.unvalidated-password"):        "flask_django_misconfig",

    # ---- xxe_xml ----
    ("bandit",  "B314"): "xxe_xml",  # xml.etree.ElementTree.parse
    ("bandit",  "B318"): "xxe_xml",  # xml.dom.minidom.parse
    ("bandit",  "B411"): "xxe_xml",  # xmlrpc FastUnmarshaller
    ("bandit",  "B313"): "xxe_xml",  # xml.etree.cElementTree.parse
    ("semgrep", "python.lang.security.use-defused-xml.use-defused-xml"):             "xxe_xml",
    ("semgrep", "python.lang.security.use-defused-xml-parse.use-defused-xml-parse"): "xxe_xml",
    ("semgrep", "python.lang.security.use-defused-xmlrpc.use-defused-xmlrpc"):       "xxe_xml",
    ("semgrep", "java.lang.security.audit.xml-decoder.xml-decoder"):                 "xxe_xml",

    # ---- tempfile_and_perms ----
    ("bandit",  "B108"): "tempfile_and_perms",  # insecure tempfile
    ("bandit",  "B103"): "tempfile_and_perms",  # chmod bad permissions
    ("semgrep", "python.lang.security.audit.insecure-file-permissions.insecure-file-permissions"): "tempfile_and_perms",

    # ---- weak_crypto ----
    ("bandit",  "B324"): "weak_crypto",  # weak MD5
    ("semgrep", "python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5"):   "weak_crypto",
    ("semgrep", "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1"):      "weak_crypto",
    ("semgrep", "python.lang.security.audit.sha224-hash.sha224-hash"):                              "weak_crypto",
    ("semgrep", "python.lang.security.insecure-uuid-version.insecure-uuid-version"):                "weak_crypto",

    # ---- path_traversal ----
    ("bandit",  "B202"): "path_traversal",  # tarfile.extractall

    # ---- hardcoded_secret ----
    ("semgrep", "python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure"): "hardcoded_secret",
    ("semgrep", "python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret"): "hardcoded_secret",
}

# Rules explicitly dropped from the taxonomy (4 categories deemed too sparse).
# Tracked separately so the audit-trail CSV can flag them rather than silently
# omitting them.
DROPPED_RULES: set[tuple[str, str]] = {
    ("bandit",  "B507"),   # Paramiko auto-trust host key
    ("bandit",  "B613"),   # bidi control chars
    ("semgrep", "dockerfile.security.last-user-is-root.last-user-is-root"),
    ("semgrep", "python.flask.security.injection.nan-injection.nan-injection"),
}


# ============================================================================
# I/O helpers
# ============================================================================

def repo_key_from_url(url: str) -> str:
    parts = url.rstrip("/").split("/")
    if len(parts) < 2:
        return url.replace("/", "__")
    return f"{parts[-2]}__{parts[-1]}"


def load_corpus(path: str) -> list[str]:
    repos: list[str] = []
    with open(path, "r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise ValueError(f"{path}: no header row")
        field = "repo" if "repo" in reader.fieldnames else reader.fieldnames[0]
        for row in reader:
            url = (row.get(field) or "").strip()
            if url:
                repos.append(url)
    return repos


def load_json_list(path: str) -> list[dict[str, Any]]:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[warn] could not parse {path}: {exc}", file=sys.stderr)
        return []
    return data if isinstance(data, list) else []


# ============================================================================
# Categorization + stage attribution
# ============================================================================

def categorize_static(tool: str, rule_id: str) -> str | None:
    """Return the semantic category for a static finding, or None if dropped."""
    tool = (tool or "").lower()
    rid = rule_id or ""
    if tool == "pip_audit" or tool == "pip-audit":
        return "vulnerable_dependency"
    if (tool, rid) in DROPPED_RULES:
        return None
    return STATIC_RULE_MAP.get((tool, rid))


def categorize_llm(rule_id: str) -> str | None:
    """Strip 'absent_control.' prefix; return None if it doesn't match."""
    if not rule_id or not rule_id.startswith("absent_control."):
        return None
    cat = rule_id[len("absent_control."):]
    return cat if cat in LLM_CATEGORIES else None


def stage_weights(stage_field: str | None, mode: str) -> list[tuple[str, float]]:
    """Map a finding's `stage` value to [(matrix_row, weight), ...].

    mode:
      'expand'     — multi-stage findings count once (weight 1) in EACH listed
                     stage. Per-stage totals exceed the unique-finding count;
                     this is the default and the paper's footnoted convention.
      'primary'    — first listed stage only. NOTE: stage_mapping.py sorts
                     stage names alphabetically before joining, so 'first' is
                     alphabetical, which systematically over-credits
                     data_acquisition. Kept for comparison, not for the paper.
      'fractional' — each of the N listed stages gets weight 1/N; totals sum
                     to the unique-finding count, cells become floats.
    """
    if not stage_field:
        return [("out_of_scope", 1.0)]
    if stage_field == "dependencies":
        return [("dependencies", 1.0)]
    if stage_field in ("reachable_unmapped", "unreachable", "unknown"):
        return [("out_of_scope", 1.0)]
    parts = [p.strip() for p in stage_field.split("+")]
    stages = [p for p in parts if p in PIPELINE_STAGES]
    if not stages:
        return [("out_of_scope", 1.0)]
    if mode == "primary":
        return [(stages[0], 1.0)]
    if mode == "fractional":
        w = 1.0 / len(stages)
        return [(s, w) for s in stages]
    # default: expand
    return [(s, 1.0) for s in stages]


def is_multi_stage(stage_field: str | None) -> bool:
    if not stage_field:
        return False
    return "+" in stage_field


# ============================================================================
# Aggregation
# ============================================================================

class Aggregator:
    """Collect everything in one pass so we can write all 5 outputs without
    re-walking the JSON files."""

    def __init__(self, attribution: str = "expand") -> None:
        self.attribution = attribution
        # Stage x category cell weights (floats to support fractional mode).
        self.static_matrix: dict[tuple[str, str], float] = defaultdict(float)
        self.llm_matrix:    dict[tuple[str, str], float] = defaultdict(float)
        # Audit trail: (tool, rule_id) -> {count, assigned_category, example_message}
        self.static_rule_info: dict[tuple[str, str], dict[str, Any]] = {}
        # Per-stage repo hit sets (for the figure's bottom number).
        self.static_repos_per_stage: dict[str, set[str]] = defaultdict(set)
        self.llm_repos_per_stage:    dict[str, set[str]] = defaultdict(set)
        # Per-stage total findings (weighted).
        self.static_total_per_stage: dict[str, float] = defaultdict(float)
        self.llm_total_per_stage:    dict[str, float] = defaultdict(float)
        # Diagnostics.
        self.unmapped_rules: Counter = Counter()
        self.multi_stage_findings: int = 0
        self.total_static: int = 0
        self.total_llm:    int = 0

    def ingest_static(self, repo_key: str, finding: dict[str, Any]) -> None:
        tool = (finding.get("tool") or "").lower()
        rid  = finding.get("rule_id") or ""
        cat  = categorize_static(tool, rid)

        # Audit-trail bookkeeping (covers dropped and unmapped too).
        key = (tool, rid)
        info = self.static_rule_info.setdefault(key, {
            "count": 0,
            "assigned_category": None,
            "example_message": (finding.get("message") or "")[:200],
        })
        info["count"] += 1
        if cat is not None:
            info["assigned_category"] = cat
        elif (tool, rid) in DROPPED_RULES:
            info["assigned_category"] = "(dropped)"
        else:
            info["assigned_category"] = "(unmapped)"
            self.unmapped_rules[key] += 1

        self.total_static += 1
        if is_multi_stage(finding.get("stage")):
            self.multi_stage_findings += 1

        # Dropped findings contribute to neither matrix nor per-stage totals.
        if cat is None:
            return

        for stage, w in stage_weights(finding.get("stage"), self.attribution):
            self.static_matrix[(stage, cat)] += w
            self.static_total_per_stage[stage] += w
            self.static_repos_per_stage[stage].add(repo_key)

    def ingest_llm(self, repo_key: str, finding: dict[str, Any]) -> None:
        rid = finding.get("rule_id") or ""
        cat = categorize_llm(rid)
        self.total_llm += 1
        if cat is None:
            return
        for stage, w in stage_weights(finding.get("stage"), self.attribution):
            if stage not in PIPELINE_STAGES:
                # LLM findings are stage-scoped by design; off-pipeline rows
                # would indicate a data problem, so skip rather than count.
                continue
            self.llm_matrix[(stage, cat)] += w
            self.llm_total_per_stage[stage] += w
            self.llm_repos_per_stage[stage].add(repo_key)


# ============================================================================
# Output writers
# ============================================================================

def _fmt(x: float) -> Any:
    """Integers render as ints; fractional weights render with 2 decimals."""
    return int(round(x)) if abs(x - round(x)) < 1e-9 else round(x, 2)


def write_static_matrix(agg: Aggregator, path: str) -> None:
    rows = PIPELINE_STAGES + EXTRA_STATIC_ROWS
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["stage"] + STATIC_CATEGORIES + ["total"])
        col_totals: dict[str, float] = defaultdict(float)
        grand_total = 0.0
        for r in rows:
            row_cells = [agg.static_matrix.get((r, c), 0.0) for c in STATIC_CATEGORIES]
            row_total = sum(row_cells)
            grand_total += row_total
            for c, n in zip(STATIC_CATEGORIES, row_cells):
                col_totals[c] += n
            w.writerow([r] + [_fmt(v) for v in row_cells] + [_fmt(row_total)])
        w.writerow(["total"] + [_fmt(col_totals[c]) for c in STATIC_CATEGORIES]
                   + [_fmt(grand_total)])


def write_llm_matrix(agg: Aggregator, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["stage"] + LLM_CATEGORIES + ["total"])
        col_totals: dict[str, float] = defaultdict(float)
        grand_total = 0.0
        for r in PIPELINE_STAGES:
            row_cells = [agg.llm_matrix.get((r, c), 0.0) for c in LLM_CATEGORIES]
            row_total = sum(row_cells)
            grand_total += row_total
            for c, n in zip(LLM_CATEGORIES, row_cells):
                col_totals[c] += n
            w.writerow([r] + [_fmt(v) for v in row_cells] + [_fmt(row_total)])
        w.writerow(["total"] + [_fmt(col_totals[c]) for c in LLM_CATEGORIES]
                   + [_fmt(grand_total)])


def write_static_rules(agg: Aggregator, path: str) -> None:
    """Audit-trail CSV: every (tool, rule_id) seen, with its assigned category."""
    rows = []
    for (tool, rid), info in agg.static_rule_info.items():
        rows.append((tool, rid, info["assigned_category"], info["count"],
                     info["example_message"]))
    # Sort: by category, then count desc within category.
    rows.sort(key=lambda r: (r[2] or "", -r[3]))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "rule_id", "assigned_category", "count", "example_message"])
        w.writerows(rows)


def write_stage_summary(agg: Aggregator, n_repos: int, path: str) -> list[dict[str, Any]]:
    """Per-stage figure inputs. Denominator for pct_of_all_findings is the
    pipeline-stage attribution total — so the six percentages sum to ~100%
    in every attribution mode. In 'expand' mode a multi-stage finding
    contributes to several stages, so the underlying totals exceed the
    unique-finding count; the paper footnote covers this.
    dependencies/out_of_scope counts appear elsewhere (matrix CSV, stdout).
    """
    pipeline_static_total = sum(agg.static_total_per_stage[s] for s in PIPELINE_STAGES)
    rows: list[dict[str, Any]] = []
    for s in PIPELINE_STAGES:
        n_static = agg.static_total_per_stage[s]
        n_llm    = agg.llm_total_per_stage[s]
        n_hit    = len(agg.static_repos_per_stage[s])
        pct_findings = (100.0 * n_static / pipeline_static_total) if pipeline_static_total else 0.0
        pct_repos    = (100.0 * n_hit / n_repos) if n_repos else 0.0
        rows.append({
            "stage": s,
            "total_findings_static": _fmt(n_static),
            "total_findings_llm":    _fmt(n_llm),
            "pct_of_all_findings":   round(pct_findings, 1),
            "repos_with_findings":   n_hit,
            "pct_of_repos":          round(pct_repos, 1),
        })
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return rows


def draw_figure(rows: list[dict[str, Any]], out_png: str, out_svg: str) -> None:
    """Six rounded rectangles, arrows between, two-number caption above each.
    Matches the reference figure's layout. Muted colors, no severity coding.
    """
    import matplotlib.patches as mpatches
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(13, 3.2))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 3.0)
    ax.axis("off")

    box_w, box_h = 1.6, 1.15
    gap = 0.3
    y_box = 0.55
    x = 0.4
    for row in rows:
        stage = row["stage"]
        rect = mpatches.FancyBboxPatch(
            (x, y_box), box_w, box_h,
            boxstyle="round,pad=0.02,rounding_size=0.15",
            linewidth=1.0,
            edgecolor="#37474f",
            facecolor=STAGE_COLORS[stage],
        )
        ax.add_patch(rect)
        ax.text(x + box_w / 2, y_box + box_h / 2,
                STAGE_DISPLAY[stage],
                ha="center", va="center", fontsize=10.5)
        # Two-line numeric caption above the box.
        ax.text(x + box_w / 2, y_box + box_h + 0.40,
                f"{row['pct_of_all_findings']:.1f}%",
                ha="center", va="bottom", fontsize=10.5, fontweight="bold")
        ax.text(x + box_w / 2, y_box + box_h + 0.10,
                f"{row['pct_of_repos']:.1f}%",
                ha="center", va="bottom", fontsize=10.5, fontweight="bold")
        # Arrow to the next box.
        if stage != PIPELINE_STAGES[-1]:
            ax.annotate(
                "", xy=(x + box_w + gap, y_box + box_h / 2),
                xytext=(x + box_w, y_box + box_h / 2),
                arrowprops=dict(arrowstyle="->", lw=1.2, color="#37474f"),
            )
        x += box_w + gap

    fig.tight_layout()
    fig.savefig(out_png, dpi=300, bbox_inches="tight")
    fig.savefig(out_svg, bbox_inches="tight")
    plt.close(fig)


# ============================================================================
# Stdout reporting
# ============================================================================

def print_report(agg: Aggregator, rows: list[dict[str, Any]], n_repos: int) -> None:
    print()
    print("=" * 68)
    print(f" Taxonomy aggregation report  (attribution mode: {agg.attribution})")
    print("=" * 68)
    print(f" Corpus size                       : {n_repos} repos")
    print(f" Total static findings (unique)    : {agg.total_static}")
    print(f" Total LLM (Claude) findings       : {agg.total_llm}")
    print(f" Multi-stage findings              : {agg.multi_stage_findings} "
          f"of {agg.total_static} "
          f"({100.0 * agg.multi_stage_findings / agg.total_static:.1f}%)"
          if agg.total_static else " Multi-stage findings              : 0")
    print(f" Unmapped static rule_ids          : {len(agg.unmapped_rules)}")
    if agg.unmapped_rules:
        print("   --- WARNING: unmapped rules ---")
        for (tool, rid), n in agg.unmapped_rules.most_common(10):
            print(f"   {tool:<10} {rid:<70} {n}")
    dropped_count = sum(info["count"] for info in agg.static_rule_info.values()
                        if info["assigned_category"] == "(dropped)")
    print(f" Dropped findings (by design)      : {dropped_count}")
    print()
    print(f" Per-stage static totals ({agg.attribution} attribution):")
    for s in PIPELINE_STAGES:
        print(f"   {s:<22} {_fmt(agg.static_total_per_stage[s]):>8}")
    print(f"   {'dependencies':<22} {_fmt(agg.static_total_per_stage['dependencies']):>8}")
    print(f"   {'out_of_scope':<22} {_fmt(agg.static_total_per_stage['out_of_scope']):>8}")
    print()
    print(" Headline numbers (paste straight into the paper draft):")
    print(f"   {'stage':<22} {'top %':>8} {'bottom %':>10}")
    for r in rows:
        print(f"   {r['stage']:<22} {r['pct_of_all_findings']:>7.1f}% "
              f"{r['pct_of_repos']:>9.1f}%")
    print()


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--findings-dir",    default="stage4_findings")
    p.add_argument("--llm-dir",         default="llm_findings")
    p.add_argument("--corpus",          default="verified_corpus.csv")
    p.add_argument("--out-dir",         default=".",
                   help="where to write the 5 output files (default: project root)")
    p.add_argument("--attribution", choices=["expand", "primary", "fractional"],
                   default="expand",
                   help="how to attribute multi-stage findings (default: expand; "
                        "'primary' kept only for comparison — it inherits the "
                        "alphabetical-sort bias from stage_mapping.py)")
    args = p.parse_args()

    repos = load_corpus(args.corpus)
    n_repos = len(repos)
    print(f"[info] corpus: {n_repos} repos from {args.corpus}")
    print(f"[info] attribution mode: {args.attribution}")

    agg = Aggregator(attribution=args.attribution)
    for url in repos:
        key = repo_key_from_url(url)
        for f in load_json_list(os.path.join(args.findings_dir, f"{key}.json")):
            # Skip claude_judgment rows if they ever appear in stage4_findings/
            # by mistake — they belong to the LLM taxonomy.
            if (f.get("tool") or "").lower() == "claude_judgment":
                continue
            agg.ingest_static(key, f)
        for f in load_json_list(os.path.join(args.llm_dir, f"{key}.json")):
            if (f.get("tool") or "").lower() != "claude_judgment":
                continue
            agg.ingest_llm(key, f)

    os.makedirs(args.out_dir, exist_ok=True)
    write_static_matrix(agg, os.path.join(args.out_dir, "taxonomy_static_matrix.csv"))
    write_llm_matrix   (agg, os.path.join(args.out_dir, "taxonomy_llm_matrix.csv"))
    write_static_rules (agg, os.path.join(args.out_dir, "taxonomy_static_rules.csv"))
    rows = write_stage_summary(agg, n_repos,
                               os.path.join(args.out_dir, "stage_summary.csv"))
    draw_figure(rows,
                os.path.join(args.out_dir, "pipeline_figure.png"),
                os.path.join(args.out_dir, "pipeline_figure.svg"))

    print_report(agg, rows, n_repos)
    print(f"[ok] wrote 5 outputs to {args.out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
