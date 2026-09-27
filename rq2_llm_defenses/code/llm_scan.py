"""Stage 4b: LLM-based defense gap analysis using Claude.

For each verified repo, this script:
  1. Shallow-clones the repo
  2. Rebuilds the call graph (Stages 1-3) to identify which files are
     reachable from the Dockerfile entry point and which stages they
     contribute to
  3. For each stage with non-empty call-graph reachable files, extracts a
     focused code slice (the call-graph files for that pipeline)
  4. Sends the slice to Claude with a stage-specific prompt asking about
     ML-specific defense gaps the static tools can't catch
  5. Parses Claude's structured JSON response into Finding objects with
     tool='claude_judgment'
  6. Writes those findings to llm_findings/{owner}__{repo}.json (separate
     from Stage 4's stage4_findings/ — does not touch existing files)
  7. Writes the call-graph file list to call_graphs/{owner}__{repo}.json
     for reproducibility / downstream reuse
  8. Deletes the clone

Usage:
    python -m stage4.llm_scan verified_corpus.csv

Requires:
    ANTHROPIC_API_KEY environment variable
    GITHUB_TOKEN (optional but recommended for clones)
    The 'anthropic' pip package: pip install anthropic

Outputs (all NEW files; never modifies prior outputs):
    llm_findings/{owner}__{repo}.json   — claude_judgment findings only
    call_graphs/{owner}__{repo}.json    — call-graph file list per stage
    llm_scan_log.csv                    — per-repo run log

Resume support: repos already in llm_scan_log.csv are skipped.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
import subprocess
import sys
import tempfile
import time
import shutil
import traceback
from collections import Counter
from typing import Any

# Make the sibling helpers (findings.py) and the Stage 1-3 scanner package
# (<repo>/00_corpus/scanner) importable from the reorganized layout.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
for _p in (_HERE, os.path.join(_ROOT, "00_corpus", "scanner")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from findings import Finding, dump_findings_json  # type: ignore  # noqa: E402


# -- Anthropic client -------------------------------------------------------

def _get_client():
    """Lazy-import anthropic so the module is importable even if not installed."""
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError(
            "anthropic package not installed. Run: pip install anthropic"
        ) from exc
    return anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env


# Model and pricing notes:
#   We use claude-sonnet-4-6 (current stable Sonnet 4.6).
#   Per-call budget caps prevent runaway costs on pathological inputs.
MODEL = "claude-sonnet-4-6"
MAX_TOKENS_OUT = 1500


# -- Defense gap categories per stage --------------------------------------

# Each stage maps to a list of gap categories. For each category we send
# Claude a focused question. Categories are derived from the professor's
# "key gap" column (image 1 of the screenshot batch).

STAGE_PROMPTS: dict[str, dict[str, str]] = {
    "data_acquisition": {
        "input_validation": (
            "Does the code validate the structure, type, or range of incoming "
            "data (e.g., schema checks, dtype assertions, value-range guards)?"
        ),
        "untrusted_source_handling": (
            "When the code fetches data from a remote source (URL, S3 bucket, "
            "HuggingFace Hub, etc.), does it verify integrity (checksums, "
            "signed URLs, pinned commits/revisions) or authenticate the source?"
        ),
    },
    "data_preparation": {
        "label_flipping_detection": (
            "Does the code check for label-flipping anomalies before training, "
            "e.g., comparing label distributions, validating label values against "
            "an expected set, or using a tool like Cleanlab for label-noise "
            "detection?"
        ),
        "data_poisoning_defenses": (
            "Does the preparation code defend against data poisoning, e.g., "
            "outlier detection on training samples, statistical anomaly checks "
            "on the dataset, or filtering of suspicious inputs?"
        ),
    },
    "modeling": {
        "model_integrity_verification": (
            "When the code loads pretrained weights or a serialized model, does "
            "it verify integrity (hash check, signature verification, pinned "
            "model revision), or load only from a controlled internal source?"
        ),
    },
    "training": {
        "label_distribution_validation": (
            "Before training begins, does the code validate the label distribution "
            "(class balance check, expected-label-set check) or detect anomalous "
            "training samples?"
        ),
        "backdoor_or_trigger_detection": (
            "Does the training loop include defenses against backdoor injection — "
            "e.g., neural-cleanse-style trigger detection, activation-pattern "
            "analysis, or anomaly detection on training gradients?"
        ),
        "differential_privacy": (
            "Does the training code use differential privacy mechanisms "
            "(Opacus, TensorFlow Privacy, DP-SGD) to protect training data?"
        ),
    },
    "evaluation": {
        "adversarial_robustness_testing": (
            "Does the evaluation include any adversarial-robustness testing — "
            "Foolbox, ART evaluation, FGSM/PGD attacks, or other robustness "
            "stress tests?"
        ),
        "metric_tampering_protection": (
            "Does the evaluation protect against metric manipulation — "
            "e.g., held-out test set isolated from training, signed/hashed "
            "evaluation data, multiple independent metrics?"
        ),
    },
    "inference": {
        "input_sanitization": (
            "Does the inference path sanitize or validate incoming requests "
            "before passing them to the model (input shape/range checks, "
            "Pydantic schema validation, rejecting malformed inputs)?"
        ),
        "output_bounds_checks": (
            "Does the inference code check the model's outputs before returning "
            "them (probability sanity bounds, NaN guards, calibrated thresholds)?"
        ),
        "prompt_injection_defenses": (
            "If the model is an LLM (text-in/text-out), does the inference code "
            "include prompt-injection defenses — input filtering, system-prompt "
            "isolation, output content moderation, or jailbreak detection?"
        ),
    },
}


SYSTEM_PROMPT = (
    "You are auditing an ML pipeline for missing defensive controls. You will be "
    "given a snippet of Python code that belongs to one stage of a six-stage "
    "MLOps pipeline (data acquisition, data preparation, modeling, training, "
    "evaluation, or inference). For each defensive control I ask about, decide "
    "whether the code implements it.\n\n"
    "Respond ONLY with valid JSON in this exact structure:\n"
    "{\n"
    '  "checks": [\n'
    '    {\n'
    '      "category": "<the category key I asked about>",\n'
    '      "present": true|false,\n'
    '      "evidence_line": <line number if present, else 0>,\n'
    '      "evidence_snippet": "<short snippet of the defense, or empty>",\n'
    '      "justification": "<one short sentence>"\n'
    '    }\n'
    '  ]\n'
    "}\n\n"
    "Do not add prose before or after the JSON. Do not fabricate defenses. "
    "If you are unsure, set present=false and explain in justification. "
    "A custom validation function (e.g., a `validate_input()` you can see in "
    "the code) counts as present even if it does not use a known library."
)


# -- Per-repo orchestration -----------------------------------------------

@dataclasses.dataclass
class LlmRepoResult:
    repo: str
    status: str               # ok | clone_failed | error
    duration_s: float
    findings: list[Finding]   # claude_judgment findings only
    stages_called: list[str]  # which stages we actually queried
    api_calls: int
    stage_to_files: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    all_reachable: list[str] = dataclasses.field(default_factory=list)
    repo_root: str = ""
    detail: str = ""


def shallow_clone(url: str, dest: str, *, timeout: int = 300,
                  token: str | None = None) -> tuple[bool, str]:
    """git clone --depth 1. Same shape as the Stage 4 orchestrator."""
    clone_url = url
    if token and url.startswith("https://github.com/"):
        clone_url = url.replace("https://", f"https://x-access-token:{token}@", 1)
    cmd = [
        "git", "-c", "core.longpaths=true", "-c", "credential.helper=",
        "clone", "--depth", "1", "--quiet", clone_url, dest,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return False, f"clone timeout {timeout}s"
    except Exception as exc:
        return False, f"clone exc: {type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        last = err[-1] if err else "unknown clone error"
        return False, f"git rc={proc.returncode}: {last[:200]}"
    return True, ""


def build_call_graph_files(repo_root: str) -> tuple[dict[str, list[str]], list[str], list[str]]:
    """Re-run Stages 1-3 and return:
        stage_to_files: dict mapping each of the six stage names to the FULL
                        list of call-graph reachable files (NOT just files
                        where Stage 3 found a specific keyword signal).
                        Same file list under every stage key — we send the
                        full pipeline code to Claude for every stage's
                        question because defenses can live anywhere in the
                        deployed code, not only in files that contained
                        keyword signals.
        all_reachable:  flat list of absolute paths in the call graph (same
                        as the value under each stage key; broken out for
                        the call-graph snapshot output).
        warnings:       human-readable problems encountered.
    """
    warnings: list[str] = []
    out: dict[str, list[str]] = {s: [] for s in STAGE_PROMPTS}
    all_reachable: list[str] = []

    try:
        from scanner.dockerfile_parser import get_entry_points
        from scanner.ast_callgraph import build_call_graph
        from scanner.stage_verifier import verify_stages
    except ImportError as exc:
        warnings.append(f"scanner import failed: {exc}")
        return out, all_reachable, warnings

    try:
        eps = get_entry_points(repo_root)
    except Exception as exc:
        warnings.append(f"get_entry_points: {exc}")
        return out, all_reachable, warnings

    if not eps:
        warnings.append("no entry points")
        return out, all_reachable, warnings

    cgs = []
    for ep in eps:
        ef = getattr(ep, "entry_file", None) or getattr(ep, "resolved_path", None)
        if not ef:
            continue
        try:
            cgs.append(build_call_graph(ef, repo_root))
        except Exception as exc:
            warnings.append(f"build_call_graph: {exc}")

    if not cgs:
        warnings.append("no call graphs")
        return out, all_reachable, warnings

    # Union of reachable files across all entry-point call graphs.
    seen: set[str] = set()
    for cg in cgs:
        modules = getattr(cg, "modules", None) or {}
        for abs_path in modules:
            if abs_path in seen:
                continue
            if os.path.isfile(abs_path):
                seen.add(abs_path)
                all_reachable.append(abs_path)

    # We also run verify_stages so the snapshot can record which stages
    # were verified as present (useful for the call_graphs/ artifact),
    # but the code slice sent to Claude is the FULL call-graph reachable
    # set, not the stage-evidence subset.
    try:
        report = verify_stages(cgs, repo_root)
    except Exception as exc:
        warnings.append(f"verify_stages: {exc}")
        report = None

    # Only ask Claude about a stage if Stage 3 actually verified it present.
    # If a stage isn't present in the pipeline, there's nothing to audit.
    present_stages = set()
    if report is not None:
        for stage_name, is_present in (getattr(report, "present", {}) or {}).items():
            if is_present:
                present_stages.add(stage_name)
    else:
        # Fallback: assume all six present if we couldn't verify
        present_stages = set(STAGE_PROMPTS.keys())

    for stage in STAGE_PROMPTS:
        if stage in present_stages:
            out[stage] = list(all_reachable)
        else:
            out[stage] = []

    return out, all_reachable, warnings


def extract_code_slice(file_paths: list[str], *, max_chars: int = 12000) -> str:
    """Read up to max_chars of code from the listed files, with file headers.

    Returns a concatenated string with `# === file: path ===` separators.
    Truncates at max_chars to keep prompt size predictable.
    """
    parts: list[str] = []
    total = 0
    for path in file_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        rel_header = f"\n# === file: {os.path.basename(path)} ===\n"
        # Trim file content if it's huge — keep first ~4K chars per file
        # so the slice always covers multiple files instead of one giant one
        per_file_cap = 4000
        snippet = content if len(content) <= per_file_cap else (
            content[:per_file_cap] + f"\n# ... (file truncated, original {len(content)} chars) ...\n"
        )
        chunk = rel_header + snippet
        if total + len(chunk) > max_chars:
            remaining = max_chars - total
            if remaining > 200:
                parts.append(chunk[:remaining] + "\n# ... (slice truncated) ...\n")
            break
        parts.append(chunk)
        total += len(chunk)
    return "".join(parts)


def query_claude_for_stage(client, stage: str, code_slice: str,
                            categories: dict[str, str]) -> tuple[list[dict], str]:
    """One Claude API call. Returns (parsed_checks, error_or_empty)."""
    # Build the user-facing prompt: code + the questions for this stage.
    questions = "\n".join(
        f'  - "{cat}": {desc}' for cat, desc in categories.items()
    )
    user_msg = (
        f"PIPELINE STAGE: {stage}\n\n"
        f"CODE SLICE (function bodies on this stage's data-flow path):\n"
        f"```python\n{code_slice}\n```\n\n"
        f"For each of these defensive control categories, decide whether the "
        f"code implements it:\n{questions}\n\n"
        f"Respond ONLY with the JSON structure described in the system prompt. "
        f"One entry in 'checks' per category I just listed."
    )

    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS_OUT,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
    except Exception as exc:
        return [], f"api: {type(exc).__name__}: {exc}"[:200]

    # Extract text from response
    text_parts: list[str] = []
    for block in (resp.content or []):
        if getattr(block, "type", None) == "text":
            text_parts.append(block.text or "")
    text = "".join(text_parts).strip()
    if not text:
        return [], "empty response"

    # Strip code fences if Claude wrapped JSON despite instructions
    if text.startswith("```"):
        lines = text.split("\n")
        # drop the first fence line
        lines = lines[1:]
        # drop trailing fence
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], f"json parse: {exc}"

    if not isinstance(parsed, dict) or "checks" not in parsed:
        return [], "missing 'checks' key"
    checks = parsed["checks"]
    if not isinstance(checks, list):
        return [], "'checks' not a list"
    return checks, ""


def checks_to_findings(stage: str, checks: list[dict],
                       evidence_paths: list[str]) -> list[Finding]:
    """Convert Claude's check responses into Finding records.

    Only ABSENT controls produce findings (we record what's missing).
    Present controls are noted in the log but not turned into findings,
    matching the methodology: findings = absent controls.
    """
    # Use first evidence file path as a representative location for the stage.
    # This isn't precise but the snippet field carries the real evidence.
    rep_path = ""
    if evidence_paths:
        rep_path = os.path.basename(evidence_paths[0])

    findings: list[Finding] = []
    for c in checks:
        if not isinstance(c, dict):
            continue
        if c.get("present", False):
            continue  # present defenses don't generate findings
        category = str(c.get("category") or "unknown")
        justification = str(c.get("justification") or "").strip()[:300]
        # Severity for absent ML-defense controls: medium by default,
        # unless the category is one of the gaps the professor specifically
        # called out as high-impact (backdoor, prompt injection).
        high_impact = {
            "backdoor_or_trigger_detection",
            "prompt_injection_defenses",
            "data_poisoning_defenses",
        }
        severity = "high" if category in high_impact else "medium"
        findings.append(Finding(
            tool="claude_judgment",
            severity=severity,
            rule_id=f"absent_control.{category}",
            file_path=rep_path,
            line=0,
            message=f"No detected {category.replace('_', ' ')}: {justification}",
            snippet="",
            stage=stage,
        ))
    return findings


def repo_url_to_filename(url: str) -> str:
    parts = url.rstrip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}__{parts[-1]}.json"
    return url.replace("/", "__").replace(":", "_") + ".json"


def write_llm_findings_file(findings_dir: str, repo_url: str,
                             new_findings: list[Finding]) -> None:
    """Write claude_judgment findings to a fresh per-repo JSON file.

    Does NOT touch stage4_findings/. Overwrites llm_findings/{file}.json
    cleanly on each scan of that repo (idempotent reruns).
    """
    os.makedirs(findings_dir, exist_ok=True)
    path = os.path.join(findings_dir, repo_url_to_filename(repo_url))
    payload = [f.as_dict() for f in new_findings]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def write_call_graph_snapshot(snapshot_dir: str, repo_url: str, repo_root: str,
                               stage_to_files: dict[str, list[str]],
                               all_reachable: list[str]) -> None:
    """Persist the import-reachability snapshot for this repo as a JSON artifact.

    Stored separately from findings so downstream scripts can reuse it
    without re-cloning. File paths are stored relative to repo_root.

    NOTE on `rq2_context_files`: for RQ2 the same FULL reachable file list is
    recorded under every present stage, because the LLM audit reads all
    reachable code for each stage's question. It is *not* a per-file stage
    attribution (RQ1 uses StageReport.evidence_files for that). The released
    snapshots were relabelled to this schema by tools/relabel_snapshots.py.
    """
    os.makedirs(snapshot_dir, exist_ok=True)
    path = os.path.join(snapshot_dir, repo_url_to_filename(repo_url))

    def to_rel(abs_path: str) -> str:
        try:
            return os.path.relpath(abs_path, repo_root).replace(os.sep, "/")
        except ValueError:
            return abs_path.replace(os.sep, "/")

    payload = {
        "repo": repo_url,
        "analysis": ("Static import-reachability from the entry point; nodes are "
                     "files, edges are imports; not a function-level call graph."),
        "reachable_files": [to_rel(p) for p in all_reachable],
        "rq2_context_files": {
            stage: [to_rel(p) for p in files]
            for stage, files in stage_to_files.items()
            if files
        },
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def scan_one_repo(url: str, client, *, token: str | None = None,
                  snapshot_dir: str | None = None) -> LlmRepoResult:
    """Clone, query Claude per present stage, return findings.

    If snapshot_dir is provided, also writes the call-graph snapshot for
    this repo before the temp clone is cleaned up (since we need repo_root
    to compute relative paths).
    """
    t0 = time.monotonic()
    tmp = tempfile.mkdtemp(prefix="llm_scan_")
    repo_dir = os.path.join(tmp, "repo")
    api_calls = 0
    stages_called: list[str] = []

    try:
        ok, err = shallow_clone(url, repo_dir, token=token)
        if not ok:
            return LlmRepoResult(repo=url, status="clone_failed",
                                 duration_s=time.monotonic() - t0,
                                 findings=[], stages_called=[], api_calls=0,
                                 detail=err)

        stage_to_files, all_reachable, warnings = build_call_graph_files(repo_dir)

        # Write the call-graph snapshot BEFORE the temp clone is deleted,
        # so the relative paths are computed against the live repo_dir.
        if snapshot_dir is not None:
            try:
                write_call_graph_snapshot(snapshot_dir, url, repo_dir,
                                           stage_to_files, all_reachable)
            except Exception as exc:
                warnings.append(f"snapshot write failed: {exc}")

        all_findings: list[Finding] = []
        for stage, prompts in STAGE_PROMPTS.items():
            files = stage_to_files.get(stage, [])
            if not files:
                continue  # stage not present in this repo; skip
            code_slice = extract_code_slice(files)
            if not code_slice.strip():
                continue
            checks, api_err = query_claude_for_stage(
                client, stage, code_slice, prompts,
            )
            api_calls += 1
            stages_called.append(stage)
            if api_err:
                # Don't kill the whole repo on one stage's API error
                continue
            all_findings.extend(checks_to_findings(stage, checks, files))

        return LlmRepoResult(
            repo=url, status="ok",
            duration_s=time.monotonic() - t0,
            findings=all_findings,
            stages_called=stages_called,
            api_calls=api_calls,
            stage_to_files=stage_to_files,
            all_reachable=all_reachable,
            repo_root=repo_dir,
            detail="; ".join(warnings[:2]),
        )
    except Exception as exc:
        return LlmRepoResult(repo=url, status="error",
                             duration_s=time.monotonic() - t0,
                             findings=[], stages_called=stages_called,
                             api_calls=api_calls,
                             detail=f"{type(exc).__name__}: {exc}\n"
                                    f"{traceback.format_exc()[:400]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# -- Logging and resume ---------------------------------------------------

LOG_COLUMNS = [
    "repo", "status", "duration_s", "api_calls", "stages_called",
    "findings", "high_findings", "medium_findings", "detail",
]


def already_done(log_path: str) -> set[str]:
    done: set[str] = set()
    if not os.path.isfile(log_path):
        return done
    try:
        with open(log_path, "r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                if row.get("repo"):
                    done.add(row["repo"].strip())
    except Exception:
        pass
    return done


def write_log_row(log_path: str, result: LlmRepoResult) -> None:
    new_file = not os.path.isfile(log_path)
    sev = Counter(f.severity for f in result.findings)
    with open(log_path, "a", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=LOG_COLUMNS)
        if new_file:
            w.writeheader()
        w.writerow({
            "repo": result.repo,
            "status": result.status,
            "duration_s": f"{result.duration_s:.1f}",
            "api_calls": result.api_calls,
            "stages_called": ";".join(result.stages_called),
            "findings": len(result.findings),
            "high_findings": sev.get("high", 0),
            "medium_findings": sev.get("medium", 0),
            "detail": (result.detail or "")[:300],
        })


# -- Main -----------------------------------------------------------------

def run(verified_csv: str, log_path: str, findings_dir: str,
        snapshot_dir: str, token: str | None = None) -> None:
    client = _get_client()

    with open(verified_csv, "r", encoding="utf-8", newline="") as fh:
        repos = [r["repo"].strip() for r in csv.DictReader(fh) if r.get("repo")]

    done = already_done(log_path)
    todo = [u for u in repos if u not in done]
    print(f"LLM scan: {len(repos)} repos total, {len(done)} done, "
          f"{len(todo)} to scan.", flush=True)

    for i, url in enumerate(todo, start=1):
        owner_repo = "/".join(url.rstrip("/").split("/")[-2:])
        result = scan_one_repo(url, client, token=token,
                                snapshot_dir=snapshot_dir)
        write_log_row(log_path, result)
        if result.status == "ok":
            write_llm_findings_file(findings_dir, url, result.findings)

        marker = {"ok": "[ok ]", "clone_failed": "[clf]",
                  "error": "[err]"}.get(result.status, "[?  ]")
        print(f"  [{i:4d}/{len(todo)}] {marker} {owner_repo[:55]:55s} "
              f"findings={len(result.findings):3d}  "
              f"calls={result.api_calls}  "
              f"t={result.duration_s:6.1f}s", flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("verified_csv", help="Path to verified_corpus.csv")
    ap.add_argument("--log", default="llm_scan_log.csv",
                    help="Per-repo log (used for resume)")
    ap.add_argument("--findings-dir", default="llm_findings",
                    help="Per-repo LLM findings JSON output directory")
    ap.add_argument("--snapshot-dir", default="call_graphs",
                    help="Per-repo call-graph snapshot output directory")
    args = ap.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY environment variable required.",
              file=sys.stderr)
        return 1

    token = os.environ.get("GITHUB_TOKEN") or None
    if token:
        print("Using GITHUB_TOKEN for authenticated clones.", flush=True)
    else:
        print("No GITHUB_TOKEN set; clones unauthenticated.", flush=True)

    run(args.verified_csv, args.log, args.findings_dir,
        args.snapshot_dir, token=token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
