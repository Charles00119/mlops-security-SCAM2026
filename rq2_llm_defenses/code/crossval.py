"""Cross-validation phase: re-score a stratified sample of Claude's findings
with GPT (OpenAI) and compute inter-LLM agreement (Cohen's kappa).

For each verified repo we have:
  - llm_findings/{owner}__{repo}.json  -- Claude's per-finding judgments
  - call_graphs/{owner}__{repo}.json   -- the code-file list Claude saw

This script:
  1. Loads all Claude findings across all repos.
  2. Bucket findings by (category, severity) and stratified-sample n_per_cell
     from each bucket. Categories with fewer findings than n_per_cell are
     taken in full (no replacement).
  3. For each sampled finding, shallow-clone the repo (or skip if already
     cached), re-read the call-graph files, send the same prompt to GPT
     asking about ONLY that specific category, get back present=true/false.
  4. For each finding, record Claude's judgment (always present=false since
     we only saved absent controls) vs GPT's judgment.
  5. Compute Cohen's kappa, accuracy, and per-category breakdown.

Outputs:
    crossval_sample.csv          -- the stratified sample (repo, finding,
                                    Claude's verdict, GPT's verdict, agreement)
    crossval_summary.csv         -- per-category and overall kappa/accuracy
    crossval_log.csv             -- per-finding run log

Usage:
    python -m stage4.crossval verified_corpus.csv

Requires:
    OPENAI_API_KEY environment variable
    GITHUB_TOKEN (optional, recommended for clones)
    pip install openai
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import shutil
import traceback
from collections import Counter, defaultdict
from typing import Any

# Make scanner/stage4 importable when run from project root
PROJ = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
if PROJ not in sys.path:
    sys.path.insert(0, PROJ)


# ---- OpenAI client -----------------------------------------------------

def _get_openai_client():
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError(
            "openai package not installed. Run: pip install openai"
        ) from exc
    return OpenAI()  # reads OPENAI_API_KEY from env


# GPT-4o is the default cross-validator. Strong code understanding, mid-cost.
# Switch to "gpt-4.1" for higher capability, "gpt-4o-mini" for cheaper.
GPT_MODEL = "gpt-4o"
MAX_TOKENS_OUT = 600


# ---- Defense categories (must match llm_scan.py) ---------------------

CATEGORY_PROMPTS: dict[str, str] = {
    "input_validation": (
        "Does the code validate the structure, type, or range of incoming "
        "data (e.g., schema checks, dtype assertions, value-range guards)?"
    ),
    "untrusted_source_handling": (
        "When the code fetches data from a remote source (URL, S3 bucket, "
        "HuggingFace Hub, etc.), does it verify integrity (checksums, "
        "signed URLs, pinned commits/revisions) or authenticate the source?"
    ),
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
    "model_integrity_verification": (
        "When the code loads pretrained weights or a serialized model, does "
        "it verify integrity (hash check, signature verification, pinned "
        "model revision), or load only from a controlled internal source?"
    ),
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
}


SYSTEM_PROMPT = (
    "You are auditing an ML pipeline for missing defensive controls. You will "
    "be given Python code from a specific stage of an MLOps pipeline and asked "
    "whether ONE specific defensive control is implemented in the code.\n\n"
    "Respond ONLY with valid JSON in this exact structure:\n"
    "{\n"
    '  "present": true|false,\n'
    '  "justification": "<one short sentence>"\n'
    "}\n\n"
    "Do not add prose before or after the JSON. Do not fabricate defenses. "
    "If you are unsure, set present=false and explain in justification. "
    "A custom validation function counts as present even if it does not use "
    "a known library."
)


# ---- Stratified sampling ------------------------------------------------

def load_all_claude_findings(llm_findings_dir: str) -> list[dict]:
    """Walk llm_findings/*.json and flatten every finding, adding repo info."""
    out: list[dict] = []
    if not os.path.isdir(llm_findings_dir):
        return out
    for fn in sorted(os.listdir(llm_findings_dir)):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(llm_findings_dir, fn)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        # Reconstruct the repo URL from the filename: "owner__name.json"
        stem = fn[:-len(".json")]
        if "__" in stem:
            owner, name = stem.split("__", 1)
            repo_url = f"https://github.com/{owner}/{name}"
        else:
            repo_url = stem
        for f in data or []:
            if not isinstance(f, dict):
                continue
            f["_repo_url"] = repo_url
            f["_findings_file"] = fn
            out.append(f)
    return out


def category_from_rule_id(rule_id: str) -> str:
    """absent_control.<category> -> <category>"""
    if rule_id.startswith("absent_control."):
        return rule_id[len("absent_control."):]
    return rule_id


def stratified_sample(findings: list[dict], total_n: int,
                       seed: int = 42) -> list[dict]:
    """Sample stratified by (category, severity)."""
    rng = random.Random(seed)
    buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in findings:
        cat = category_from_rule_id(str(f.get("rule_id") or ""))
        sev = str(f.get("severity") or "unknown")
        buckets[(cat, sev)].append(f)

    n_buckets = len(buckets)
    if n_buckets == 0:
        return []
    per_bucket = max(1, total_n // n_buckets)

    sample: list[dict] = []
    for key, items in sorted(buckets.items()):
        if len(items) <= per_bucket:
            sample.extend(items)
        else:
            sample.extend(rng.sample(items, per_bucket))
    return sample


# ---- Code slice reconstruction ------------------------------------------

def shallow_clone(url: str, dest: str, *, timeout: int = 180,
                  token: str | None = None) -> tuple[bool, str]:
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


def extract_code_slice(repo_root: str, rel_files: list[str],
                        max_chars: int = 12000) -> str:
    """Concatenate up to max_chars of code from listed files (per-file cap)."""
    parts: list[str] = []
    total = 0
    per_file_cap = 4000
    for rel in rel_files:
        path = os.path.join(repo_root, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        snippet = content if len(content) <= per_file_cap else (
            content[:per_file_cap] +
            f"\n# ... (file truncated, original {len(content)} chars) ...\n"
        )
        chunk = f"\n# === file: {os.path.basename(path)} ===\n" + snippet
        if total + len(chunk) > max_chars:
            remaining = max_chars - total
            if remaining > 200:
                parts.append(chunk[:remaining] + "\n# ... (slice truncated) ...\n")
            break
        parts.append(chunk)
        total += len(chunk)
    return "".join(parts)


def load_call_graph_files(call_graphs_dir: str, repo_url: str,
                           stage: str) -> list[str]:
    """Get the RQ2 context file list for a stage from import_graphs/{repo}.json.

    Accepts both the current key (`rq2_context_files`) and the legacy one
    (`stages_with_files`)."""
    fn = repo_url_to_filename(repo_url)
    path = os.path.join(call_graphs_dir, fn)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    ctx = data.get("rq2_context_files") or data.get("stages_with_files") or {}
    return list(ctx.get(stage) or [])


def repo_url_to_filename(url: str) -> str:
    parts = url.rstrip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}__{parts[-1]}.json"
    return url.replace("/", "__").replace(":", "_") + ".json"


# ---- GPT query ----------------------------------------------------------

def query_gpt(client, stage: str, category: str, code_slice: str
              ) -> tuple[bool | None, str, str]:
    """Ask GPT whether one category is present. Returns (present, justification, error)."""
    cat_desc = CATEGORY_PROMPTS.get(category, f"defense category '{category}'")
    user_msg = (
        f"PIPELINE STAGE: {stage}\n\n"
        f"CODE SLICE (function bodies on this stage's data-flow path):\n"
        f"```python\n{code_slice}\n```\n\n"
        f"DEFENSE CATEGORY TO JUDGE: \"{category}\"\n"
        f"QUESTION: {cat_desc}\n\n"
        f"Respond ONLY with the JSON structure described in the system prompt."
    )
    try:
        resp = client.chat.completions.create(
            model=GPT_MODEL,
            max_tokens=MAX_TOKENS_OUT,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0,
        )
    except Exception as exc:
        return None, "", f"api: {type(exc).__name__}: {exc}"[:200]

    try:
        text = (resp.choices[0].message.content or "").strip()
    except (AttributeError, IndexError):
        return None, "", "empty response"

    # Strip code fences if present
    if text.startswith("```"):
        lines = text.split("\n")[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, "", f"json parse: {exc}"

    if not isinstance(parsed, dict) or "present" not in parsed:
        return None, "", "missing 'present' key"

    present = bool(parsed.get("present"))
    justification = str(parsed.get("justification") or "").strip()[:300]
    return present, justification, ""


# ---- Cohen's kappa ------------------------------------------------------

def cohens_kappa(pairs: list[tuple[bool, bool]]) -> float:
    """Cohen's kappa for binary judgments. Returns kappa in [-1, 1]."""
    n = len(pairs)
    if n == 0:
        return float("nan")
    agree = sum(1 for a, b in pairs if a == b)
    p_o = agree / n
    a_pos = sum(1 for a, _ in pairs if a) / n
    b_pos = sum(1 for _, b in pairs if b) / n
    p_e = a_pos * b_pos + (1 - a_pos) * (1 - b_pos)
    if p_e == 1.0:
        return 1.0 if p_o == 1.0 else 0.0
    return (p_o - p_e) / (1 - p_e)


# ---- Main orchestration -------------------------------------------------

def already_done_log(log_path: str) -> set[str]:
    done: set[str] = set()
    if not os.path.isfile(log_path):
        return done
    try:
        with open(log_path, "r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                key = row.get("finding_key")
                if key:
                    done.add(key)
    except Exception:
        pass
    return done


def finding_key(f: dict) -> str:
    """Stable identifier for a finding (for resume)."""
    return f"{f.get('_repo_url')}|{f.get('stage')}|{f.get('rule_id')}"


LOG_COLUMNS = [
    "finding_key", "repo", "stage", "category", "severity",
    "claude_present", "gpt_present", "agreement",
    "gpt_justification", "error",
]


def write_log_row(log_path: str, row: dict) -> None:
    new_file = not os.path.isfile(log_path)
    with open(log_path, "a", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=LOG_COLUMNS)
        if new_file:
            w.writeheader()
        w.writerow(row)


def run(llm_findings_dir: str, call_graphs_dir: str, log_path: str,
        summary_path: str, sample_path: str, total_n: int,
        token: str | None = None, seed: int = 42) -> None:
    client = _get_openai_client()

    print(f"Loading Claude findings from {llm_findings_dir}/ ...", flush=True)
    findings = load_all_claude_findings(llm_findings_dir)
    print(f"  loaded {len(findings)} total findings across "
          f"{len({f.get('_repo_url') for f in findings})} repos", flush=True)

    sample = stratified_sample(findings, total_n, seed=seed)
    print(f"Stratified sample: {len(sample)} findings selected "
          f"(target ~{total_n})", flush=True)

    # Write the sample manifest before scanning, so we have a record even if
    # the GPT pass crashes partway through.
    with open(sample_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["finding_key", "repo", "stage", "category", "severity",
                    "claude_message"])
        for f in sample:
            w.writerow([finding_key(f), f.get("_repo_url"), f.get("stage"),
                        category_from_rule_id(str(f.get("rule_id") or "")),
                        f.get("severity"),
                        (f.get("message") or "")[:200]])

    done = already_done_log(log_path)
    todo = [f for f in sample if finding_key(f) not in done]
    print(f"{len(done)} already validated, {len(todo)} to validate.", flush=True)

    # Group todo findings by repo to clone each repo only once.
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for f in todo:
        by_repo[f["_repo_url"]].append(f)

    total_repos = len(by_repo)
    findings_processed = 0
    pairs: list[tuple[bool, bool]] = []
    per_cat_pairs: dict[str, list[tuple[bool, bool]]] = defaultdict(list)

    for repo_idx, (repo_url, repo_findings) in enumerate(by_repo.items(), 1):
        owner_repo = "/".join(repo_url.rstrip("/").split("/")[-2:])
        tmp = tempfile.mkdtemp(prefix="crossval_")
        repo_dir = os.path.join(tmp, "repo")
        try:
            ok, err = shallow_clone(repo_url, repo_dir, token=token)
            if not ok:
                for f in repo_findings:
                    write_log_row(log_path, {
                        "finding_key": finding_key(f),
                        "repo": repo_url, "stage": f.get("stage"),
                        "category": category_from_rule_id(str(f.get("rule_id") or "")),
                        "severity": f.get("severity"),
                        "claude_present": False, "gpt_present": "",
                        "agreement": "", "gpt_justification": "",
                        "error": f"clone_failed: {err[:100]}",
                    })
                    findings_processed += 1
                print(f"  [{repo_idx}/{total_repos}] [clf] {owner_repo[:50]:50s}"
                      f"  clone failed: {err[:60]}", flush=True)
                continue

            for f in repo_findings:
                t0 = time.monotonic()
                stage = str(f.get("stage") or "")
                category = category_from_rule_id(str(f.get("rule_id") or ""))
                rel_files = load_call_graph_files(call_graphs_dir, repo_url, stage)
                code_slice = extract_code_slice(repo_dir, rel_files)
                if not code_slice.strip():
                    write_log_row(log_path, {
                        "finding_key": finding_key(f),
                        "repo": repo_url, "stage": stage,
                        "category": category, "severity": f.get("severity"),
                        "claude_present": False, "gpt_present": "",
                        "agreement": "", "gpt_justification": "",
                        "error": "no code slice (files missing)",
                    })
                    findings_processed += 1
                    continue

                present, justif, err = query_gpt(client, stage, category, code_slice)
                # Claude only saved absent controls, so Claude's verdict is always False.
                claude_present = False
                if err or present is None:
                    write_log_row(log_path, {
                        "finding_key": finding_key(f), "repo": repo_url,
                        "stage": stage, "category": category,
                        "severity": f.get("severity"),
                        "claude_present": claude_present, "gpt_present": "",
                        "agreement": "", "gpt_justification": justif,
                        "error": err,
                    })
                    findings_processed += 1
                    continue

                agreement = "agree" if present == claude_present else "disagree"
                pairs.append((claude_present, present))
                per_cat_pairs[category].append((claude_present, present))
                write_log_row(log_path, {
                    "finding_key": finding_key(f), "repo": repo_url,
                    "stage": stage, "category": category,
                    "severity": f.get("severity"),
                    "claude_present": claude_present, "gpt_present": present,
                    "agreement": agreement, "gpt_justification": justif,
                    "error": "",
                })
                findings_processed += 1
                dt = time.monotonic() - t0
                marker = "=" if present == claude_present else "≠"
                print(f"  [{repo_idx}/{total_repos}] {owner_repo[:35]:35s} "
                      f"{category[:30]:30s} claude=absent gpt={'present' if present else 'absent':7s} "
                      f"{marker}  t={dt:4.1f}s", flush=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # Final stats
    overall_k = cohens_kappa(pairs)
    accuracy = (sum(1 for a, b in pairs if a == b) / len(pairs)) if pairs else float("nan")

    with open(summary_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scope", "n", "agreement_pct", "cohens_kappa"])
        w.writerow(["overall", len(pairs),
                    f"{accuracy*100:.1f}" if pairs else "",
                    f"{overall_k:.3f}" if pairs else ""])
        for cat in sorted(per_cat_pairs):
            ps = per_cat_pairs[cat]
            cat_k = cohens_kappa(ps)
            cat_acc = sum(1 for a, b in ps if a == b) / len(ps)
            w.writerow([cat, len(ps), f"{cat_acc*100:.1f}", f"{cat_k:.3f}"])

    print()
    print(f"Validated {len(pairs)} findings successfully.", flush=True)
    print(f"Overall agreement: {accuracy*100:.1f}% (n={len(pairs)})", flush=True)
    print(f"Cohen's kappa: {overall_k:.3f}", flush=True)
    print(f"\nPer-category breakdown in {summary_path}", flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("verified_csv",
                    help="Path to verified_corpus.csv (used for repo URL list)")
    ap.add_argument("--llm-findings-dir", default="llm_findings")
    ap.add_argument("--call-graphs-dir", default="00_corpus/data/import_graphs")
    ap.add_argument("--log", default="crossval_log.csv")
    ap.add_argument("--summary", default="crossval_summary.csv")
    ap.add_argument("--sample", default="crossval_sample.csv")
    ap.add_argument("--n", type=int, default=150,
                    help="Target sample size (will be distributed across "
                         "(category, severity) cells)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY environment variable required.",
              file=sys.stderr)
        return 1

    token = os.environ.get("GITHUB_TOKEN") or None
    if token:
        print("Using GITHUB_TOKEN for authenticated clones.", flush=True)
    else:
        print("No GITHUB_TOKEN set; clones unauthenticated.", flush=True)

    run(args.llm_findings_dir, args.call_graphs_dir, args.log,
        args.summary, args.sample, args.n, token=token, seed=args.seed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
