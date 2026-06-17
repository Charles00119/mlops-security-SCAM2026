"""
Stage 1 — Dockerfile entry-point parser.

Goal: replace filename-guessing with a verified entry point. The Dockerfile's
ENTRYPOINT / CMD tells us the literal command the container runs; resolving it
gives a real starting file for the AST walk in Stage 2.

Standalone: no third-party dependencies, no network. Point it at a local repo
checkout (the directory you cloned the repo into).

Fallback rule (Stage 1 open item): when the Dockerfile does not cleanly name a
Python file, we fall back through a candidate list. The exact ordering should be
confirmed against the six-repo manual look.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EntryPoint:
    """A resolved (or attempted) entry point for one Dockerfile."""
    dockerfile_path: str               # path to the Dockerfile this came from
    raw_instruction: str               # the literal CMD/ENTRYPOINT text
    kind: str                          # 'python_file' | 'python_module' | 'shell_script' | 'unresolved'
    entry_file: Optional[str] = None   # resolved path to a .py file, if any
    module_name: Optional[str] = None  # dotted module name, if 'python_module'
    workdir: str = "/"                 # WORKDIR in effect when CMD/ENTRYPOINT ran
    notes: list[str] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return self.kind in ("python_file", "python_module") and (
            self.entry_file is not None or self.module_name is not None
        )


# ---------------------------------------------------------------------------
# Dockerfile discovery
# ---------------------------------------------------------------------------

def _is_dockerfile_name(filename: str) -> bool:
    """True if a filename is a Dockerfile, in any common naming variant.

    Case-insensitive. Catches:
      Dockerfile / dockerfile          (exact)
      Dockerfile.cpu / Dockerfile.gpu  (suffix variants)
      cpu.Dockerfile / torch-light.dockerfile  (extension-style, e.g. transformers)
    Excludes Dockerfile.dockerignore-type companions.
    """
    low = filename.lower()
    if low in ("dockerfile",):
        return True
    if low.startswith("dockerfile."):
        # e.g. dockerfile.cpu — but not dockerfile.md / dockerfile.txt docs
        return not low.endswith((".md", ".txt", ".rst"))
    if low.endswith(".dockerfile"):
        return True
    return False


def find_dockerfiles(repo_root: str) -> list[str]:
    """Return all Dockerfile paths in a repo, found by a full recursive walk.

    A repo may keep Dockerfiles at any depth — e.g. transformers has eleven of
    them under docker/<variant>/Dockerfile. We walk the whole tree (skipping
    vendored dirs) and match names case-insensitively.
    """
    found: list[str] = []
    skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__",
                 "site-packages", ".tox", "dist", "build"}

    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if _is_dockerfile_name(fn):
                found.append(os.path.join(dirpath, fn))

    # Priority order: shallower paths first (root Dockerfile before docker/x/Dockerfile),
    # and a bare "Dockerfile" before a variant at the same depth.
    def _rank(p: str) -> tuple[int, int, str]:
        rel = os.path.relpath(p, repo_root)
        depth = rel.count(os.sep)
        is_bare = 0 if os.path.basename(p).lower() == "dockerfile" else 1
        return (depth, is_bare, rel.lower())

    found.sort(key=_rank)
    return found


# ---------------------------------------------------------------------------
# Dockerfile instruction parsing
# ---------------------------------------------------------------------------

# A Dockerfile instruction can be continued across lines with a trailing backslash.
def _logical_lines(text: str) -> list[str]:
    """Join backslash-continued lines into single logical instructions."""
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        stripped = raw.rstrip()
        # Strip full-line comments only (a '#' mid-instruction is rare and risky to strip).
        if stripped.lstrip().startswith("#"):
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
        else:
            buffer += stripped
            if buffer.strip():
                lines.append(buffer.strip())
            buffer = ""
    if buffer.strip():
        lines.append(buffer.strip())
    return lines


def _parse_exec_or_shell(arg: str) -> list[str]:
    """Parse the argument of CMD/ENTRYPOINT into a token list.

    Two Dockerfile forms:
      exec form  : CMD ["python", "src/run.py"]   -> JSON array
      shell form : CMD python src/run.py          -> shell-split
    """
    arg = arg.strip()
    if arg.startswith("["):
        # exec form — a JSON-ish array. Tolerate single quotes.
        inner = arg.strip()[1:-1] if arg.endswith("]") else arg.strip()[1:]
        tokens = re.findall(r'["\']([^"\']*)["\']', inner)
        return tokens
    # shell form
    try:
        return shlex.split(arg)
    except ValueError:
        return arg.split()


def parse_dockerfile(dockerfile_path: str) -> dict:
    """Extract the instructions we care about from one Dockerfile.

    Returns a dict with: workdir, entrypoint tokens, cmd tokens.
    ENTRYPOINT and CMD interact — if both exist, CMD provides default args to
    ENTRYPOINT. We capture both and let resolve_entry_point() combine them.
    """
    with open(dockerfile_path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    result = {"workdir": "/", "entrypoint": None, "cmd": None,
              "entrypoint_raw": "", "cmd_raw": ""}

    for line in _logical_lines(text):
        m = re.match(r"^(\w+)\s+(.*)$", line)
        if not m:
            continue
        instr, arg = m.group(1).upper(), m.group(2)

        if instr == "WORKDIR":
            # Last WORKDIR wins; may be relative to a previous one.
            w = arg.strip().strip('"').strip("'")
            result["workdir"] = w if w.startswith("/") else os.path.join(result["workdir"], w)
        elif instr == "ENTRYPOINT":
            result["entrypoint"] = _parse_exec_or_shell(arg)
            result["entrypoint_raw"] = arg
        elif instr == "CMD":
            result["cmd"] = _parse_exec_or_shell(arg)
            result["cmd_raw"] = arg

    return result


# ---------------------------------------------------------------------------
# Entry-point resolution
# ---------------------------------------------------------------------------

_PY_INTERPRETERS = {"python", "python3", "python2", "py"}


def _tokens_to_entry(tokens: list[str], repo_root: str, workdir: str) -> tuple[str, Optional[str], Optional[str]]:
    """Inspect a command token list and classify it.

    Returns (kind, entry_file, module_name).
    """
    if not tokens:
        return "unresolved", None, None

    # Drop a leading absolute-path interpreter like /usr/bin/python3.
    head = os.path.basename(tokens[0])

    if head in _PY_INTERPRETERS:
        rest = tokens[1:]
        # python -m package.module
        if rest and rest[0] == "-m" and len(rest) > 1:
            return "python_module", None, rest[1]
        # python path/to/script.py  (skip flags like -u, -O)
        for tok in rest:
            if tok.startswith("-"):
                continue
            if tok.endswith(".py"):
                cand = _locate(tok, repo_root, workdir)
                return "python_file", cand, None
            # first non-flag, non-.py token: could be a script w/o extension
            break
        return "unresolved", None, None

    # Shell script entry: ./start.sh, bash run.sh, sh entrypoint.sh
    if head in {"bash", "sh"} and len(tokens) > 1:
        return "shell_script", _locate(tokens[1], repo_root, workdir), None
    if head.endswith(".sh"):
        return "shell_script", _locate(tokens[0], repo_root, workdir), None

    # A bare script path with .py
    if head.endswith(".py"):
        return "python_file", _locate(tokens[0], repo_root, workdir), None

    return "unresolved", None, None


def _locate(path_token: str, repo_root: str, workdir: str) -> Optional[str]:
    """Resolve a path token (possibly relative to WORKDIR) to a real file on disk.

    The Dockerfile's WORKDIR is a *container* path, not a host path, so we can't
    use it directly. We treat the repo root as the container working tree and
    try a few plausible joins.
    """
    token = path_token.lstrip("./")
    candidates = [
        os.path.join(repo_root, token),
        os.path.join(repo_root, os.path.basename(token)),
    ]
    # WORKDIR-relative: strip the workdir prefix and rejoin under repo_root.
    wd = workdir.strip("/")
    if wd:
        candidates.append(os.path.join(repo_root, token))
        # if token already includes the workdir segment, try without it
        if token.startswith(wd + "/"):
            candidates.append(os.path.join(repo_root, token[len(wd) + 1:]))
    for c in candidates:
        if os.path.isfile(c):
            return os.path.normpath(c)
    return None


def resolve_module(module_name: str, repo_root: str) -> Optional[str]:
    """Resolve a dotted module name (`python -m pkg.mod`) to a file on disk.

    `python -m pkg.mod` runs pkg/mod.py — or pkg/mod/__main__.py if mod is a
    package. Tries both, and also the common case where the first path segment
    is the top-level package name and is *not* a directory under repo_root.
    """
    parts = module_name.split(".")
    bases = [os.path.join(repo_root, *parts)]
    if len(parts) > 1:
        bases.append(os.path.join(repo_root, *parts[1:]))  # drop top-level pkg name
    for base in bases:
        for cand in (base + ".py", os.path.join(base, "__main__.py")):
            if os.path.isfile(cand):
                return os.path.normpath(cand)
    return None


# A python invocation inside a shell script: `python foo.py`, `python -m pkg`,
# possibly prefixed (exec, &&) and with flags. We grab the script + any -m module.
_SH_PYTHON = re.compile(
    r"\bpython[0-9.]*\s+(?:-[A-Za-z]+\s+)*"      # python / python3, optional flags
    r"(?:(-m)\s+([\w.]+)|([^\s;&|]+\.py))"        # either -m module  OR  a .py path
)


def resolve_shell_entry(script_path: str, repo_root: str) -> tuple[Optional[str], Optional[str]]:
    """Read a shell-script entry point and recover the python file/module it runs.

    Returns (entry_file, module_name) — at most one is set. Best-effort: scans
    the script text for the first `python ...` invocation.
    """
    if not script_path or not os.path.isfile(script_path):
        return None, None
    try:
        with open(script_path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None, None
    m = _SH_PYTHON.search(text)
    if not m:
        return None, None
    if m.group(1) == "-m" and m.group(2):
        return None, m.group(2)
    if m.group(3):
        token = m.group(3).lstrip("./")
        for cand in (os.path.join(repo_root, token),
                     os.path.join(repo_root, os.path.basename(token))):
            if os.path.isfile(cand):
                return os.path.normpath(cand), None
    return None, None


# Fallback candidates when the Dockerfile yields no usable Python entry point.
# ORDER IS PROVISIONAL — confirm against the six-repo manual look.
_FALLBACK_FILES = ["main.py", "run.py", "app.py", "train.py", "__main__.py"]


def _fallback_entry(repo_root: str) -> Optional[EntryPoint]:
    """Best-effort entry point when the Dockerfile doesn't give us one."""
    for rel in _FALLBACK_FILES:
        p = os.path.join(repo_root, rel)
        if os.path.isfile(p):
            return EntryPoint(
                dockerfile_path="(fallback)",
                raw_instruction=f"(no usable CMD/ENTRYPOINT — fell back to {rel})",
                kind="python_file",
                entry_file=os.path.normpath(p),
                notes=["resolved via fallback, not the Dockerfile"],
            )
    # setup.py console_scripts is another fallback worth adding once confirmed.
    return None


def resolve_entry_point(dockerfile_path: str, repo_root: str) -> EntryPoint:
    """Turn one Dockerfile into a single best EntryPoint.

    CMD/ENTRYPOINT interaction: if ENTRYPOINT is set, it is the command and CMD
    is its default arguments. If only CMD is set, CMD is the command.
    """
    parsed = parse_dockerfile(dockerfile_path)
    workdir = parsed["workdir"]

    # Build the effective command token list.
    if parsed["entrypoint"]:
        tokens = list(parsed["entrypoint"])
        if parsed["cmd"]:
            tokens += list(parsed["cmd"])  # CMD supplies default args
        raw = parsed["entrypoint_raw"] + (
            f"  (+CMD: {parsed['cmd_raw']})" if parsed["cmd"] else ""
        )
    elif parsed["cmd"]:
        tokens = list(parsed["cmd"])
        raw = parsed["cmd_raw"]
    else:
        ep = EntryPoint(dockerfile_path, "(no CMD or ENTRYPOINT)", "unresolved", workdir=workdir)
        ep.notes.append("Dockerfile has neither CMD nor ENTRYPOINT")
        return ep

    kind, entry_file, module = _tokens_to_entry(tokens, repo_root, workdir)
    ep = EntryPoint(
        dockerfile_path=dockerfile_path,
        raw_instruction=raw,
        kind=kind,
        entry_file=entry_file,
        module_name=module,
        workdir=workdir,
    )

    # Resolve a `python -m module` entry to a real file.
    if kind == "python_module" and module:
        resolved_file = resolve_module(module, repo_root)
        if resolved_file:
            ep.entry_file = resolved_file
            ep.notes.append(f"module {module} resolved to {os.path.relpath(resolved_file, repo_root)}")
        else:
            ep.notes.append(f"module {module} could not be resolved to a file in-repo")

    # Resolve a shell-script entry by reading the script for its python call.
    if kind == "shell_script" and entry_file:
        sh_file, sh_module = resolve_shell_entry(entry_file, repo_root)
        if sh_module:
            resolved_file = resolve_module(sh_module, repo_root)
            if resolved_file:
                ep.kind = "python_module"
                ep.module_name = sh_module
                ep.entry_file = resolved_file
                ep.notes.append(f"shell script runs `python -m {sh_module}` -> {os.path.relpath(resolved_file, repo_root)}")
            else:
                ep.notes.append(f"shell script runs `python -m {sh_module}` but module not found in-repo")
        elif sh_file:
            ep.kind = "python_file"
            ep.entry_file = sh_file
            ep.notes.append(f"shell script runs {os.path.relpath(sh_file, repo_root)}")
        else:
            ep.notes.append(
                "Entry is a shell script with no recoverable python invocation."
            )

    if kind == "python_file" and entry_file is None:
        ep.notes.append("CMD named a .py file but it was not found on disk")
    if kind == "unresolved":
        ep.notes.append("Could not classify the command tokens: " + " ".join(tokens))

    return ep


def get_entry_points(repo_root: str) -> list[EntryPoint]:
    """Top-level: every entry point for a repo, with fallback if none resolve.

    A repo may have multiple Dockerfiles (cpu/gpu, train/serve) — each is its
    own entry point and Stage 2 walks each separately.
    """
    dockerfiles = find_dockerfiles(repo_root)
    entry_points = [resolve_entry_point(df, repo_root) for df in dockerfiles]

    if not any(ep.resolved for ep in entry_points):
        fb = _fallback_entry(repo_root)
        if fb is not None:
            entry_points.append(fb)

    return entry_points


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python dockerfile_parser.py <path-to-cloned-repo>")
        raise SystemExit(1)

    root = sys.argv[1]
    print(f"Repo: {root}")
    dfs = find_dockerfiles(root)
    print(f"Dockerfiles found: {len(dfs)}")
    for df in dfs:
        print(f"  - {df}")
    print()
    for ep in get_entry_points(root):
        print(f"[{ep.kind}] from {ep.dockerfile_path}")
        print(f"  instruction : {ep.raw_instruction}")
        print(f"  workdir     : {ep.workdir}")
        print(f"  entry_file  : {ep.entry_file}")
        print(f"  module_name : {ep.module_name}")
        print(f"  resolved    : {ep.resolved}")
        for n in ep.notes:
            print(f"  note        : {n}")
        print()
