"""
Stage 2 — AST call-graph walker.

Takes an EntryPoint (from Stage 1) and walks outward through in-repo imports to
build the *reachability graph*: the set of files and functions that actually
execute when the container starts. This replaces the old "up to 10 files by
filename heuristic, truncated to 4000 chars" approach.

Standalone: stdlib only (`ast`), no network. Operates on a local repo checkout.

What it does NOT do yet:
  - Resolve dynamic imports (importlib, __import__) — flagged, not followed.
  - Notebook (.ipynb) parsing — see notebook_to_module() stub; ~40/189 repos
    are notebooks and need cell extraction before this stage.
  - Shell-script entry points — Stage 1 flags these; a small shell parser to
    recover the `python ...` line is a separate helper.
"""

from __future__ import annotations

import ast
import json
import os
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ModuleNode:
    """One in-repo Python file reached by the walk."""
    path: str                              # absolute path on disk
    rel_path: str                          # path relative to repo root
    imports: list[str] = field(default_factory=list)        # raw import targets
    in_repo_deps: list[str] = field(default_factory=list)   # resolved in-repo file paths
    external_deps: list[str] = field(default_factory=list)  # stdlib / pip packages
    functions: list[str] = field(default_factory=list)      # def names in this file
    calls: list[str] = field(default_factory=list)          # call names seen in this file
    parse_error: Optional[str] = None
    depth: int = 0                         # BFS distance from the entry point


@dataclass
class CallGraph:
    """The reachability result for one entry point."""
    repo_root: str
    entry_file: str
    modules: dict[str, ModuleNode] = field(default_factory=dict)  # keyed by abs path
    unresolved_imports: list[str] = field(default_factory=list)
    dynamic_import_sites: list[str] = field(default_factory=list)

    @property
    def reachable_files(self) -> list[str]:
        return sorted(self.modules.keys())

    def summary(self) -> dict:
        return {
            "entry_file": self.entry_file,
            "reachable_file_count": len(self.modules),
            "total_functions": sum(len(m.functions) for m in self.modules.values()),
            "max_depth": max((m.depth for m in self.modules.values()), default=0),
            "parse_errors": [m.rel_path for m in self.modules.values() if m.parse_error],
            "dynamic_import_sites": self.dynamic_import_sites,
            "unresolved_imports": sorted(set(self.unresolved_imports)),
        }


# ---------------------------------------------------------------------------
# Per-file AST analysis
# ---------------------------------------------------------------------------

class _FileVisitor(ast.NodeVisitor):
    """Collects imports, function defs, and call names from one module's AST.

    Calls are emitted as 'canonical_name@line' so downstream stage verification
    can match against canonical names (resolving aliases like
    `import pandas as panda`) and report file+line for every match.

    Alias resolution covers the two common forms:
      `import pandas as panda`            -> panda  → pandas
      `from pandas import read_csv as rc` -> rc     → pandas.read_csv
    Plain `from pandas import read_csv`   -> read_csv → pandas.read_csv
    The most-common canonical form is also added: `pd.read_csv` is kept as-is
    when `import pandas as pd` (we map panda back to its actual pandas name).
    """

    # Canonical short aliases the ML world uses everywhere — we treat these as
    # the canonical form so signal lists can use 'pd.read_csv', 'np.load' etc.
    _CANONICAL_ALIASES = {
        "pandas": "pd", "numpy": "np", "polars": "pl",
        "tensorflow": "tf", "matplotlib.pyplot": "plt",
        "seaborn": "sns", "torch.nn": "nn",
        "dask.dataframe": "dd", "xgboost": "xgb", "lightgbm": "lgb",
        "albumentations": "A", "gradio": "gr", "streamlit": "st",
        "statsmodels.api": "sm", "torch.nn.functional": "F",
    }

    def __init__(self) -> None:
        self.imports: list[tuple[str, int]] = []   # (module, level) — level>0 = relative
        self.functions: list[str] = []
        self.calls: list[str] = []                  # 'name@line' entries
        self.dynamic_imports: list[str] = []
        # Local-name -> canonical-dotted-name mappings for this file.
        self._alias: dict[str, str] = {}

    # ---- imports build the alias map --------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            canonical = self._CANONICAL_ALIASES.get(alias.name, alias.name)
            local = alias.asname or alias.name.split(".")[0]
            self._alias[local] = canonical
            self.imports.append((alias.name, 0))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        # `from X import Y as Z` -> Z resolves to X.Y
        for alias in (node.names or []):
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            target = f"{mod}.{alias.name}" if mod else alias.name
            # Apply canonical alias rewrite to the source module too.
            target = self._rewrite_with_canonical(target)
            self._alias[local] = target
        self.imports.append((mod, node.level))
        self.generic_visit(node)

    def _rewrite_with_canonical(self, dotted: str) -> str:
        """If a fully-qualified name starts with a known canonical-aliased
        module, rewrite the prefix to the short form (pandas.read_csv → pd.read_csv).
        """
        for full, short in self._CANONICAL_ALIASES.items():
            if dotted == full or dotted.startswith(full + "."):
                return short + dotted[len(full):]
        return dotted

    # ---- definitions ------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)

    # ---- calls — resolve and stamp with line number -----------------------

    def visit_Call(self, node: ast.Call) -> None:
        raw = _call_name(node.func)
        if raw:
            canonical = self._resolve_call(raw)
            line = getattr(node, "lineno", 0) or 0
            self.calls.append(f"{canonical}@{line}")
            if canonical in ("__import__", "importlib.import_module", "import_module"):
                self.dynamic_imports.append(canonical)
        self.generic_visit(node)

    def _resolve_call(self, raw: str) -> str:
        """Map a raw dotted call name through this file's alias table.

        Example: file imports `from pandas import read_csv as rc`, then calls
        rc(path). raw == 'rc'. _alias['rc'] == 'pandas.read_csv'. We canonicalize
        'pandas.' to 'pd.' so the signal list ('pd.read_csv') matches.
        """
        head, _, rest = raw.partition(".")
        if head in self._alias:
            resolved = self._alias[head] + ("." + rest if rest else "")
            return self._rewrite_with_canonical(resolved)
        # Even without an alias entry, canonicalize prefixes like 'pandas.read_csv'.
        return self._rewrite_with_canonical(raw)


def _call_name(node: ast.AST) -> Optional[str]:
    """Best-effort dotted name for a call target (e.g. 'pd.read_csv', 'pickle.load')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def analyze_file(abs_path: str) -> _FileVisitor | None:
    """Parse one file and return its visitor, or None on unreadable file."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError:
        return None
    try:
        tree = ast.parse(source, filename=abs_path)
    except SyntaxError as exc:
        v = _FileVisitor()
        v._syntax_error = f"{exc.msg} (line {exc.lineno})"  # type: ignore[attr-defined]
        return v
    v = _FileVisitor()
    v.visit(tree)
    return v


# ---------------------------------------------------------------------------
# Import resolution — the heart of "is this dependency in the repo?"
# ---------------------------------------------------------------------------

def _module_to_paths(module: str, level: int, current_file: str, repo_root: str) -> list[str]:
    """Map an import target to candidate file paths *inside the repo*.

    Handles:
      absolute imports : `import pkg.sub`        -> repo_root/pkg/sub.py or .../sub/__init__.py
      relative imports : `from . import x`       -> resolved against current_file's package
    Returns only paths that exist on disk; empty list => not an in-repo import.
    """
    candidates: list[str] = []

    if level > 0:
        # Relative import: start from the current file's directory, go up `level-1` times.
        base = os.path.dirname(current_file)
        for _ in range(level - 1):
            base = os.path.dirname(base)
        parts = module.split(".") if module else []
        target = os.path.join(base, *parts)
        candidates += [target + ".py", os.path.join(target, "__init__.py")]
    else:
        # Absolute import: try to resolve against the repo root.
        parts = module.split(".")
        target = os.path.join(repo_root, *parts)
        candidates += [target + ".py", os.path.join(target, "__init__.py")]
        # Also try dropping the first segment — repos often import themselves by
        # their top-level package name which equals the repo dir name.
        if len(parts) > 1:
            inner = os.path.join(repo_root, *parts[1:])
            candidates += [inner + ".py", os.path.join(inner, "__init__.py")]

    return [os.path.normpath(c) for c in candidates if os.path.isfile(c)]


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------

def build_call_graph(entry_file: str, repo_root: str, max_depth: int = 25) -> CallGraph:
    """Breadth-first walk from `entry_file` through in-repo imports.

    `max_depth` guards against pathological repos; 25 is far beyond any real
    pipeline's import depth but prevents runaway walks.
    """
    repo_root = os.path.normpath(os.path.abspath(repo_root))
    entry_file = os.path.normpath(os.path.abspath(entry_file))

    graph = CallGraph(repo_root=repo_root, entry_file=entry_file)
    queue: list[tuple[str, int]] = [(entry_file, 0)]
    seen: set[str] = set()

    while queue:
        path, depth = queue.pop(0)
        if path in seen or depth > max_depth:
            continue
        seen.add(path)

        rel = os.path.relpath(path, repo_root)
        node = ModuleNode(path=path, rel_path=rel, depth=depth)

        visitor = analyze_file(path)
        if visitor is None:
            node.parse_error = "could not read file"
            graph.modules[path] = node
            continue
        if hasattr(visitor, "_syntax_error"):
            node.parse_error = f"syntax error: {visitor._syntax_error}"  # type: ignore[attr-defined]
            graph.modules[path] = node
            continue

        node.functions = visitor.functions
        node.calls = visitor.calls
        for d in visitor.dynamic_imports:
            graph.dynamic_import_sites.append(f"{rel}: {d}")

        for module, level in visitor.imports:
            label = ("." * level) + module
            node.imports.append(label)
            resolved = _module_to_paths(module, level, path, repo_root)
            if resolved:
                for r in resolved:
                    node.in_repo_deps.append(r)
                    if r not in seen:
                        queue.append((r, depth + 1))
            else:
                # Not found in-repo => external (stdlib or pip) or unresolved.
                if level > 0:
                    graph.unresolved_imports.append(f"{rel}: {label}")
                else:
                    node.external_deps.append(module)

        graph.modules[path] = node

    return graph


# ---------------------------------------------------------------------------
# Notebook handling — stub (~40/189 repos are .ipynb)
# ---------------------------------------------------------------------------

def notebook_to_module(ipynb_path: str, out_path: str) -> str:
    """Extract code cells from a .ipynb into a synthetic .py file for AST parsing.

    Notebooks are JSON; code cells live under cells[].source where cell_type ==
    'code'. We concatenate them in order. IPython magics (%, !) are commented
    out so `ast.parse` does not choke.
    """
    with open(ipynb_path, "r", encoding="utf-8", errors="replace") as fh:
        nb = json.load(fh)

    chunks: list[str] = []
    for cell in nb.get("cells", []):
        if cell.get("cell_type") != "code":
            continue
        src = cell.get("source", [])
        text = "".join(src) if isinstance(src, list) else str(src)
        safe_lines = []
        for line in text.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("%") or stripped.startswith("!"):
                safe_lines.append("# [magic] " + line)
            else:
                safe_lines.append(line)
        chunks.append("\n".join(safe_lines))

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n\n# --- cell boundary ---\n\n".join(chunks))
    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("usage: python ast_callgraph.py <repo-root> <entry-file>")
        raise SystemExit(1)

    repo_root, entry = sys.argv[1], sys.argv[2]
    g = build_call_graph(entry, repo_root)

    s = g.summary()
    print(f"Entry file        : {s['entry_file']}")
    print(f"Reachable files   : {s['reachable_file_count']}")
    print(f"Total functions   : {s['total_functions']}")
    print(f"Max import depth  : {s['max_depth']}")
    if s["parse_errors"]:
        print(f"Parse errors      : {s['parse_errors']}")
    if s["dynamic_import_sites"]:
        print(f"Dynamic imports   : {s['dynamic_import_sites']}")
    print()
    print("Reachable modules (depth | rel_path | #funcs):")
    for path in g.reachable_files:
        m = g.modules[path]
        print(f"  d{m.depth:<2} {m.rel_path:<45} {len(m.functions)} fn")
