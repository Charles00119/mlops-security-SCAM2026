"""Shared helpers for invoking external scanner tools as subprocesses.

Each tool wrapper uses run_tool() to call its CLI with a timeout, capture
stdout/stderr, and tolerate non-zero exit codes (many scanners return non-zero
when findings exist, which is not a failure for us).
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class ToolResult:
    """Result of invoking a scanner subprocess."""
    ok: bool                # whether the tool ran to completion (not whether it found things)
    stdout: str
    stderr: str
    returncode: int
    error: str = ""         # populated when ok=False with a short reason


def is_installed(binary: str) -> bool:
    """True if `binary` is on PATH."""
    return shutil.which(binary) is not None


def run_tool(
    cmd: list[str],
    *,
    cwd: str | None = None,
    timeout: int = 300,
    allowed_returncodes: tuple[int, ...] = (0, 1),
) -> ToolResult:
    """Run a subprocess and capture output.

    Many scanners use exit code 1 to mean "findings present" rather than error;
    allowed_returncodes lets each wrapper declare which codes are non-fatal.
    """
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            # Tool output is UTF-8 JSON; never let a stray byte kill the reader
            # thread (on Windows the default is cp1252, which raised
            # UnicodeDecodeError and surfaced as 'NoneType'.strip crashes).
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(ok=False, stdout="", stderr="", returncode=-1,
                          error=f"timeout after {timeout}s")
    except FileNotFoundError:
        return ToolResult(ok=False, stdout="", stderr="", returncode=-1,
                          error=f"binary not found: {cmd[0]}")
    except Exception as exc:  # broad: never let a tool crash the orchestrator
        return ToolResult(ok=False, stdout="", stderr="", returncode=-1,
                          error=f"{type(exc).__name__}: {exc}")

    if proc.returncode not in allowed_returncodes:
        return ToolResult(ok=False, stdout=proc.stdout, stderr=proc.stderr,
                          returncode=proc.returncode,
                          error=f"unexpected exit {proc.returncode}")

    return ToolResult(ok=True, stdout=proc.stdout, stderr=proc.stderr,
                      returncode=proc.returncode)
