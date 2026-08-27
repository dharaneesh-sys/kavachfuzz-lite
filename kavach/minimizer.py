"""N09: PoC minimizer — delta-debug a crash input while preserving the crash signature."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_python_bin(project_root: Path) -> str:
    venv_python = project_root / ".venv" / "bin" / "python"
    if not venv_python.exists():
        venv_python = Path(".venv/bin/python")
    if venv_python.exists():
        return str(venv_python.absolute())
    return sys.executable


def _find_harness_for_crash(crash_path: Path, project_root: Path) -> Path | None:
    parts = crash_path.parts
    for i, part in enumerate(parts):
        if part == "campaigns" and i + 1 < len(parts):
            campaign_name = parts[i + 1]
            target = campaign_name.split("-")[0] if "-" in campaign_name else campaign_name
            harness = project_root / "targets" / target / "harness.py"
            if harness.exists():
                return harness
    return None


def _get_stack_hash(harness: Path, data: bytes, project_root: Path, python_bin: str) -> str:
    """Run harness on data and return stack hash (sha256 of stderr frames)."""
    import re

    env = os.environ.copy()
    env["PYTHONFAULTHANDLER"] = "1"
    pp = str(project_root)
    if "PYTHONPATH" in env and env["PYTHONPATH"]:
        env["PYTHONPATH"] = pp + os.pathsep + env["PYTHONPATH"]
    else:
        env["PYTHONPATH"] = pp

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_corpus = Path(tmpdir) / "corpus"
        tmp_corpus.mkdir()
        (tmp_corpus / "input").write_bytes(data)

        cmd = [
            python_bin,
            str(harness),
            str(tmp_corpus),
            "-max_total_time=5",
            "-close_fd_mask=3",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project_root),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                text=True,
            )
        except Exception:
            return "error"

        stderr = result.stderr or ""
        exit_code = result.returncode

        # Check if it crashed
        crash_signals = ["SEGFAULT", "SIGSEGV", "Segmentation fault", "Fatal Python error",
                         "AddressSanitizer", "MEMORY ERROR", "Aborted"]
        is_crash = any(sig.lower() in stderr.lower() for sig in crash_signals) or exit_code not in (0, None)

        if not is_crash:
            return ""

        # Extract frames
        file_pat = re.compile(r'File\s+"([^"]+)",\s+line\s+(\d+),\s+in\s+(\S+)')
        frames: list[str] = []
        for line in stderr.splitlines():
            m = file_pat.search(line)
            if m:
                filename = Path(m.group(1)).name
                func = m.group(3)
                frames.append(f"{filename}:{func}")
                if len(frames) >= 3:
                    break

        if frames:
            return hashlib.sha256("|".join(frames).encode()).hexdigest()[:16]
        # Fallback
        for line in stderr.splitlines():
            stripped = line.strip()
            if stripped:
                return hashlib.sha256(stripped.encode()).hexdigest()[:16]
        return hashlib.sha256(b"crash").hexdigest()[:16]


def _delta_debug(data: bytes, target_hash: str, harness: Path,
                 project_root: Path, python_bin: str) -> bytes:
    """Binary delta-debugging: halve the input while preserving the crash.

    Returns the smallest input that still triggers the same stack_hash.
    """
    best = data
    best_hash = target_hash

    # Try removing chunks of increasing size
    chunk_size = len(data) // 2
    while chunk_size >= 1:
        changed = False
        for offset in range(0, len(best), chunk_size):
            # Try removing this chunk
            candidate = best[:offset] + best[offset + chunk_size:]
            if len(candidate) == 0:
                continue
            h = _get_stack_hash(harness, candidate, project_root, python_bin)
            if h == target_hash and len(candidate) < len(best):
                best = candidate
                best_hash = h
                changed = True
                break  # Restart with smaller chunk from the beginning
        if not changed:
            chunk_size //= 2
    return best


def minimize_poc(crash_file_arg: str) -> None:
    """Minimize a crash PoC via delta-debugging. Writes poc/<bug_id>.min + repro.json."""
    project_root = _project_root()
    python_bin = _resolve_python_bin(project_root)

    crash_path = Path(crash_file_arg)
    if not crash_path.is_absolute():
        crash_path = project_root / crash_path
    if not crash_path.exists():
        print(f"error: file not found: {crash_file_arg}", file=sys.stderr)
        return

    harness = _find_harness_for_crash(crash_path, project_root)
    if harness is None:
        print(f"error: could not find harness for {crash_file_arg}", file=sys.stderr)
        return

    orig_data = crash_path.read_bytes()
    orig_size = len(orig_data)
    print(f"Minimizing {crash_path.name} ({orig_size} bytes)...")

    # Get original stack hash
    target_hash = _get_stack_hash(harness, orig_data, project_root, python_bin)
    if not target_hash:
        print("error: original input does not crash", file=sys.stderr)
        return

    print(f"Original stack_hash: {target_hash}")

    # Delta-debug
    min_data = _delta_debug(orig_data, target_hash, harness, project_root, python_bin)
    min_size = len(min_data)

    # Compute bug_id from stack hash
    bug_id = target_hash

    # Write minimized PoC
    poc_dir = project_root / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)
    min_path = poc_dir / f"{bug_id}.min"
    min_path.write_bytes(min_data)

    # Verify minimized PoC still crashes
    verify_hash = _get_stack_hash(harness, min_data, project_root, python_bin)
    verified = verify_hash == target_hash

    # Write repro.json
    repro_info = [
        {
            "bug_id": bug_id,
            "orig_size": orig_size,
            "min_size": min_size,
            "stack_hash": target_hash,
            "verified": verified,
            "repro_command": f"kavach repro poc/{bug_id}.min",
            "source_file": str(crash_path.relative_to(project_root)) if crash_path.is_absolute() else str(crash_path),
        }
    ]
    repro_path = project_root / "repro.json"
    repro_path.write_text(json.dumps(repro_info, indent=2))

    print(f"Minimized: {orig_size} → {min_size} bytes ({min_size/orig_size*100:.1f}% of original)")
    print(f"Written: poc/{bug_id}.min")
    print(f"Verified: {'YES' if verified else 'NO (stack hash changed!)'}")
    print(f"Repro: kavach repro poc/{bug_id}.min")
