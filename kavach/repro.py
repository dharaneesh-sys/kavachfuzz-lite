"""N08: Reproduce a crash PoC against its harness."""

from __future__ import annotations

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
    """Find the harness.py for a crash by looking up its campaign in the DB or path."""
    # Try to find via campaign directory name
    # crash path example: campaigns/toy_crash-20260827-.../crash-xxx
    parts = crash_path.parts
    for i, part in enumerate(parts):
        if part == "campaigns" and i + 1 < len(parts):
            campaign_name = parts[i + 1]
            target = campaign_name.split("-")[0] if "-" in campaign_name else campaign_name
            harness = project_root / "targets" / target / "harness.py"
            if harness.exists():
                return harness

    # Try via crashes.db lookup
    try:
        # Walk up to find campaigns dir
        parent = crash_path.parent
        while parent != parent.parent:
            db_path = parent / "crashes.db"
            if db_path.exists():
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT campaign_id FROM crashes WHERE file LIKE ? LIMIT 1",
                    (f"%{crash_path.name}%",),
                ).fetchall()
                conn.close()
                if rows:
                    campaign_id = rows[0]["campaign_id"]
                    target = campaign_id.split("-")[0] if "-" in campaign_id else campaign_id
                    harness = project_root / "targets" / target / "harness.py"
                    if harness.exists():
                        return harness
            parent = parent.parent
    except Exception:
        pass

    return None


def run_repro(crash_file_arg: str) -> int:
    """Reproduce a crash PoC. Returns 0 if reproduced, 1 if not."""
    project_root = _project_root()
    python_bin = _resolve_python_bin(project_root)

    # Resolve crash file path
    crash_path = Path(crash_file_arg)
    if not crash_path.is_absolute():
        crash_path = project_root / crash_path
    if not crash_path.exists():
        print(f"NOT REPRODUCED — file not found: {crash_file_arg}", file=sys.stderr)
        return 1

    # Find harness
    harness = _find_harness_for_crash(crash_path, project_root)
    if harness is None:
        print(f"NOT REPRODUCED — could not find harness for {crash_file_arg}", file=sys.stderr)
        return 1

    # Replay
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
        replay_file = tmp_corpus / "replay-input"
        replay_file.write_bytes(crash_path.read_bytes())

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
        except subprocess.TimeoutExpired:
            print(f"NOT REPRODUCED — timeout after 15s: {crash_file_arg}")
            return 1
        except Exception as e:
            print(f"NOT REPRODUCED — error: {e}", file=sys.stderr)
            return 1

    # Determine if crash reproduced
    stderr = result.stderr or ""
    exit_code = result.returncode

    # Look for crash signals in stderr or non-zero exit
    crash_signals = ["SEGFAULT", "SIGSEGV", "Segmentation fault", "Fatal Python error",
                     "AddressSanitizer", "MEMORY ERROR", "Aborted"]
    is_crash = any(sig.lower() in stderr.lower() for sig in crash_signals)
    # libFuzzer returns non-zero on crash (often 77 for SIGSEGV)
    if exit_code not in (0, None):
        is_crash = True

    # Look up taxonomy from DB if available
    taxonomy = "UNKNOWN"
    bug_id = ""
    try:
        parent = crash_path.parent
        while parent != parent.parent:
            db_path = parent / "crashes.db"
            if db_path.exists():
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT bug_id, taxonomy FROM crashes WHERE file LIKE ? LIMIT 1",
                    (f"%{crash_path.name}%",),
                ).fetchall()
                conn.close()
                if rows:
                    bug_id = rows[0]["bug_id"]
                    taxonomy = rows[0]["taxonomy"]
                    break
            parent = parent.parent
    except Exception:
        pass

    if is_crash:
        label = f"REPRODUCED bug_id={bug_id}" if bug_id else "REPRODUCED"
        print(f"{label} (taxonomy={taxonomy}, exit={exit_code})")
        return 0
    else:
        print(f"NOT REPRODUCED — exit={exit_code}: {crash_file_arg}")
        return 1
