"""Triage crash artifacts into SQLite crashes.db with stack-hash clustering (N07)."""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# 40 hex chars
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")

SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS crashes (
    bug_id TEXT PRIMARY KEY,
    campaign_id TEXT,
    file TEXT,
    size INTEGER,
    sha1 TEXT,
    stack_hash TEXT,
    frames TEXT,
    taxonomy TEXT,
    severity TEXT,
    created_at TEXT
);
"""

INDEX_SQL = "CREATE INDEX IF NOT EXISTS idx_crashes_campaign ON crashes(campaign_id);"
INDEX_SQL_STACK = "CREATE INDEX IF NOT EXISTS idx_crashes_stack_hash ON crashes(stack_hash);"

# Taxonomy patterns — order matters (first match wins)
_TAXONOMY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("SEGV", re.compile(r"Fatal Python error: Segmentation fault|SIGSEGV|Segmentation fault|SIGABRT|Fatal signal")),
    ("OOM", re.compile(r"MemoryError|Cannot allocate memory")),
    ("EXC_SWALLOWED_CANDIDATE", re.compile(r"IndexError|TypeError|ValueError|KeyError|AttributeError|OverflowError|UnicodeDecodeError|StructError")),
]

# libFuzzer/atheris exit codes: 128+signal. SIGSEGV=11, SIGABRT=6, SIGBUS=7
_EXIT_SIGNAL_MAP: dict[int, str] = {
    139: "SEGV",   # 128 + 11 (SIGSEGV)
    134: "SEGV",   # 128 + 6 (SIGABRT) — often from ASan/MSan
    140: "SEGV",   # 128 + 12 (SIGBUS)
    137: "OOM",    # 128 + 9 (SIGKILL) — OOM killer
    1: "SEGV",     # libFuzzer non-zero on crash (common with atheris)
    77: "SEGV",    # atheris/libFuzzer crash exit code
}

_SEVERITY_MAP: dict[str, str] = {
    "SEGV": "High",
    "OOM": "Medium",
    "EXC_SWALLOWED_CANDIDATE": "Low",
    "UNCLASSIFIED": "Low",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _campaigns_root() -> Path:
    root = _project_root() / "campaigns"
    if root.exists():
        return root
    cwd_root = Path("campaigns")
    if cwd_root.exists():
        return cwd_root.resolve()
    return root


def _extract_sha1(filename: str, file_path: Path) -> str:
    """Extract sha1 from filename suffix after last crash-, else hash content."""
    if "crash-" in filename:
        suffix = filename.rsplit("crash-", 1)[-1]
        candidate = suffix.strip()
        if _SHA1_RE.match(candidate):
            return candidate.lower()
        m = re.match(r"^([0-9a-fA-F]{40})", candidate)
        if m:
            return m.group(1).lower()
    try:
        data = file_path.read_bytes()
        return hashlib.sha1(data).hexdigest()
    except Exception:
        return hashlib.sha1(filename.encode()).hexdigest()


def _ensure_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(SCHEMA_V2)
        conn.execute(INDEX_SQL)
        conn.commit()
    except Exception:
        conn.close()
        raise
    # Create stack_hash index only if column exists (may be added by _migrate_db)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(crashes)")}
        if "stack_hash" in cols:
            conn.execute(INDEX_SQL_STACK)
            conn.commit()
    except Exception:
        pass
    return conn


def _migrate_db(conn: sqlite3.Connection) -> None:
    """Add stack_hash/frames/taxonomy columns if missing (migration for old rows)."""
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(crashes)")}
    except Exception:
        return
    for col, default in [
        ("stack_hash", ""),
        ("frames", ""),
        ("taxonomy", "UNCLASSIFIED"),
        ("severity", "Low"),
    ]:
        if col not in cols:
            try:
                conn.execute(f"ALTER TABLE crashes ADD COLUMN {col} TEXT DEFAULT '{default}'")
            except Exception:
                pass
    # Backfill stack_hash = sha1 for rows where stack_hash is empty
    try:
        conn.execute(
            "UPDATE crashes SET stack_hash = sha1, taxonomy = 'UNCLASSIFIED', severity = 'Low' "
            "WHERE stack_hash IS NULL OR stack_hash = ''"
        )
        conn.commit()
    except Exception:
        pass


def _normalize_stack(stderr_text: str) -> list[str]:
    """Extract normalized frames from faulthandler stderr output.

    Returns list of 'file:func' strings (top 3 frames).
    """
    frames: list[str] = []
    # faulthandler format:  "  File "foo.py", line 42, in bar"
    file_pat = re.compile(r'File\s+"([^"]+)",\s+line\s+(\d+),\s+in\s+(\S+)')
    for line in stderr_text.splitlines():
        m = file_pat.search(line)
        if m:
            filename = Path(m.group(1)).name  # basename only
            func = m.group(3)
            frames.append(f"{filename}:{func}")
            if len(frames) >= 3:
                break
    return frames


def _compute_stack_hash(frames: list[str], stderr_text: str) -> str:
    """Compute stack_hash = sha256(normalized_frames)[:16].

    Falls back to hashing the first line of stderr if no frames found.
    """
    if frames:
        key = "|".join(frames)
    else:
        # Fallback: use first non-empty line
        for line in stderr_text.splitlines():
            stripped = line.strip()
            if stripped:
                key = stripped
                break
        else:
            key = "empty"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _classify_taxonomy(stderr_text: str, exit_code: int = 0) -> str:
    """Map stderr output + exit code to taxonomy category."""
    # First try stderr patterns
    for taxonomy, pattern in _TAXONOMY_PATTERNS:
        if pattern.search(stderr_text):
            return taxonomy
    # Fallback: map exit signal
    if exit_code in _EXIT_SIGNAL_MAP:
        return _EXIT_SIGNAL_MAP[exit_code]
    # Non-zero exit without signal match → still likely a crash
    if exit_code not in (0, None):
        return "SEGV"
    return "UNCLASSIFIED"


def _score_severity(taxonomy: str) -> str:
    return _SEVERITY_MAP.get(taxonomy, "Low")


def _replay_crash(
    crash_file: Path,
    harness_path: Path,
    project_root: Path,
    python_bin: str,
) -> tuple[str, int, str]:
    """Re-run a PoC against its harness with PYTHONFAULTHANDLER=1.

    Returns (stderr_text, exit_code, stdout_text).
    """
    env = os.environ.copy()
    env["PYTHONFAULTHANDLER"] = "1"
    pp = str(project_root)
    if "PYTHONPATH" in env and env["PYTHONPATH"]:
        env["PYTHONPATH"] = pp + os.pathsep + env["PYTHONPATH"]
    else:
        env["PYTHONPATH"] = pp

    # Build command: python harness.py <crash_file> (libFuzzer reads from stdin/file)
    # For atheris, we pass the crash file as a corpus dir argument — but for replay
    # we need to feed it as a single input. Use a temporary single-file corpus dir.
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_corpus = Path(tmpdir) / "corpus"
        tmp_corpus.mkdir()
        # Copy crash file into temp corpus with a known name
        replay_file = tmp_corpus / "replay-input"
        replay_file.write_bytes(crash_file.read_bytes())

        cmd = [
            python_bin,
            str(harness_path),
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
            stderr = result.stderr or ""
            stdout = result.stdout or ""
            return stderr, result.returncode, stdout
        except subprocess.TimeoutExpired:
            return "", 0, ""
        except Exception as e:
            return f"replay error: {e}", 1, ""


def _find_harness_for_campaign(campaign_dir: Path, project_root: Path) -> Path | None:
    """Find the harness.py for a campaign by looking at its target name."""
    campaign_name = campaign_dir.name
    # campaign name format: <target>-<timestamp>-<uuid>
    target = campaign_name.split("-")[0] if "-" in campaign_name else campaign_name
    harness = project_root / "targets" / target / "harness.py"
    if harness.exists():
        return harness
    return None


def _resolve_python_bin(project_root: Path) -> str:
    venv_python = project_root / ".venv" / "bin" / "python"
    if not venv_python.exists():
        venv_python = Path(".venv/bin/python")
    if venv_python.exists():
        return str(venv_python.absolute())
    return sys.executable


def _triage_single_campaign(campaign_dir: Path, campaign_id: str) -> int:
    """Triage one campaign dir, return unique count."""
    project_root = _project_root()
    python_bin = _resolve_python_bin(project_root)
    harness = _find_harness_for_campaign(campaign_dir, project_root)

    # Collect crash files
    seen: set[Path] = set()
    files: list[Path] = []
    try:
        for pat in ("crash-*", "crash-crash-*"):
            for p in campaign_dir.glob(pat):
                try:
                    if p.is_file() and p not in seen:
                        seen.add(p)
                        files.append(p)
                except Exception:
                    continue
    except Exception:
        files = []

    # Prepare DB
    db_path = campaign_dir / "crashes.db"
    root_db_path = project_root / "crashes.db"

    conn = _ensure_db(db_path)
    _migrate_db(conn)
    root_conn: sqlite3.Connection | None = None
    try:
        root_conn = _ensure_db(root_db_path)
        _migrate_db(root_conn)
    except Exception:
        root_conn = None

    # Clear stale entries
    try:
        conn.execute("DELETE FROM crashes")
        conn.commit()
    except Exception:
        pass
    if root_conn is not None:
        try:
            root_conn.execute("DELETE FROM crashes WHERE campaign_id = ?", (campaign_id,))
            root_conn.commit()
        except Exception:
            pass

    unique_inserted = 0
    created_at = datetime.now().isoformat()

    for crash_file in files:
        try:
            size = crash_file.stat().st_size
        except Exception:
            size = 0
        try:
            filename = crash_file.name
            sha1 = _extract_sha1(filename, crash_file)
            bug_id = sha1

            # N07: replay crash to get stack trace
            stack_hash = ""
            frames_list: list[str] = []
            taxonomy = "UNCLASSIFIED"
            severity = "Low"

            if harness is not None:
                try:
                    stderr, exit_code, _stdout = _replay_crash(
                        crash_file, harness, project_root, python_bin
                    )
                    frames_list = _normalize_stack(stderr)
                    stack_hash = _compute_stack_hash(frames_list, stderr)
                    taxonomy = _classify_taxonomy(stderr, exit_code)
                    severity = _score_severity(taxonomy)
                except Exception:
                    # Fallback: use sha1 as stack_hash
                    stack_hash = sha1[:16]
            else:
                stack_hash = sha1[:16]

            frames_str = "|".join(frames_list) if frames_list else ""

            # File path relative to project root
            try:
                rel = crash_file.relative_to(project_root)
                file_str = str(rel)
            except ValueError:
                try:
                    campaigns_root = _campaigns_root()
                    rel = crash_file.relative_to(campaigns_root.parent)
                    file_str = str(rel)
                except Exception:
                    file_str = f"campaigns/{campaign_id}/{filename}"
            if not file_str:
                file_str = f"campaigns/{campaign_id}/{filename}"

            try:
                conn.execute(
                    "INSERT OR IGNORE INTO crashes "
                    "(bug_id, campaign_id, file, size, sha1, stack_hash, frames, taxonomy, severity, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (bug_id, campaign_id, file_str, size, sha1, stack_hash, frames_str, taxonomy, severity, created_at),
                )
            except Exception:
                continue
            if root_conn is not None:
                try:
                    root_conn.execute(
                        "INSERT OR IGNORE INTO crashes "
                        "(bug_id, campaign_id, file, size, sha1, stack_hash, frames, taxonomy, severity, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (bug_id, campaign_id, file_str, size, sha1, stack_hash, frames_str, taxonomy, severity, created_at),
                    )
                except Exception:
                    pass
        except Exception:
            continue

    try:
        conn.commit()
        cur = conn.execute("SELECT COUNT(*) FROM crashes")
        row = cur.fetchone()
        unique_inserted = int(row[0]) if row else 0
    except Exception:
        unique_inserted = 0
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if root_conn is not None:
        try:
            root_conn.commit()
        except Exception:
            pass
        try:
            root_conn.close()
        except Exception:
            pass

    # Print summary with taxonomy breakdown
    try:
        conn2 = sqlite3.connect(str(db_path))
        rows = conn2.execute("SELECT taxonomy, severity, stack_hash FROM crashes").fetchall()
        conn2.close()
        tax_counts: dict[str, int] = {}
        stack_hashes: set[str] = set()
        for tax, sev, sh in rows:
            tax_counts[f"{tax}({sev})"] = tax_counts.get(f"{tax}({sev})", 0) + 1
            stack_hashes.add(sh)
        tax_str = ", ".join(f"{k}:{v}" for k, v in tax_counts.items())
        print(
            f"Campaign {campaign_id}: triaged {len(files)} crashes -> "
            f"crashes.db ({unique_inserted} unique, {len(stack_hashes)} stacks: {tax_str})"
        )
    except Exception:
        print(f"Campaign {campaign_id}: triaged {len(files)} crashes -> crashes.db ({unique_inserted} unique)")

    return unique_inserted


def triage_campaign(campaign: str | None = None) -> None:
    """Triage campaign(s) - scan crash-* artifacts and populate crashes.db."""
    campaigns_root = _campaigns_root()
    if not campaigns_root.exists():
        try:
            campaigns_root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    campaign_norm = campaign.strip() if isinstance(campaign, str) else campaign
    if campaign_norm:
        campaign_norm = campaign_norm.strip()
        campaign_dir = campaigns_root / campaign_norm
        if not campaign_dir.exists():
            alt = _project_root() / "campaigns" / campaign_norm
            if alt.exists():
                campaign_dir = alt
            else:
                alt2 = Path("campaigns") / campaign_norm
                if alt2.exists():
                    campaign_dir = alt2.resolve()
        if not campaign_dir.exists():
            try:
                campaign_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                print(f"Campaign {campaign_norm}: not found, creating empty entry")
        _triage_single_campaign(campaign_dir, campaign_norm)
        return
    else:
        try:
            subdirs = [p for p in campaigns_root.iterdir() if p.is_dir()]
        except Exception:
            subdirs = []
        subdirs_sorted = sorted(subdirs, key=lambda p: p.name)
        if not subdirs_sorted:
            print("No campaigns found under campaigns/")
            try:
                root_db = _project_root() / "crashes.db"
                conn = _ensure_db(root_db)
                conn.close()
            except Exception:
                pass
            return
        for d in subdirs_sorted:
            if d.name.startswith("."):
                continue
            try:
                _triage_single_campaign(d, d.name)
            except Exception as e:
                print(f"Campaign {d.name}: failed to triage ({e})")
