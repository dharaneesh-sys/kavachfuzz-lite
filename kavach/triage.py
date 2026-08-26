"""Triage crash artifacts into SQLite crashes.db (T08)."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from datetime import datetime
from pathlib import Path

# 40 hex chars
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS crashes (
    bug_id TEXT PRIMARY KEY,
    campaign_id TEXT,
    file TEXT,
    size INTEGER,
    sha1 TEXT,
    severity TEXT,
    created_at TEXT
);
"""

INDEX_SQL = "CREATE INDEX IF NOT EXISTS idx_crashes_campaign ON crashes(campaign_id);"


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _campaigns_root() -> Path:
    root = _project_root() / "campaigns"
    if root.exists():
        return root
    # fallback to cwd
    cwd_root = Path("campaigns")
    if cwd_root.exists():
        return cwd_root.resolve()
    # default to project root
    return root


def _severity(filename: str, size: int) -> str:
    low = filename.lower()
    if size > 1024 * 1024 or "oom" in low:
        return "Low"
    if "timeout" in low or "leak" in low:
        return "Low"
    return "High"


def _extract_sha1(filename: str, file_path: Path) -> str:
    """Extract sha1 from filename suffix after last crash-, else hash content."""
    # suffix after last 'crash-'
    if "crash-" in filename:
        suffix = filename.rsplit("crash-", 1)[-1]
        # suffix may contain extra? take first 40 chars if longer? spec says suffix is sha1
        # handle case where suffix includes extra extension? we only care if 40 hex
        # also if suffix length >40 but starts with 40 hex, extract that prefix
        candidate = suffix.strip()
        # In case of crash-abc123... with no extra, candidate is sha1
        if _SHA1_RE.match(candidate):
            return candidate.lower()
        # try to find 40 hex substring at start of suffix
        m = re.match(r"^([0-9a-fA-F]{40})", candidate)
        if m:
            return m.group(1).lower()
    # fallback: hash file content
    try:
        data = file_path.read_bytes()
        return hashlib.sha1(data).hexdigest()
    except Exception:
        # ultimate fallback: hash filename
        return hashlib.sha1(filename.encode()).hexdigest()


def _ensure_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(SCHEMA)
        conn.execute(INDEX_SQL)
        conn.commit()
    except Exception:
        conn.close()
        raise
    return conn


def _triage_single_campaign(campaign_dir: Path, campaign_id: str) -> int:
    """Triage one campaign dir, return unique count."""
    # Collect crash files: glob crash-* and crash-crash-*
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

    # Deduplicate by resolved path (in case glob overlap)
    # Already handled via seen

    # Prepare DB
    db_path = campaign_dir / "crashes.db"
    # Also aggregation at project root
    project_root = _project_root()
    root_db_path = project_root / "crashes.db"

    # Ensure empty DB even if no crashes
    conn = _ensure_db(db_path)
    # For aggregation, ensure root db also has schema
    root_conn: sqlite3.Connection | None = None
    try:
        root_conn = _ensure_db(root_db_path)
    except Exception:
        root_conn = None

    # Clear stale entries for this campaign so DB reflects current artifacts
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
    # We count total files vs unique; need to track attempted inserts
    # Use INSERT OR IGNORE semantics, count rows after
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
            severity = _severity(filename, size)
            # file path relative to project root if possible
            try:
                rel = crash_file.relative_to(project_root)
                file_str = str(rel)
            except ValueError:
                try:
                    # relative to campaigns root
                    campaigns_root = _campaigns_root()
                    rel = crash_file.relative_to(campaigns_root.parent)
                    file_str = str(rel)
                except Exception:
                    file_str = f"campaigns/{campaign_id}/{filename}"
            # Also fallback to campaign relative
            if not file_str:
                file_str = f"campaigns/{campaign_id}/{filename}"

            # Parameterized queries
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO crashes (bug_id, campaign_id, file, size, sha1, severity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (bug_id, campaign_id, file_str, size, sha1, severity, created_at),
                )
            except Exception:
                continue
            if root_conn is not None:
                try:
                    root_conn.execute(
                        "INSERT OR IGNORE INTO crashes (bug_id, campaign_id, file, size, sha1, severity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (bug_id, campaign_id, file_str, size, sha1, severity, created_at),
                    )
                except Exception:
                    pass
        except Exception:
            continue

    try:
        conn.commit()
        # count unique rows in this campaign's db
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

    # Summary print
    # Use N unique also as total triaged; artifact count = len(files)
    # But unique may be less due to dedup; spec says print N crashes → crashes.db (N unique)
    # We interpret N as unique_inserted, but also show if deduplicated.
    print(f"Campaign {campaign_id}: triaged {len(files)} crashes -> crashes.db ({unique_inserted} unique)")

    return unique_inserted


def triage_campaign(campaign: str | None = None) -> None:
    """Triage campaign(s) - scan crash-* artifacts and populate crashes.db."""
    campaigns_root = _campaigns_root()
    # Also ensure alternative cwd path if project root empty but cwd has campaigns
    if not campaigns_root.exists():
        try:
            campaigns_root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    target_ids: list[str] = []

    # Normalize campaign arg: None, empty string, whitespace
    campaign_norm = campaign.strip() if isinstance(campaign, str) else campaign
    if campaign_norm:
        # Specific campaign
        campaign_norm = campaign_norm.strip()
        campaign_dir = campaigns_root / campaign_norm
        # Also check cwd variant
        if not campaign_dir.exists():
            # try project_root alternative
            alt = _project_root() / "campaigns" / campaign_norm
            if alt.exists():
                campaign_dir = alt
            else:
                alt2 = Path("campaigns") / campaign_norm
                if alt2.exists():
                    campaign_dir = alt2.resolve()
        if not campaign_dir.exists():
            # Still create empty db to satisfy zero-crash case? But spec says only that campaign.
            # Create dir if not exists? Instead warn and create empty db
            try:
                campaign_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                print(f"Campaign {campaign_norm}: not found, creating empty entry")
        # Ensure we triage this one even if dir was just created
        _triage_single_campaign(campaign_dir, campaign_norm)
        return
    else:
        # All campaigns
        try:
            subdirs = [p for p in campaigns_root.iterdir() if p.is_dir()]
        except Exception:
            subdirs = []
        # Filter subdirs: include those that are campaign dirs (contain fuzz.log or stats.json or crash-* or named like target-date)
        # But per spec: each subdir containing crash-* . However for zero-crash case we must handle dirs with 0 crashes.
        # So we triage every subdir under campaigns that looks like a campaign.
        # Exclude hidden files and files
        # Sort for determinism
        subdirs_sorted = sorted(subdirs, key=lambda p: p.name)
        if not subdirs_sorted:
            # No campaigns - still handle aggregation
            print("No campaigns found under campaigns/")
            # Ensure root crashes.db exists empty
            try:
                root_db = _project_root() / "crashes.db"
                conn = _ensure_db(root_db)
                conn.close()
            except Exception:
                pass
            return
        for d in subdirs_sorted:
            # Skip .gitkeep etc - only dirs that have plausible campaign naming? But spec says ALL campaigns under campaigns/ (each subdir)
            # We will triage all subdirs; zero-crash still creates db.
            # Skip if name starts with .
            if d.name.startswith("."):
                continue
            try:
                _triage_single_campaign(d, d.name)
            except Exception as e:
                print(f"Campaign {d.name}: failed to triage ({e})")
        # Done
        return
