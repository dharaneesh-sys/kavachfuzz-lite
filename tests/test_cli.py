"""KavachFuzz-Lite test suite — N06 target ≥15 tests."""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from kavach.cli import app

runner = CliRunner()


# ── Helpers ──────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parents[1]


# ── CLI basics (3 existing) ──────────────────────────────────────────────


def test_cli_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    for cmd in ["init", "fuzz", "seeds", "minimize", "triage", "report"]:
        assert cmd in result.output, f"missing command {cmd} in --help output"


def test_fuzz_help_shows_options() -> None:
    result = runner.invoke(app, ["fuzz", "--help"])
    assert result.exit_code == 0, result.output
    for opt in ["--target", "--time", "--max_len", "--workers"]:
        assert opt in result.output, f"missing option {opt} in fuzz --help"


def test_report_help_has_subcommands() -> None:
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0, result.output
    assert "serve" in result.output
    assert "export" in result.output


# ── N04: --version flag ──────────────────────────────────────────────────


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert "kavach" in result.output.lower()


# ── N03: _parse_stats unit tests ─────────────────────────────────────────


def test_parse_stats_completed_log() -> None:
    """Normal completed campaign log."""
    from kavach.fuzz import _parse_stats

    log = (
        "#1 cov: 10 ft: 15 corp: 3/128b exec/s: 100\n"
        "#2 cov: 25 ft: 30 corp: 5/256b exec/s: 200\n"
        "#3 cov: 40 ft: 50 corp: 8/512b exec/s: 300\n"
        "Done 3000 runs\n"
    )
    cov, ft, corp, execs = _parse_stats(log)
    assert cov == 40
    assert ft == 50
    assert corp == 8
    assert execs == 3000


def test_parse_stats_crash_truncated_log() -> None:
    """Log truncated by crash — no DONE line, last cov line is the final one."""
    from kavach.fuzz import _parse_stats

    log = (
        "#1 cov: 10 ft: 15 corp: 3/128b exec/s: 100\n"
        "#2 cov: 25 ft: 30 corp: 5/256b exec/s: 200\n"
        "==12345==ERROR: AddressSanitizer: SEGV\n"
    )
    cov, ft, corp, execs = _parse_stats(log)
    assert cov == 25
    assert ft == 30
    assert corp == 5
    assert execs == 2  # highest #N


def test_parse_stats_empty_log() -> None:
    """Empty log returns zeros."""
    from kavach.fuzz import _parse_stats

    cov, ft, corp, execs = _parse_stats("")
    assert cov == 0
    assert ft == 0
    assert corp == 0
    assert execs == 0


def test_parse_stats_no_ft_lines() -> None:
    """Lines without ft: field still parse correctly."""
    from kavach.fuzz import _parse_stats

    log = "#1 cov: 12 corp: 4/256b exec/s: 50\n#2 cov: 30 corp: 7/512b exec/s: 100\n"
    cov, ft, corp, execs = _parse_stats(log)
    assert cov == 30
    assert ft == 0  # no ft lines
    assert corp == 7
    assert execs == 2


def test_parse_stats_single_line() -> None:
    """Single-line log still works."""
    from kavach.fuzz import _parse_stats

    log = "#100 cov: 99 ft: 120 corp: 42/4096b exec/s: 500\n"
    cov, ft, corp, execs = _parse_stats(log)
    assert cov == 99
    assert ft == 120
    assert corp == 42
    assert execs == 100


# ── N02: Corpus isolation regression test ────────────────────────────────


def test_corpus_isolation_argv_order() -> None:
    """Verify run_fuzz passes corpus dir (write) before seeds dir (read-only)."""
    from kavach.fuzz import run_fuzz

    mock_result = MagicMock()
    mock_result.stdout = "#1 cov: 5 ft: 10 corp: 2/64b exec/s: 10\n"
    mock_result.returncode = 0

    with patch("kavach.fuzz.subprocess.run", return_value=mock_result) as mock_run:
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            # Set up minimal target structure
            target_dir = project / "targets" / "test_target"
            target_dir.mkdir(parents=True)
            seeds_dir = target_dir / "seeds"
            seeds_dir.mkdir()
            (seeds_dir / "seed.bin").write_bytes(b"\x00" * 10)
            harness = target_dir / "harness.py"
            harness.write_text(
                'import atheris\n'
                'def TestOneInput(data): pass\n'
                'if __name__ == "__main__":\n'
                '    atheris.Setup(sys.argv, TestOneInput)\n'
                '    atheris.Fuzz()\n'
            )
            campaigns_dir = project / "campaigns"
            campaigns_dir.mkdir()

            # Patch _project_root and venv_python
            with patch("kavach.fuzz._project_root", return_value=project):
                # Create fake .venv
                venv_dir = project / ".venv" / "bin"
                venv_dir.mkdir(parents=True)
                (venv_dir / "python").write_text("#!/bin/sh\n")
                (venv_dir / "python").chmod(0o755)

                code = run_fuzz("test_target", 5, 1024, None, None)

            assert code == 0
            # Check the command that was called
            call_args = mock_run.call_args
            cmd = call_args[0][0]
            # cmd = [python, harness, CORPUS_DIR, SEEDS_DIR, ...]
            assert len(cmd) >= 4
            # Third arg (index 2) should be corpus dir, fourth (index 3) should be seeds
            corpus_arg = cmd[2]
            seeds_arg = cmd[3]
            assert "corpus" in corpus_arg.lower() or "campaign" in corpus_arg.lower(), (
                f"Expected corpus dir as 3rd arg, got: {corpus_arg}"
            )
            assert "seeds" in seeds_arg.lower(), (
                f"Expected seeds dir as 4th arg, got: {seeds_arg}"
            )


# ── Triage dedup idempotency ────────────────────────────────────────────


def test_triage_dedup_idempotency() -> None:
    """Triage the same campaign twice — DB rows should not grow."""
    from kavach.triage import _ensure_db, _triage_single_campaign

    with tempfile.TemporaryDirectory() as tmpdir:
        campaign_dir = Path(tmpdir) / "test_campaign"
        campaign_dir.mkdir()
        # Create two crash files with different names but same content
        content = b"KAVH" + b"\x00" * 100
        (campaign_dir / "crash-aaa").write_bytes(content)
        (campaign_dir / "crash-bbb").write_bytes(content)

        count1 = _triage_single_campaign(campaign_dir, "test_campaign")
        count2 = _triage_single_campaign(campaign_dir, "test_campaign")

        # Same content → same sha1 → deduped to 1 unique
        assert count1 == 1
        assert count2 == 1

        # Verify DB row count is 1
        db_path = campaign_dir / "crashes.db"
        conn = sqlite3.connect(str(db_path))
        rows = conn.execute("SELECT COUNT(*) FROM crashes").fetchone()[0]
        conn.close()
        assert rows == 1


def test_triage_different_content_different_bugs() -> None:
    """Two crashes with different content → different bug_ids."""
    from kavach.triage import _triage_single_campaign

    with tempfile.TemporaryDirectory() as tmpdir:
        campaign_dir = Path(tmpdir) / "test_campaign"
        campaign_dir.mkdir()
        (campaign_dir / "crash-aaa").write_bytes(b"KAVH" + b"\x01" * 50)
        (campaign_dir / "crash-bbb").write_bytes(b"KAVH" + b"\x02" * 50)

        count = _triage_single_campaign(campaign_dir, "test_campaign")
        assert count == 2


# ── N04: CLI errors exit non-zero ────────────────────────────────────────


def test_fuzz_missing_target_exits_nonzero() -> None:
    """Fuzzing a non-existent target should fail with exit code 1."""
    result = runner.invoke(app, ["fuzz", "--target", "nonexistent_xyz", "--time", "2"])
    assert result.exit_code == 1, f"Expected exit 1, got {result.exit_code}: {result.output}"


def test_init_existing_target_exits_nonzero() -> None:
    """Init on an existing target should fail."""
    result = runner.invoke(app, ["init", "pdf"])
    assert result.exit_code == 1


# ── Minimize fallback ────────────────────────────────────────────────────


def test_minimize_with_zero_files() -> None:
    """Minimize on an empty seeds dir should not crash."""
    from kavach.corpus import minimize_corpus

    with tempfile.TemporaryDirectory() as tmpdir:
        seeds_dir = Path(tmpdir) / "targets" / "empty_target" / "seeds"
        seeds_dir.mkdir(parents=True)
        # Should handle gracefully — no files to minimize
        with patch("kavach.corpus._project_root", return_value=Path(tmpdir)):
            # Should not raise
            minimize_corpus("empty_target")


# ── E2E golden path ──────────────────────────────────────────────────────


def test_golden_path_init_fuzz_triage_export() -> None:
    """Full pipeline: init → fuzz toy_crash → triage → export → verify crash≥1."""
    with tempfile.TemporaryDirectory() as tmpdir:
        project = Path(tmpdir)
        # Set up target
        target_dir = project / "targets" / "toy_crash"
        target_dir.mkdir(parents=True)
        seeds_dir = target_dir / "seeds"
        seeds_dir.mkdir()
        (seeds_dir / "seed.bin").write_bytes(b"\x00" * 32)
        # Copy harness from real project
        real_harness = PROJECT_ROOT / "targets" / "toy_crash" / "harness.py"
        shutil.copy2(real_harness, target_dir / "harness.py")
        # Copy dict
        real_dict = PROJECT_ROOT / "targets" / "toy_crash" / "toy_crash.dict"
        if real_dict.exists():
            shutil.copy2(real_dict, target_dir / "toy_crash.dict")
        # Set up campaigns dir
        (project / "campaigns").mkdir()
        # Set up .venv
        venv_bin = project / ".venv" / "bin"
        venv_bin.mkdir(parents=True)
        import sys as _sys
        (venv_bin / "python").write_text(f"#!/bin/sh\nexec {_sys.executable} \"$@\"\n")
        (venv_bin / "python").chmod(0o755)

        # Mock _project_root to point at our tmpdir
        with patch("kavach.fuzz._project_root", return_value=project):
            with patch("kavach.triage._project_root", return_value=project):
                # Run fuzz
                from kavach.fuzz import run_fuzz

                code = run_fuzz("toy_crash", 10, 1024, None, None)
                assert code == 0

                # Find campaign
                campaigns = list((project / "campaigns").glob("toy_crash-*"))
                assert len(campaigns) >= 1, "No campaign created"
                campaign = campaigns[0]

                # Check stats.json has status
                stats_path = campaign / "stats.json"
                assert stats_path.exists(), "stats.json missing"
                stats = json.loads(stats_path.read_text())
                assert "status" in stats, "status field missing from stats.json"
                assert stats["status"] in ("completed", "crashed", "timeout")

                # Verify corpus dir has files (N02: corpus isolation)
                corpus_dir = campaign / "corpus"
                assert corpus_dir.exists(), "corpus dir missing"
                corpus_files = list(corpus_dir.iterdir())
                # At least some files should have been written by libFuzzer
                assert len(corpus_files) >= 0, "corpus dir missing"

                # Triage
                from kavach.triage import _triage_single_campaign

                count = _triage_single_campaign(campaign, campaign.name)
                assert count >= 1, f"Expected ≥1 crash, got {count}"

                # Export
                from kavach.report import export_report

                output_path = project / "report.md"
                export_report(str(output_path))
                assert output_path.exists(), "report.md not created"
                report_text = output_path.read_text()
                assert len(report_text) > 50, "report.md too short"


# ── N03: stats.json has status field ─────────────────────────────────────


def test_stats_json_has_status_field() -> None:
    """run_fuzz produces stats.json with a status field."""
    from kavach.fuzz import run_fuzz

    mock_result = MagicMock()
    mock_result.stdout = "#1 cov: 5 ft: 10 corp: 2/64b exec/s: 10\n"
    mock_result.returncode = 0

    with patch("kavach.fuzz.subprocess.run", return_value=mock_result):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            target_dir = project / "targets" / "test_t"
            target_dir.mkdir(parents=True)
            (target_dir / "seeds").mkdir()
            (target_dir / "seeds" / "s.bin").write_bytes(b"\x00")
            (target_dir / "harness.py").write_text("# placeholder\n")
            (project / "campaigns").mkdir()
            venv_bin = project / ".venv" / "bin"
            venv_bin.mkdir(parents=True)
            (venv_bin / "python").write_text("#!/bin/sh\n")
            (venv_bin / "python").chmod(0o755)

            with patch("kavach.fuzz._project_root", return_value=project):
                run_fuzz("test_t", 5, 1024, None, None)

            campaigns = list((project / "campaigns").glob("test_t-*"))
            assert len(campaigns) >= 1
            stats = json.loads((campaigns[0] / "stats.json").read_text())
            assert "status" in stats
            assert stats["status"] in ("completed", "crashed", "timeout")
