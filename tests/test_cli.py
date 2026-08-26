from typer.testing import CliRunner

from kavach.cli import app

runner = CliRunner()


def test_cli_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    for cmd in ["init", "fuzz", "seeds", "minimize", "triage", "report"]:
        assert cmd in result.output, f"missing command {cmd} in --help output: {result.output}"


def test_fuzz_help_shows_options() -> None:
    result = runner.invoke(app, ["fuzz", "--help"])
    assert result.exit_code == 0, result.output
    for opt in ["--target", "--time", "--max_len"]:
        assert opt in result.output, f"missing option {opt} in fuzz --help: {result.output}"


def test_report_help_has_subcommands() -> None:
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0, result.output
    assert "serve" in result.output
    assert "export" in result.output
