"""KavachFuzz-Lite Typer CLI."""

from __future__ import annotations

from pathlib import Path

import typer
import yaml

from kavach import __version__

app = typer.Typer(help="KavachFuzz-Lite coverage-guided fuzzing")
report_app = typer.Typer(help="Report commands")
app.add_typer(report_app, name="report", help="Reporting commands")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"kavach {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v", callback=_version_callback, is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """KavachFuzz-Lite: coverage-guided fuzzing for Python-native parsers."""



@app.command("init")
def init_cmd(
    target: str = typer.Argument(..., help="Target name to initialise"),
) -> None:
    """Create a new target pack from template."""
    dest = Path(f"targets/{target}")
    if dest.exists():
        typer.echo(f"target '{target}' already exists at {dest}")
        raise typer.Exit(code=1)
    dest.mkdir(parents=True, exist_ok=False)
    (dest / "seeds").mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": target,
        "harness": "harness.py",
        "seeds_glob": "seeds/*",
        "max_len": 8192,
    }
    with open(dest / "manifest.yaml", "w") as f:
        yaml.safe_dump(manifest, f, sort_keys=False)
    # placeholder harness
    harness_content = f'''"""Harness for target {target} - placeholder (T03 will overwrite)."""
import atheris

with atheris.instrument_imports():
    import pymupdf  # noqa: F401

def TestOneInput(data: bytes) -> None:
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
        if doc.page_count:
            doc.load_page(0)
        doc.close()
    except Exception:
        pass

if __name__ == "__main__":
    atheris.Setup([__file__], TestOneInput)
    atheris.Fuzz()
'''
    (dest / "harness.py").write_text(harness_content)
    typer.echo(f"initialised target '{target}' at {dest}")


@app.command("fuzz")
def fuzz_cmd(
    target: str = typer.Option("pdf", "--target", help="Target name"),
    time: int = typer.Option(60, "--time", help="Fuzzing time in seconds"),
    max_len: int = typer.Option(8192, "--max_len", help="Maximum input length"),
    dict_path: str | None = typer.Option(None, "--dict", help="Path to fuzzer dictionary"),
    artifact_prefix: str | None = typer.Option(
        None, "--artifact_prefix", help="Prefix for crash artifacts"
    ),
    workers: int = typer.Option(1, "--workers", help="Number of parallel fuzzing workers (maps to libFuzzer -jobs/-workers)"),
) -> None:
    """Launch coverage-guided fuzzing campaign."""
    from kavach.fuzz import run_fuzz

    code = run_fuzz(target, time, max_len, dict_path, artifact_prefix, workers=workers)
    raise typer.Exit(code=code)


@app.command("seeds")
def seeds_cmd(
    target: str | None = typer.Option(None, "--target", help="Target to bootstrap seeds for"),
) -> None:
    """Bootstrap seeds corpus."""
    from kavach.corpus import bootstrap_seeds

    bootstrap_seeds(target)
    typer.echo("seeds bootstrap")


@app.command("minimize")
def minimize_cmd(
    target: str | None = typer.Option(None, "--target", help="Target to minimize corpus for"),
) -> None:
    """Minimize corpus via libFuzzer -merge=1."""
    from kavach.corpus import minimize_corpus

    minimize_corpus(target)


@app.command("triage")
def triage_cmd(
    campaign: str | None = typer.Option(None, "--campaign", help="Campaign id to triage"),
) -> None:
    """Triage crash artifacts into crashes.db."""
    from kavach.triage import triage_campaign

    triage_campaign(campaign)


@app.command("repro")
def repro_cmd(
    crash_file: str = typer.Argument(..., help="Path to crash artifact to reproduce"),
) -> None:
    """Reproduce a crash PoC against its harness."""
    from kavach.repro import run_repro

    code = run_repro(crash_file)
    raise typer.Exit(code=code)


@app.command("minimize-poc")
def minimize_poc_cmd(
    crash_file: str = typer.Argument(..., help="Path to crash artifact to minimize"),
) -> None:
    """Minimize a crash PoC via delta-debugging."""
    from kavach.minimizer import minimize_poc

    minimize_poc(crash_file)


@report_app.command("serve")
def report_serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind"),
    port: int = typer.Option(8000, "--port", help="Port to bind"),
) -> None:
    """Serve report dashboard."""
    from kavach.report import serve_report

    serve_report(host, port)
    typer.echo(f"serve report on {host}:{port}")


@report_app.command("export")
def report_export(
    output: str = typer.Option("report.md", "--output", help="Output file"),
) -> None:
    """Export report to markdown/pdf."""
    from kavach.report import export_report

    export_report(output)
    typer.echo(f"export report to {output}")


if __name__ == "__main__":
    app()
