# KavachFuzz-Lite

[![CI](https://github.com/dinusus/kavachfuzz-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/dinusus/kavachfuzz-lite/actions/workflows/ci.yml)

Coverage-guided fuzzing for Python-native parsers. Built on [Atheris](https://github.com/google/atheris) (libFuzzer) with stack-hash triage, PoC minimization, and a live dashboard.

## Features

| Feature | Description |
|---|---|
| Coverage-guided fuzzing | Atheris/libFuzzer with dict bootstrap, parallel workers (`--workers N`) |
| Corpus isolation | Campaign write-dir separated from seed read-dir; no more polluted seeds |
| Stack-hash triage | Replays PoCs with `PYTHONFAULTHANDLER=1`, normalizes frames, computes `sha256(frames)[:16]` |
| Taxonomy & severity | Auto-classifies crashes: SEGV=High, OOM=Medium, EXC=Low, UNCLASSIFIED=Low |
| PoC minimization | Binary delta-debugging preserves stack_hash, writes `poc/<bug_id>.min` |
| Reproduction | `kavach repro <crash-file>` verifies PoC triggers same crash on demand |
| Coverage time-series | Per-iteration `(t, cov, corp, exec_s)` in `stats.json.timeseries[]` |
| Dashboard v2 | Trend chart, severity donut, stack-hash groups, auto-refresh, campaign detail |
| Parallel fuzzing | `--workers N` maps to libFuzzer `-jobs=N -workers=N` |

## Quickstart

```bash
# Install
uv pip install -e .

# Fuzz a target (10s test)
kavach fuzz --target toy_crash --time 10

# Triage crashes
kavach triage

# Reproduce a crash
kavach repro campaigns/toy_crash-*/crash-*

# Minimize a PoC
kavach minimize-poc campaigns/toy_crash-*/crash-*

# Launch dashboard
kavach report serve --port 8000
# Open http://localhost:8000

# Export markdown report
kavach report export --output report.md
```

## Target packs

Each target lives in `targets/<name>/` with:

- `harness.py` — Atheris harness (`TestOneInput(data)`)
- `seeds/` — initial corpus (read-only during fuzzing)
- `<name>.dict` — libFuzzer dictionary (optional)
- `manifest.yaml` — metadata

### Built-in targets

| Target | Library | Harness strategy | Coverage |
|---|---|---|---|
| `pdf` | PyMuPDF | `open(stream=data)` + `load_page(0)` | ~65k execs/s |
| `image` | Pillow | `Image.open().verify()` | ~118k execs/s |
| `image_deep` | Pillow | `open().load().getexif().resize().split()` | deeper parser surface |
| `toy_crash` | ctypes | `string_at(0)` on KAVH magic — guaranteed SIGSEGV | demo |

## Architecture

```
kavach/
├── cli.py          # Typer CLI (init/fuzz/seeds/minimize/triage/repro/minimize-poc/report)
├── fuzz.py         # Atheris campaign engine + stats parser + timeseries
├── triage.py       # Stack-hash triage, taxonomy, severity, DB migration
├── repro.py        # PoC reproduction against harness
├── minimizer.py    # Delta-debug PoC minimizer
├── corpus.py       # Seed bootstrap (pdf.js/synthetic) + merge minimization
└── report.py       # FastAPI dashboard v2 + markdown export
```

## Commands

```
kavach init <target>          Create new target pack from template
kavach fuzz --target <t>      Launch fuzzing campaign
  --time 60                     Duration in seconds
  --workers 1                   Parallel workers (libFuzzer -jobs/-workers)
  --dict <path>                 Custom dictionary
kavach seeds --target <t>    Bootstrap seeds corpus
kavach minimize --target <t> Minimize corpus via libFuzzer -merge=1
kavach triage                 Triage crashes into crashes.db
kavach repro <crash-file>    Reproduce a crash PoC
kavach minimize-poc <file>   Minimize a crash PoC (delta-debug)
kavach report serve           Launch dashboard (default :8000)
kavach report export          Export markdown report
kavach --version              Show version
```

## API endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard v2 (auto-refresh 5s) |
| `GET /campaign/<id>` | Per-campaign detail with timeseries chart |
| `GET /api/stats` | JSON: campaigns, totals, timeseries |
| `GET /api/crashes` | JSON: triaged crashes with stack_hash, taxonomy, severity |

## Known limitations

- **No Windows support** — Atheris requires Linux. Windows vertical slice (WinAFL/DrAFL) is on the roadmap.
- **C coverage** — Atheris instruments Python bytecode only; C library internals (libjpeg, libpng) get indirect coverage via Python wrappers. True C coverage requires a different instrumented build.
- **Single-machine** — No distributed fuzzing. Each machine runs independently.
- **No crash dedup across machines** — stack_hash is computed locally; cross-machine dedup requires shared DB.

## Development

```bash
# Run tests
pytest -q

# Run local CI (tests + fuzz gate)
bash scripts/ci_local.sh

# Lint
ruff check kavach/ tests/
```

## License

MIT
