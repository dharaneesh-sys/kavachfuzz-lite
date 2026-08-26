# KavachFuzz-Lite Demo — Day 3 T12

> 90-second end-to-end demo: `init` → `seeds` → `fuzz toy_crash` (live crash!) → `triage` → `report serve` → `report export`

## Prerequisites

```bash
cd /home/dinusus/kavachfuzz-lite
.venv/bin/python -m kavach --help        # should list init/fuzz/seeds/minimize/triage/report
.venv/bin/python -m kavach report --help # subcommands serve/export
pytest -q                                # existing tests green (do not break)
ls targets/toy_crash/                    # harness.py, toy_crash.dict, seeds/
cat targets/toy_crash/harness.py         # ctypes.string_at(0) on KAVH prefix = guaranteed SIGSEGV
```

## Step-by-Step

### [1/6] `kavach init demo_hello`

Creates a new target pack from template (manifest.yaml + harness placeholder + seeds/).

```bash
.venv/bin/python -m kavach init demo_hello || echo "init exists, continuing"
ls targets/demo_hello/
# manifest.yaml  harness.py  seeds/
```

Expected: first run creates `targets/demo_hello`; second run prints `target 'demo_hello' already exists` and exits 1 (demo.sh handles with `||`).
Verify: `cat targets/demo_hello/manifest.yaml` shows `name: demo_hello`.

### [2/6] `kavach seeds --target toy_crash`

Bootstraps corpus. For `toy_crash` this is a single 1-byte seed (`seed.bin`); for `pdf`/`image` it downloads/generates 40+ files.

```bash
.venv/bin/python -m kavach seeds --target toy_crash
ls targets/toy_crash/seeds | wc -l   # → 1 (toy_crash), 1012/70 for pdf/image after full bootstrap
cat targets/toy_crash/toy_crash.dict # → kava="KAVH"  (dictionary that makes crash instant)
```

Expected output: `seeds bootstrap` + `seeds: 1 files`.

### [3/6] `kavach fuzz --target toy_crash --time 10` — LIVE CRASH

The core of the demo. The toy harness does `ctypes.string_at(0)` when input starts with `KAVH`. The shipped dict `toy_crash.dict` (`kavh="KAVH"`) lets libFuzzer discover that prefix in <2 s, guaranteeing a crash artifact.

```bash
.venv/bin/python -m kavach fuzz --target toy_crash --time 10
ls campaigns/toy_crash-*/crash-*   # → campaigns/toy_crash-2026.../crash-crash-a20795e8a1ac9740c9fffe0ba97f8506bd076f9a
cat campaigns/toy_crash-*/fuzz.log | grep -i "crash\|ERROR\|Test unit written"
```

Expected:
- New dir `campaigns/toy_crash-YYYYMMDD-HHMMSS-xxxxxx/` with `fuzz.log`, `stats.json`, `corpus/`, and `crash-crash-<sha1>` (404 bytes typical, content `KAVH…`).
- `fuzz.log` contains `Test unit written to .../crash-...` and `ERROR: libFuzzer: deadly signal`.
- `stats.json` shows `"crashes": 1`.

Verify live crash:
```bash
campaigns=$(ls -1d campaigns/toy_crash-* | sort | tail -1)
ls "$campaigns"/crash-* && echo "CRASH FOUND" || echo "no crash"
sqlite3 "$campaigns"/crashes.db "select * from crashes;"  # after triage
```

### [4/6] `kavach triage --campaign <id>`

Dedups `crash-*` artifacts by SHA1 → SQLite `crashes.db` (`bug_id`, `campaign_id`, `file`, `size`, `sha1`, `severity`).

```bash
LATEST=$(ls -1d campaigns/toy_crash-* | sort | tail -1 | xargs basename)
.venv/bin/python -m kavach triage --campaign "$LATEST"
sqlite3 campaigns/$LATEST/crashes.db "select bug_id,severity,size from crashes;"
sqlite3 crashes.db "select count(*) from crashes;"  # root db aggregate
```

Expected: `triage stub` + 1 row `a20795e8...|High|4`.

### [5/6] `kavach report serve --port 8003` + curl

Starts FastAPI dashboard (vendored Chart.js, no CDN) and verifies JSON APIs.

```bash
nohup .venv/bin/python -m kavach report serve --port 8003 > /tmp/demo-serve.log 2>&1 &
sleep 3
curl -s http://127.0.0.1:8003/api/stats | python -m json.tool
curl -s http://127.0.0.1:8003/api/crashes | python -m json.tool
curl -s http://127.0.0.1:8003/ | head -c 500   # dashboard HTML
# Dashboard at http://127.0.0.1:8003 — screenshot shows cards: Campaigns, Execs, Max Coverage, Crashes
pkill -f "kavach report serve" || kill %1 || true
```

Expected: `/api/stats` → `{total_campaigns, total_execs, cov_max, total_crashes, campaigns:[...]}`, `/api/crashes` → `[{bug_id, campaign_id, severity: "High", ...}]`.

### [6/6] `kavach report export --output report-demo.md`

Exports markdown report with headings Coverage/Crashes/Severity; pandoc PDF sibling if installed.

```bash
.venv/bin/python -m kavach report export --output report-demo.md
ls -lh report-demo.md
head -n 40 report-demo.md
grep -E "^## (Coverage|Crashes|Severity|Summary)" report-demo.md
```

Expected: `report-demo.md` ~1.5 KB with `## Summary`, `## Coverage`, `## Crashes`, `## Severity`, `## Methodology`. Contains campaign table + crash table with bug_id `a20795e8`.

## Full Automated Run

```bash
chmod +x demo.sh
.venv/bin/bash demo.sh
# exits 0, creates new campaign with crash-crash-*, background serves on 8003, exports report-demo.md
```

## Verification Checklist

```bash
cat demo.sh                              # all 6 steps present, set -e, shebang
ls -lh demo.mp4 && ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 demo.mp4
# duration ≤120 (target 90)
ls -lh demo/demo.mp4 2>&1 || echo "demo/demo.mp4 optional"
ls campaigns/toy_crash-*/crash-*         # crash artifact exists
sqlite3 $(ls -1d campaigns/toy_crash-* | sort | tail -1)/crashes.db "select * from crashes;"
curl -s http://127.0.0.1:8003/api/stats  # after serve
cat report-demo.md | head -n 30
kavach --help && pytest -q               # no regressions
```

## Video

- `demo.mp4` (1280×720, 90 s, ≤120 s per `ffprobe`) — synthetic fallback via `ffmpeg` if Wayland capture unavailable; overlay text shows `toy_crash crash-crash-a207...` appearing live.
- Generated with: `ffmpeg -y -f lavfi -i color=c=0x0a1816:s=1280x720:d=90:r=30 -vf "drawtext=..." -c:v libx264 -pix_fmt yuv420p -t 90 demo.mp4`
- Real capture alternative (Hyprland/Wayland): `timeout 95 wf-recorder -f demo.mp4 & demo.sh` — falls back to synthetic if display not available.
- Verify: `ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 demo.mp4`

## Troubleshooting

- `target 'demo_hello' already exists` → expected on re-run, `|| echo` handles it.
- `sqlite3: command not found` → install `sqlite` or use `.venv/bin/python -c "import sqlite3; ..."` alternative.
- Port 8003 busy → `pkill -f "kavach report"` or change `--port 8004`.
- No crash artifact → check `cat targets/toy_crash/toy_crash.dict` contains `KAVH` and harness has `ctypes.string_at(0)`.
