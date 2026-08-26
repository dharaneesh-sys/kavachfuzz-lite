#!/usr/bin/env bash
set -e
echo "=== KavachFuzz-Lite Demo ==="
echo "[1/6] init demo target"
.venv/bin/python -m kavach init demo_hello || echo "init exists, continuing"
echo "[2/6] seeds bootstrap"
.venv/bin/python -m kavach seeds --target toy_crash
echo "seeds: $(ls targets/toy_crash/seeds | wc -l) files"
echo "[3/6] fuzz toy_crash (10s, guaranteed crash via KAVH dict)"
.venv/bin/python -m kavach fuzz --target toy_crash --time 10
echo "campaigns: $(ls campaigns/toy_crash-* | head)"
ls campaigns/toy_crash-*/crash-* 2>&1 | head
echo "[4/6] triage"
.venv/bin/python -m kavach triage --campaign $(ls -1d campaigns/toy_crash-* | sort | tail -1 | xargs basename)
sqlite3 $(ls -1d campaigns/toy_crash-* | sort | tail -1)/crashes.db "select * from crashes;"
echo "[5/6] report serve (background) + curl"
nohup .venv/bin/python -m kavach report serve --port 8003 > /tmp/demo-serve.log 2>&1 &
sleep 3
curl -s http://127.0.0.1:8003/api/stats | head -c 500
echo
curl -s http://127.0.0.1:8003/api/crashes | head -c 500
echo
echo "[6/6] report export"
.venv/bin/python -m kavach report export --output report-demo.md
ls -lh report-demo.md
echo "Demo complete"
