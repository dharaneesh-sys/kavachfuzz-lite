"""KavachFuzz-Lite reporting: dashboard v2 + export (N11)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _gather_stats() -> dict[str, Any]:
    root = _project_root()
    campaigns_root = root / "campaigns"
    campaigns: list[dict[str, Any]] = []
    total_execs = 0
    total_crashes = 0
    cov_max = 0
    if campaigns_root.exists():
        for stats_path in sorted(campaigns_root.glob("*/stats.json")):
            try:
                data = json.loads(stats_path.read_text())
                campaigns.append(data)
                total_execs += int(data.get("execs_estimated", 0) or 0)
                total_crashes += int(data.get("crashes", 0) or 0)
                cov_max = max(cov_max, int(data.get("cov_max", 0) or 0))
            except Exception:
                continue
        for camp_dir in campaigns_root.iterdir():
            if not camp_dir.is_dir():
                continue
            if any(camp_dir.glob("stats.json")):
                continue
            fuzz_log = camp_dir / "fuzz.log"
            if fuzz_log.exists():
                try:
                    import re
                    text = fuzz_log.read_text(errors="replace")
                    cov = max([int(m) for m in re.findall(r"cov:\s*(\d+)", text)] or [0])
                    campaigns.append({
                        "id": camp_dir.name,
                        "target": camp_dir.name.split("-")[0] if "-" in camp_dir.name else "unknown",
                        "cov_max": cov,
                        "execs_estimated": 0,
                        "crashes": len(list(camp_dir.glob("crash-*"))),
                    })
                    cov_max = max(cov_max, cov)
                    total_crashes += len(list(camp_dir.glob("crash-*")))
                except Exception:
                    pass
    return {
        "campaigns": campaigns,
        "total_campaigns": len(campaigns),
        "total_execs": total_execs,
        "total_crashes": total_crashes,
        "cov_max": cov_max,
        "generated_at": datetime.now().isoformat(),
    }


def _gather_crashes() -> list[dict[str, Any]]:
    root = _project_root()
    dbs: list[Path] = []
    root_db = root / "crashes.db"
    if root_db.exists():
        dbs.append(root_db)
    for p in (root / "campaigns").glob("*/crashes.db"):
        if p not in dbs:
            dbs.append(p)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for db in dbs:
        try:
            con = sqlite3.connect(str(db))
            con.row_factory = sqlite3.Row
            cur = con.execute(
                "SELECT bug_id, campaign_id, file, size, sha1, stack_hash, frames, taxonomy, severity, created_at FROM crashes"
            )
            for r in cur.fetchall():
                bug_id = r["bug_id"]
                if bug_id in seen:
                    continue
                seen.add(bug_id)
                entry: dict[str, Any] = {
                    "bug_id": r["bug_id"],
                    "campaign_id": r["campaign_id"],
                    "file": r["file"],
                    "size": r["size"],
                    "sha1": r["sha1"],
                    "severity": r["severity"],
                    "created_at": r["created_at"],
                }
                try:
                    entry["stack_hash"] = r["stack_hash"]
                    entry["taxonomy"] = r["taxonomy"]
                    entry["frames"] = r["frames"]
                except Exception:
                    pass
                rows.append(entry)
            con.close()
        except Exception:
            continue
    if not rows:
        for camp_dir in (root / "campaigns").iterdir():
            if not camp_dir.is_dir():
                continue
            for crash_file in camp_dir.glob("crash-*"):
                if crash_file.is_file():
                    try:
                        import hashlib
                        sha1 = hashlib.sha1(crash_file.read_bytes()).hexdigest()
                        rows.append({
                            "bug_id": sha1,
                            "campaign_id": camp_dir.name,
                            "file": str(crash_file.relative_to(root)),
                            "size": crash_file.stat().st_size,
                            "sha1": sha1,
                            "severity": "High",
                            "created_at": datetime.now().isoformat(),
                        })
                    except Exception:
                        pass
    return rows


_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KavachFuzz-Lite Dashboard</title>
<meta http-equiv="refresh" content="5">
<style>
:root { --bg:#0a1816; --surface:#152a26; --primary:#7ad9a8; --text:#e8f5f0; --muted:#8aa99e; }
*{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text)}
header{padding:24px 32px;background:var(--surface);border-bottom:1px solid #1e3a34;display:flex;align-items:center;gap:16px}
header h1{margin:0;font-size:22px;letter-spacing:-0.02em} header span{color:var(--muted);font-size:13px}
.container{max-width:1200px;margin:24px auto;padding:0 24px;display:grid;gap:24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.card{background:var(--surface);border:1px solid #1e3a34;border-radius:12px;padding:16px}
.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.06em}
.card .value{font-size:28px;font-weight:700;margin-top:4px}
.card .value small{font-size:13px;color:var(--muted);font-weight:500}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid #1e3a34;border-radius:12px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;font-size:13px;border-bottom:1px solid #1e3a34}
th{background:#0f2a24;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.05em;font-size:11px}
tr:last-child td{border-bottom:none}
.badge{padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600}
.badge-High{background:#3a1a1a;color:#ff8f8f;border:1px solid #5a2a2a}
.badge-Medium{background:#2a2a1a;color:#dbd88f;border:1px solid #5a5a2a}
.badge-Low{background:#1a2a1a;color:#8fdb8f;border:1px solid #2a5a2a}
canvas{background:var(--surface);border:1px solid #1e3a34;border-radius:12px;padding:12px}
footer{color:var(--muted);text-align:center;padding:24px;font-size:12px}
a{color:var(--primary);text-decoration:none} a:hover{text-decoration:underline}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:24px}
</style>
</head>
<body>
<header>
  <div style="width:36px;height:36px;background:var(--primary);border-radius:8px;display:grid;place-items:center;color:#0a1816;font-weight:800">K</div>
  <div><h1>KavachFuzz-Lite</h1><span>Coverage-guided fuzzing &bull; local dashboard</span></div>
  <div style="margin-left:auto;display:flex;gap:12px">
    <a href="/api/stats" target="_blank">/api/stats</a>
    <a href="/api/crashes" target="_blank">/api/crashes</a>
  </div>
</header>
<div class="container">
  <div class="cards" id="cards"></div>
  <div class="grid2">
    <div><h3 style="margin:0 0 8px;font-size:14px;color:var(--muted)">Coverage trend (cov vs iteration)</h3><canvas id="trendChart" height="240"></canvas></div>
    <div><h3 style="margin:0 0 8px;font-size:14px;color:var(--muted)">Severity breakdown</h3><canvas id="sevChart" height="240"></canvas></div>
  </div>
  <div>
    <h3 style="font-size:14px;color:var(--muted)">Campaigns</h3>
    <table id="campTable"><thead><tr><th>ID</th><th>Target</th><th>Cov</th><th>Corp</th><th>Execs</th><th>Crashes</th><th>Status</th><th>Time</th></tr></thead><tbody></tbody></table>
  </div>
  <div>
    <h3 style="font-size:14px;color:var(--muted)">Stack-hash groups (crashes sharing same root cause)</h3>
    <table id="stackTable"><thead><tr><th>Stack Hash</th><th>Taxonomy</th><th>Severity</th><th>Count</th><th>Bug IDs</th></tr></thead><tbody></tbody></table>
  </div>
  <div>
    <h3 style="font-size:14px;color:var(--muted)">Crashes (triaged)</h3>
    <table id="crashTable"><thead><tr><th>Bug ID</th><th>Stack</th><th>Taxonomy</th><th>Campaign</th><th>Severity</th><th>Size</th><th>File</th></tr></thead><tbody></tbody></table>
  </div>
</div>
<footer>KavachFuzz-Lite &bull; auto-refresh 5s &bull; vendored Chart.js &bull; <span id="generated"></span></footer>
<script src="/static/chart.min.js"></script>
<script>
async function load(){
  const stats = await fetch('/api/stats').then(r=>r.json());
  const crashes = await fetch('/api/crashes').then(r=>r.json());
  document.getElementById('generated').textContent = new Date(stats.generated_at).toLocaleString();
  const totalExecs = stats.total_execs || 0;
  const totalCrashes = stats.total_crashes ?? crashes.length;
  const covMax = stats.cov_max || 0;
  const sevCounts = {};
  crashes.forEach(c=>{const s=c.severity||'Unknown';sevCounts[s]=(sevCounts[s]||0)+1});
  document.getElementById('cards').innerHTML = `
    <div class="card"><div class="label">Campaigns</div><div class="value">${stats.total_campaigns}</div></div>
    <div class="card"><div class="label">Total Execs</div><div class="value">${totalExecs.toLocaleString()}</div></div>
    <div class="card"><div class="label">Max Coverage</div><div class="value">${covMax} <small>edges</small></div></div>
    <div class="card"><div class="label">Crashes</div><div class="value">${totalCrashes} <small>${sevCounts['High']||0} High</small></div></div>
  `;
  // Campaign table
  const campBody = document.querySelector('#campTable tbody');
  campBody.innerHTML = stats.campaigns.map(c=>`
    <tr>
      <td><a href="/campaign/${c.id}"><code>${c.id}</code></a></td>
      <td>${c.target || '-'}</td>
      <td>${c.cov_max ?? '-'}</td>
      <td>${c.corp_max ?? '-'}</td>
      <td>${(c.execs_estimated||0).toLocaleString()}</td>
      <td>${c.crashes ?? 0}</td>
      <td><span class="badge badge-${c.status==='crashed'?'High':'Low'}">${c.status||'completed'}</span></td>
      <td>${c.time ?? '-' }s</td>
    </tr>
  `).join('') || '<tr><td colspan=8 style="color:var(--muted);text-align:center">No campaigns yet</td></tr>';
  // Crash table
  const crashBody = document.querySelector('#crashTable tbody');
  crashBody.innerHTML = crashes.map(c=>`
    <tr>
      <td><code title="${c.sha1}">${c.bug_id.slice(0,12)}</code></td>
      <td><code title="${c.frames||''}">${(c.stack_hash||'').slice(0,12)}</code></td>
      <td>${c.taxonomy||'-'}</td>
      <td>${c.campaign_id}</td>
      <td><span class="badge badge-${c.severity}">${c.severity}</span></td>
      <td>${c.size} B</td>
      <td><code>${c.file}</code></td>
    </tr>
  `).join('') || '<tr><td colspan=7 style="color:var(--muted);text-align:center">No crashes triaged &mdash; clean bill</td></tr>';
  // Charts
  const labels = stats.campaigns.map(c=>c.id.slice(0,16));
  if(window.Chart && labels.length){
    // Trend chart: coverage timeseries per campaign
    const datasets = [];
    const colors = ['#7ad9a8','#6bc4a0','#5aef98','#4a98ff','#ff8f8f','#ffd700','#c084fc'];
    stats.campaigns.forEach((c,i)=>{
      const ts = c.timeseries || [];
      if(ts.length > 0){
        datasets.push({
          label: c.id.slice(0,20),
          data: ts.map(t=>({x:t.t, y:t.cov})),
          borderColor: colors[i % colors.length],
          backgroundColor: 'transparent',
          tension: 0.3,
          pointRadius: 1,
        });
      } else {
        datasets.push({
          label: c.id.slice(0,20),
          data: [{x:0,y:0},{x:1,y:c.cov_max||0}],
          borderColor: colors[i % colors.length],
          backgroundColor: 'transparent',
          tension: 0.3,
          borderDash: [5,5],
        });
      }
    });
    new Chart(document.getElementById('trendChart'), {
      type:'line',
      data:{datasets},
      options:{responsive:true, plugins:{legend:{labels:{color:'#8aa99e',font:{size:10}}}},
        scales:{x:{type:'linear',title:{display:true,text:'iteration',color:'#8aa99e'},ticks:{color:'#8aa99e'}}, y:{title:{display:true,text:'coverage',color:'#8aa99e'},ticks:{color:'#8aa99e'}}}}
    });
    // Severity donut
    const sevLabels = Object.keys(sevCounts);
    const sevData = Object.values(sevCounts);
    const sevColors = sevLabels.map(s=>s==='High'?'#ff8f8f':s==='Medium'?'#ffd700':'#8fdb8f');
    if(sevLabels.length){
      new Chart(document.getElementById('sevChart'), {
        type:'doughnut',
        data:{labels:sevLabels, datasets:[{data:sevData, backgroundColor:sevColors, borderColor:'#152a26', borderWidth:2}]},
        options:{responsive:true, plugins:{legend:{labels:{color:'#8aa99e'}}}}
      });
    }
  }
  // Stack-hash groups (client-side from crashes data)
  const stackGroups = {};
  crashes.forEach(c=>{
    const sh = c.stack_hash || '';
    if(!sh) return;
    if(!stackGroups[sh]) stackGroups[sh] = {stack_hash:sh, taxonomy:c.taxonomy||'-', severity:c.severity||'-', count:0, bug_ids:[]};
    stackGroups[sh].count++;
    stackGroups[sh].bug_ids.push(c.bug_id.slice(0,12));
  });
  const stackBody = document.querySelector('#stackTable tbody');
  const stackArr = Object.values(stackGroups).sort((a,b)=>b.count-a.count);
  stackBody.innerHTML = stackArr.map(g=>`
    <tr>
      <td><code>${g.stack_hash}</code></td>
      <td>${g.taxonomy}</td>
      <td><span class="badge badge-${g.severity}">${g.severity}</span></td>
      <td>${g.count}</td>
      <td><code>${g.bug_ids.join(', ')}</code></td>
    </tr>
  `).join('') || '<tr><td colspan=5 style="color:var(--muted);text-align:center">No stack groups</td></tr>';
}
load().catch(e=>{document.body.innerHTML+='<pre style="color:#ff8f8f;padding:24px">'+e+'</pre>'});
</script>
</body>
</html>"""


def _campaign_detail_html(campaign_id: str) -> str:
    root = _project_root()
    campaign_dir = root / "campaigns" / campaign_id
    stats: dict[str, Any] = {}
    stats_path = campaign_dir / "stats.json"
    if stats_path.exists():
        try:
            stats = json.loads(stats_path.read_text())
        except Exception:
            pass

    # Get crashes for this campaign
    crashes: list[dict[str, Any]] = []
    db_path = campaign_dir / "crashes.db"
    if db_path.exists():
        try:
            con = sqlite3.connect(str(db_path))
            con.row_factory = sqlite3.Row
            for r in con.execute("SELECT * FROM crashes").fetchall():
                crashes.append(dict(r))
            con.close()
        except Exception:
            pass

    ts_data = json.dumps(stats.get("timeseries", []))
    crashes_json = json.dumps(crashes)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Campaign: {campaign_id}</title>
<meta http-equiv="refresh" content="5">
<style>
:root {{ --bg:#0a1816; --surface:#152a26; --primary:#7ad9a8; --text:#e8f5f0; --muted:#8aa99e; }}
*{{box-sizing:border-box}} body{{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text)}}
header{{padding:24px 32px;background:var(--surface);border-bottom:1px solid #1e3a34;display:flex;align-items:center;gap:16px}}
header h1{{margin:0;font-size:22px;letter-spacing:-0.02em}}
.container{{max-width:1100px;margin:24px auto;padding:0 24px;display:grid;gap:24px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}}
.card{{background:var(--surface);border:1px solid #1e3a34;border-radius:12px;padding:16px}}
.card .label{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.06em}}
.card .value{{font-size:28px;font-weight:700;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid #1e3a34;border-radius:12px;overflow:hidden}}
th,td{{padding:10px 12px;text-align:left;font-size:13px;border-bottom:1px solid #1e3a34}}
th{{background:#0f2a24;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.05em;font-size:11px}}
.badge{{padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600}}
.badge-High{{background:#3a1a1a;color:#ff8f8f;border:1px solid #5a2a2a}}
.badge-Low{{background:#1a2a1a;color:#8fdb8f;border:1px solid #2a5a2a}}
canvas{{background:var(--surface);border:1px solid #1e3a34;border-radius:12px;padding:12px}}
a{{color:var(--primary);text-decoration:none}} a:hover{{text-decoration:underline}}
</style>
</head>
<body>
<header>
  <a href="/" style="color:var(--primary);text-decoration:none">&larr; Dashboard</a>
  <h1>Campaign: {campaign_id}</h1>
</header>
<div class="container">
  <div class="cards">
    <div class="card"><div class="label">Target</div><div class="value">{stats.get('target','-')}</div></div>
    <div class="card"><div class="label">Coverage</div><div class="value">{stats.get('cov_max',0)}</div></div>
    <div class="card"><div class="label">Corpus</div><div class="value">{stats.get('corp_max',0)}</div></div>
    <div class="card"><div class="label">Execs</div><div class="value">{stats.get('execs_estimated',0):,}</div></div>
    <div class="card"><div class="label">Crashes</div><div class="value">{stats.get('crashes',0)}</div></div>
    <div class="card"><div class="label">Status</div><div class="value">{stats.get('status','-')}</div></div>
  </div>
  <div><h3 style="margin:0 0 8px;font-size:14px;color:var(--muted)">Coverage over time</h3><canvas id="tsChart" height="200"></canvas></div>
  <div>
    <h3 style="font-size:14px;color:var(--muted)">Crashes</h3>
    <table><thead><tr><th>Bug ID</th><th>Stack</th><th>Taxonomy</th><th>Severity</th><th>Size</th><th>File</th></tr></thead><tbody id="crashBody"></tbody></table>
  </div>
</div>
<script src="/static/chart.min.js"></script>
<script>
const ts = {ts_data};
const crashes = {crashes_json};
if(window.Chart && ts.length){{
  new Chart(document.getElementById('tsChart'), {{
    type:'line',
    data:{{labels:ts.map(t=>t.t), datasets:[{{label:'Coverage', data:ts.map(t=>t.cov), borderColor:'#7ad9a8', backgroundColor:'rgba(122,217,168,0.15)', tension:0.3, fill:true}}]}},
    options:{{responsive:true, plugins:{{legend:{{labels:{{color:'#8aa99e'}}}}}}, scales:{{x:{{title:{{display:true,text:'iteration',color:'#8aa99e'}},ticks:{{color:'#8aa99e'}}}}, y:{{title:{{display:true,text:'coverage',color:'#8aa99e'}},ticks:{{color:'#8aa99e'}}}}}}}}
  }});
}}
document.getElementById('crashBody').innerHTML = crashes.map(c=>`
  <tr>
    <td><code>${{c.bug_id?.slice(0,12)}}</code></td>
    <td><code title="${{c.frames||''}}">${{(c.stack_hash||'').slice(0,12)}}</code></td>
    <td>${{c.taxonomy||'-'}}</td>
    <td><span class="badge badge-${{c.severity}}">${{c.severity}}</span></td>
    <td>${{c.size}} B</td>
    <td><code>${{c.file}}</code></td>
  </tr>
`).join('') || '<tr><td colspan=6 style="color:var(--muted);text-align:center">No crashes</td></tr>';
</script>
</body>
</html>"""


def serve_report(host: str = "127.0.0.1", port: int = 8000) -> None:
    root = _project_root()
    static_dir = root / "kavach" / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    chart_path = static_dir / "chart.min.js"
    if not chart_path.exists():
        chart_path.write_text("window.Chart = window.Chart || function(){};")
    app = FastAPI(title="KavachFuzz-Lite")

    @app.get("/api/stats")
    def api_stats():
        return JSONResponse(_gather_stats())

    @app.get("/api/crashes")
    def api_crashes():
        return JSONResponse(_gather_crashes())

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return HTMLResponse(_DASHBOARD_HTML)

    @app.get("/campaign/{campaign_id}", response_class=HTMLResponse)
    def campaign_detail(campaign_id: str):
        return HTMLResponse(_campaign_detail_html(campaign_id))

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    print(f"Serving KavachFuzz-Lite dashboard at http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")


def export_report(output: str = "report.md") -> None:
    root = _project_root()
    stats = _gather_stats()
    crashes = _gather_crashes()
    sev_counts: dict[str, int] = {}
    for c in crashes:
        sev = c.get("severity", "High")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    out_path = Path(output)
    if not out_path.is_absolute():
        out_path = root / out_path
    lines: list[str] = []
    lines.append("# KavachFuzz-Lite Report")
    lines.append("")
    lines.append(f"_Generated: {datetime.now().isoformat()}  •  Host: {_project_root().name}_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Campaigns:** {stats.get('total_campaigns', 0)}")
    lines.append(f"- **Total Execs:** {stats.get('total_execs', 0)}")
    lines.append(f"- **Max Coverage:** {stats.get('cov_max', 0)} edges")
    lines.append(f"- **Total Crashes:** {stats.get('total_crashes', len(crashes))} ({len(crashes)} unique)")
    lines.append(f"- **Severity:** {', '.join(f'{k}: {v}' for k, v in sev_counts.items()) if sev_counts else 'none'}")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append("| Campaign | Target | Cov | FT | Corp | Execs | Crashes | Time |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for c in stats.get("campaigns", []):
        lines.append(
            f"| {c.get('id','-')} | {c.get('target','-')} | {c.get('cov_max',0)} | {c.get('ft_max',0)} | {c.get('corp_max',0)} | {c.get('execs_estimated',0)} | {c.get('crashes',0)} | {c.get('time',0)}s |"
        )
    if not stats.get("campaigns"):
        lines.append("| _no campaigns_ | - | - | - | - | - | - | - |")
    lines.append("")
    lines.append("## Crashes")
    lines.append("")
    lines.append("| Bug ID | Stack Hash | Taxonomy | Campaign | Severity | Size | File |")
    lines.append("|---|---|---|---|---|---|---|")
    for c in crashes:
        lines.append(
            f"| `{c.get('bug_id','')[:12]}` | `{c.get('stack_hash','')[:12]}` | {c.get('taxonomy','-')} | {c.get('campaign_id','')} | {c.get('severity','')} | {c.get('size',0)} | `{c.get('file','')}` |"
        )
    if not crashes:
        lines.append("| _no crashes triaged_ | - | - | - | - | - | - |")
        lines.append("")
        lines.append("> Clean bill: no crashing inputs found in the executed campaigns.")
    lines.append("")
    lines.append("## Severity")
    lines.append("")
    for sev, cnt in sev_counts.items():
        lines.append(f"- **{sev}:** {cnt}")
    if not sev_counts:
        lines.append("- No crashes to classify")
    lines.append("")
    content = "\n".join(lines) + "\n"
    out_path.write_text(content, encoding="utf-8")
    print(f"Exported report to {out_path} ({len(content)} bytes, {len(crashes)} crashes)")
