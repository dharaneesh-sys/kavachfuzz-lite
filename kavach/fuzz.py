"""Execution logic: real Atheris launch (T04)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4


def _project_root() -> Path:
    # kavach/fuzz.py -> project root is parent of kavach/
    return Path(__file__).resolve().parents[1]


def _ensure_seed(target: str, seeds_dir: Path) -> None:
    seeds_dir.mkdir(parents=True, exist_ok=True)
    if any(seeds_dir.iterdir()):
        return
    # Empty -> bootstrap minimal seed
    if target == "pdf":
        try:
            import pymupdf  # type: ignore

            doc = pymupdf.open()
            page = doc.new_page(width=200, height=200)
            page.insert_text((20, 50), "KavachFuzz seed")
            seed_path = seeds_dir / "seed1.pdf"
            doc.save(str(seed_path))
            doc.close()
            print(f"bootstrapped minimal pdf seed at {seed_path}")
        except Exception as e:
            # fallback: write minimal PDF header manually
            print(f"pymupdf bootstrap failed ({e}), writing raw PDF", file=sys.stderr)
            seed_path = seeds_dir / "seed1.pdf"
            seed_path.write_bytes(b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\nxref\n0 4\n0000000000 65535 f\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n0\n%%EOF")
    elif target == "image":
        try:
            from PIL import Image  # type: ignore

            img = Image.new("RGB", (64, 64), color=(120, 180, 200))
            seed_path = seeds_dir / "seed1.png"
            img.save(str(seed_path), format="PNG")
            print(f"bootstrapped minimal image seed at {seed_path}")
        except Exception as e:
            print(f"PIL bootstrap failed ({e})", file=sys.stderr)
            # raw minimal PNG (1x1 transparent) as fallback
            import base64

            raw = base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAB3RJTUUH6AQWECsZq3B2WQAAABl0RVh0Q29tbWVudABDcmVhdGVkIHdpdGggR0lNUFeBDhAAAAF0SURBVFjD7dMxCsAgDETRq/3/p2M7FhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhb2B2yAH3kDG4AAAAASUVORK5CYII="
            )
            (seeds_dir / "seed1.png").write_bytes(raw)
    else:
        # generic: single byte seed
        (seeds_dir / "seed1.bin").write_bytes(b"\x00")


def _ensure_dict(target: str, dict_path: str | None) -> str | None:
    # If explicit dict_path provided
    if dict_path:
        dp = Path(dict_path)
        if dp.exists():
            return str(dp.resolve())
        print(f"warning: dict_path {dict_path} not found, ignoring", file=sys.stderr)
        # fall through to auto-detect

    project_root = _project_root()
    target_dir = project_root / "targets" / target
    # also support cwd relative
    if not target_dir.exists():
        target_dir = Path("targets") / target

    candidates = [
        target_dir / f"{target}.dict",
        target_dir / ".dict",
        target_dir / "dict",
    ]
    for c in candidates:
        if c.exists():
            return str(c.resolve())

    # No dict found -> create minimal dict per target
    if target == "pdf":
        dict_file = target_dir / "pdf.dict"
        content = (
            'header_pdf="%%PDF"\n'
            'header_obj="obj"\n'
            'header_endobj="endobj"\n'
            'header_trailer="trailer"\n'
            'header_xref="xref"\n'
        )
        try:
            dict_file.parent.mkdir(parents=True, exist_ok=True)
            dict_file.write_text(content)
            print(f"created minimal dict at {dict_file}")
            return str(dict_file.resolve())
        except Exception as e:
            print(f"failed to create pdf dict: {e}", file=sys.stderr)
            return None
    elif target == "image":
        dict_file = target_dir / "image.dict"
        content = (
            'header_png="\\x89PNG"\n'
            'header_jpeg="\\xFF\\xD8\\xFF"\n'
            'header_gif="GIF89a"\n'
            'header_bmp="BM"\n'
        )
        try:
            dict_file.parent.mkdir(parents=True, exist_ok=True)
            dict_file.write_text(content)
            print(f"created minimal dict at {dict_file}")
            return str(dict_file.resolve())
        except Exception as e:
            print(f"failed to create image dict: {e}", file=sys.stderr)
            return None
    else:
        return None


def _parse_stats(log_text: str) -> tuple[int, int, int, int]:
    """Parse fuzz.log for cov_max, ft_max, corp_max, execs_estimated.

    Handles crash-truncated logs: reads last cov: line even without DONE.
    """
    cov_max = 0
    ft_max = 0
    corp_max = 0
    execs_estimated = 0
    pat = re.compile(r"#(\d+).*cov:\s*(\d+).*?ft:\s*(\d+).*?corp:\s*(\d+)")
    pat_no_ft = re.compile(r"#(\d+).*cov:\s*(\d+).*?corp:\s*(\d+)")
    done_pat = re.compile(r"Done\s+(\d+)\s+runs")
    for line in log_text.splitlines():
        m = pat.search(line)
        if m:
            try:
                cov_max = max(cov_max, int(m.group(2)))
                ft_max = max(ft_max, int(m.group(3)))
                corp_max = max(corp_max, int(m.group(4)))
            except ValueError:
                pass
            try:
                execs_estimated = max(execs_estimated, int(m.group(1)))
            except ValueError:
                pass
            continue
        m2 = pat_no_ft.search(line)
        if m2:
            try:
                cov_max = max(cov_max, int(m2.group(2)))
                corp_max = max(corp_max, int(m2.group(3)))
            except ValueError:
                pass
            try:
                execs_estimated = max(execs_estimated, int(m2.group(1)))
            except ValueError:
                pass
            continue
        dm = done_pat.search(line)
        if dm:
            try:
                execs_estimated = max(execs_estimated, int(dm.group(1)))
            except ValueError:
                pass
    return cov_max, ft_max, corp_max, execs_estimated


def run_fuzz(
    target: str,
    time: int,
    max_len: int,
    dict_path: str | None,
    artifact_prefix: str | None,
    workers: int = 1,
) -> int:
    project_root = _project_root()
    # Also handle cwd-based paths for test contexts
    harness = project_root / "targets" / target / "harness.py"
    if not harness.exists():
        harness = Path(f"targets/{target}/harness.py")
    if not harness.exists():
        print(f"error: harness not found for target '{target}' at targets/{target}/harness.py", file=sys.stderr)
        return 1

    seeds_dir = project_root / "targets" / target / "seeds"
    if not seeds_dir.exists():
        seeds_dir = Path(f"targets/{target}/seeds")
    _ensure_seed(target, seeds_dir)
    # re-resolve absolute
    seeds_dir_abs = seeds_dir.resolve()
    if not seeds_dir_abs.exists():
        seeds_dir_abs = Path(f"targets/{target}/seeds").resolve()

    # Campaign dir
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
    campaign_id = f"{target}-{timestamp}"
    campaign_dir = project_root / "campaigns" / campaign_id
    # fallback to cwd if project_root campaigns not writable
    try:
        campaign_dir.mkdir(parents=True, exist_ok=False)
        (campaign_dir / "corpus").mkdir(parents=True, exist_ok=True)
    except Exception:
        campaign_dir = Path("campaigns") / campaign_id
        campaign_dir.mkdir(parents=True, exist_ok=True)
        (campaign_dir / "corpus").mkdir(parents=True, exist_ok=True)

    campaign_dir_abs = campaign_dir.resolve()

    # Dict
    dict_file = _ensure_dict(target, dict_path)

    # Resolve python binary
    # Resolve python binary - use .venv/bin/python WITHOUT resolving symlink (preserves venv)
    venv_python = project_root / ".venv" / "bin" / "python"
    if not venv_python.exists():
        venv_python = Path(".venv/bin/python")
    if venv_python.exists():
        # Do NOT use resolve() - it follows symlink to base interpreter and loses venv site-packages
        python_bin = str(venv_python.absolute())
    else:
        python_bin = sys.executable

    harness_abs = harness.resolve()
    # artifact prefix
    if artifact_prefix:
        ap = str(Path(artifact_prefix).resolve()) if not Path(artifact_prefix).is_absolute() else str(Path(artifact_prefix))
        # Ensure prefix ends appropriately; if user gave dir, ensure trailing
        # libFuzzer expects prefix including filename prefix like /path/crash-
        artifact_arg = ap
    else:
        artifact_arg = str(campaign_dir_abs / "crash-")

    corpus_dir = campaign_dir_abs / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    # N02: corpus dir (write target) is first arg; seeds dir (read-only) is second
    cmd = [
        python_bin,
        str(harness_abs),
        str(corpus_dir),
        str(seeds_dir_abs),
        f"-max_len={max_len}",
        "-close_fd_mask=3",
        f"-artifact_prefix={artifact_arg}",
        f"-max_total_time={time}",
    ]
    if dict_file:
        cmd.append(f"-dict={dict_file}")
    if workers > 1:
        cmd.append(f"-jobs={workers}")
        cmd.append(f"-workers={workers}")

    print(f"Campaign {campaign_id}: launching {' '.join(cmd)}")
    fuzz_log = campaign_dir / "fuzz.log"
    fuzz_log_abs = campaign_dir_abs / "fuzz.log"

    env = os.environ.copy()
    # Ensure project root on PYTHONPATH so harness imports work
    pp = str(project_root)
    if "PYTHONPATH" in env and env["PYTHONPATH"]:
        env["PYTHONPATH"] = pp + os.pathsep + env["PYTHONPATH"]
    else:
        env["PYTHONPATH"] = pp

    # Run - timeout must account for instrumentation overhead (~10s per this machine, +30s worst per plan)
    timeout_sec = time + 60
    try:
        # Use subprocess.run capturing output
        result = subprocess.run(
            cmd,
            cwd=str(project_root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_sec,
            text=True,
        )
        output = result.stdout or ""
        # Write to fuzz.log
        try:
            fuzz_log.write_text(output, encoding="utf-8", errors="replace")
        except Exception:
            fuzz_log_abs.write_text(output, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            # libFuzzer may exit non-zero on timeout? Actually timeout is normal 0
            # If crash found, also non-zero; still success for campaign
            print(f"harness exited with code {result.returncode} (crash may have been found)")
    except subprocess.TimeoutExpired as e:
        out = ""
        if e.stdout:
            out += e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout)
        if e.stderr:
            out += e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr)
        # Also try to capture partial
        try:
            combined = (e.stdout or b"")
            if isinstance(combined, bytes):
                combined = combined.decode(errors="replace")
            if isinstance(e.stderr, bytes):
                combined += e.stderr.decode(errors="replace")
            elif e.stderr:
                combined += str(e.stderr)
            output = combined
        except Exception:
            output = out
        try:
            # If subprocess timed out, we still may have output captured via file?
            # Write what we have
            if output:
                fuzz_log.write_text(output, encoding="utf-8", errors="replace")
            else:
                # Try to read if process wrote directly?
                pass
            print(f"campaign timed out after {timeout_sec}s (expected for max_total_time)", file=sys.stderr)
        except Exception as we:
            print(f"failed to write fuzz.log after timeout: {we}", file=sys.stderr)
            output = ""
    except Exception as e:
        print(f"failed to launch harness: {e}", file=sys.stderr)
        return 1

    # Ensure fuzz.log exists and parse
    log_text = ""
    if fuzz_log.exists():
        try:
            log_text = fuzz_log.read_text(encoding="utf-8", errors="replace")
        except Exception:
            log_text = ""
    elif fuzz_log_abs.exists():
        try:
            log_text = fuzz_log_abs.read_text(encoding="utf-8", errors="replace")
        except Exception:
            log_text = ""
    else:
        print(f"warning: fuzz.log not found at {fuzz_log}", file=sys.stderr)
        log_text = output if "output" in locals() else ""

    # N05: if multi-worker, also read per-worker logs and merge stats
    combined_log = log_text
    if workers > 1:
        for worker_idx in range(workers):
            worker_log = campaign_dir_abs / f"fuzz-{worker_idx}.log"
            if worker_log.exists():
                try:
                    wl = worker_log.read_text(encoding="utf-8", errors="replace")
                    combined_log += "\n" + wl
                except Exception:
                    pass

    cov_max, ft_max, corp_max, execs_estimated = _parse_stats(combined_log)
    # Try to estimate execs from log if still 0: count # lines * scale? Already attempted via #N
    # Also look for exec/s lines to approximate, fallback to parsing INITED/DONE
    if execs_estimated == 0:
        # Count # lines as proxy
        hash_lines = len(re.findall(r"^#\d+", log_text, flags=re.MULTILINE))
        if hash_lines > 0:
            execs_estimated = hash_lines * 100  # rough

    # Count crash artifacts
    crash_count = 0
    try:
        # campaign_dir may be project_root/campaigns/id or cwd
        for p in campaign_dir.glob("crash-*"):
            if p.is_file():
                crash_count += 1
        for p in campaign_dir_abs.glob("crash-*"):
            if p.is_file() and p not in list(campaign_dir.glob("crash-*")):
                crash_count += 1
    except Exception:
        pass

    # N03: determine status from log content and crash count
    status = "completed"
    log_lower = log_text.lower()
    if crash_count > 0:
        status = "crashed"
    elif "timeout" in log_lower or "timed out" in log_lower:
        status = "timeout"

    stats = {
        "target": target,
        "id": campaign_id,
        "time": time,
        "max_len": max_len,
        "cov_max": cov_max,
        "ft_max": ft_max,
        "corp_max": corp_max,
        "execs_estimated": execs_estimated,
        "crashes": crash_count,
        "dict": dict_file,
        "campaign_dir": str(campaign_dir_abs),
        "status": status,
    }
    stats_path = campaign_dir / "stats.json"
    stats_path_abs = campaign_dir_abs / "stats.json"
    try:
        stats_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    except Exception:
        try:
            stats_path_abs.write_text(json.dumps(stats, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"failed to write stats.json: {e}", file=sys.stderr)

    print(f"Campaign {campaign_id}: status={status} cov {cov_max} ft {ft_max} corp {corp_max} execs ~{execs_estimated}, artifacts: {crash_count} crashes")
    # N03: only warn if coverage is zero AND we have no crash (toy_crash can legitimately have cov 0)
    if cov_max == 0 and corp_max == 0 and crash_count == 0:
        print(f"warning: no coverage data parsed from {fuzz_log} - check harness instrumentation", file=sys.stderr)
    return 0
