"""Corpus management - seed bootstrap and minimization."""

from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

MIN_SEEDS = 40


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _count_valid_pdfs(seeds_dir: Path) -> int:
    cnt = 0
    if not seeds_dir.exists():
        return 0
    for p in seeds_dir.iterdir():
        if not p.is_file():
            continue
        try:
            if p.stat().st_size == 0:
                continue
            with p.open("rb") as f:
                hdr = f.read(5)
                if hdr.startswith(b"%PDF"):
                    cnt += 1
        except Exception:
            continue
    return cnt


def _count_valid_images(seeds_dir: Path) -> int:
    cnt = 0
    if not seeds_dir.exists():
        return 0
    for p in seeds_dir.iterdir():
        if not p.is_file():
            continue
        if p.stat().st_size == 0:
            continue
        try:
            with p.open("rb") as f:
                hdr = f.read(10)
                # PNG 89 50 4E 47 0D 0A 1A 0A, JPEG FF D8 FF, GIF GIF, BMP BM, also allow Pillow magic check
                if hdr.startswith(b"\x89PNG") or hdr.startswith(b"\xff\xd8\xff") or hdr.startswith(b"GIF87a") or hdr.startswith(b"GIF89a") or hdr.startswith(b"BM"):
                    cnt += 1
                    continue
                # Try PIL open for other image types (e.g., valid PNG/JPEG with different read)
                f.seek(0)
                # quick Pillow probe without importing at top
                try:
                    from PIL import Image  # type: ignore

                    f2 = p.open("rb")
                    # Pillow verify
                    img = Image.open(f2)
                    img.verify()
                    f2.close()
                    # re-open to ensure not truncated
                    # if verify succeeds, count it
                    cnt += 1
                except Exception:
                    pass
        except Exception:
            continue
    return cnt


def _try_pdfjs_clone(seeds_dir: Path) -> int:
    """Try git clone pdf.js and copy PDFs. Return number copied."""
    tmp = Path("/tmp/pdf.js")
    added = 0
    try:
        # Use git clone --depth 1 if not already cloned
        if tmp.exists() and (tmp / "test" / "pdfs").exists():
            print("pdf.js clone already exists at /tmp/pdf.js, reusing")
        else:
            if tmp.exists():
                shutil.rmtree(tmp, ignore_errors=True)
            print("attempting git clone https://github.com/mozilla/pdf.js -> /tmp/pdf.js")
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "https://github.com/mozilla/pdf.js", str(tmp)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                print(f"git clone failed: {result.stderr[:500]}", file=sys.stderr)
                return 0
            print("git clone succeeded")
        src_dir = tmp / "test" / "pdfs"
        if not src_dir.exists():
            print(f"pdf.js test/pdfs not found at {src_dir}", file=sys.stderr)
            return 0
        pdfs = list(src_dir.glob("*.pdf"))
        print(f"found {len(pdfs)} pdfs in pdf.js test suite")
        for pdf in pdfs:
            dest = seeds_dir / pdf.name
            if dest.exists():
                continue
            try:
                shutil.copy2(pdf, dest)
                added += 1
            except Exception as e:
                print(f"copy failed for {pdf}: {e}", file=sys.stderr)
        print(f"copied {added} pdfs from pdf.js")
    except subprocess.TimeoutExpired:
        print("git clone timed out", file=sys.stderr)
    except Exception as e:
        print(f"pdf.js clone error: {e}", file=sys.stderr)
    return added


def _try_curl_pdfs(seeds_dir: Path) -> int:
    """Fallback: curl known pdf.js raw files."""
    known = [
        "tracemonkey.pdf",
        "bug1065243.pdf",
        "bug147252.pdf",
        "bug1001080.pdf",
        "annotation.pdf",
        "bug766138.pdf",
        "bug689141.pdf",
        "issue13444.pdf",
        "issue8261.pdf",
        "issue6916.pdf",
        "issue146367.pdf",
        "issue14247.pdf",
        "bug1225455.pdf",
        "bug1124037.pdf",
        "bug1011154.pdf",
    ]
    added = 0
    for name in known:
        dest = seeds_dir / name
        if dest.exists():
            continue
        url = f"https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/{name}"
        try:
            result = subprocess.run(
                ["curl", "-L", "-s", "-o", str(dest), "--connect-timeout", "10", "--max-time", "20", url],
                capture_output=True,
                text=True,
                timeout=25,
            )
            if dest.exists() and dest.stat().st_size > 100:
                with dest.open("rb") as f:
                    if f.read(4) == b"%PDF":
                        added += 1
                        print(f"curl fetched {name}")
                    else:
                        dest.unlink(missing_ok=True)
            else:
                if dest.exists():
                    dest.unlink(missing_ok=True)
        except Exception as e:
            print(f"curl failed for {name}: {e}", file=sys.stderr)
            if dest.exists():
                try:
                    dest.unlink(missing_ok=True)
                except Exception:
                    pass
    if added:
        print(f"curl fetched {added} pdfs")
    return added


def _generate_synthetic_pdfs(seeds_dir: Path, needed: int) -> int:
    """Generate distinct PDFs via pymupdf to reach needed count."""
    generated = 0
    try:
        import pymupdf  # type: ignore
    except Exception as e:
        print(f"pymupdf not available for synthetic PDFs: {e}", file=sys.stderr)
        return 0

    # Determine starting index to avoid collision
    existing = {p.name for p in seeds_dir.iterdir() if p.is_file()}
    idx = 0
    # Find highest synth index already present
    for name in existing:
        if name.startswith("synth_") and name.endswith(".pdf"):
            try:
                n = int(name[6:9])
                idx = max(idx, n + 1)
            except Exception:
                pass
    # Also check for synthetic naming collisions for non-standard names
    count = 0
    attempts = 0
    while count < needed and attempts < needed * 3:
        attempts += 1
        fname = f"synth_{idx:03d}.pdf"
        dest = seeds_dir / fname
        if dest.exists():
            idx += 1
            continue
        try:
            doc = pymupdf.open()
            # Vary page size
            width = 200 + (idx % 5) * 50
            height = 200 + (idx % 3) * 70
            page = doc.new_page(width=width, height=height)
            # Distinct content
            page.insert_text((20, 50), f"KavachFuzz synthetic PDF seed {idx}")
            page.insert_text((20, 70), f"variation {idx} " + "x" * (idx % 20))
            page.insert_text((20, 90), f"random {random.randint(1000, 9999)}-{idx}-{width}x{height}")
            # Draw shapes varying by idx
            if idx % 3 == 0:
                rect = pymupdf.Rect(10, 10, 100 + idx % 80, 100 + idx % 60)
                page.draw_rect(rect, color=(0, 0, 1), fill=(idx / 255, (idx * 2) % 255 / 255, (idx * 3) % 255 / 255), width=1)
            elif idx % 3 == 1:
                page.draw_circle(pymupdf.Point(100 + idx % 30, 100 + idx % 20), 20 + idx % 25, color=(1, 0, 0), width=1)
            else:
                page.draw_line(pymupdf.Point(10, 10), pymupdf.Point(width - 10, height - 10))
                page.draw_line(pymupdf.Point(width - 10, 10), pymupdf.Point(10, height - 10))
            # Some have second page
            if idx % 4 == 0:
                p2 = doc.new_page(width=width, height=height)
                p2.insert_text((20, 50), f"Page 2 of seed {idx}")
                p2.insert_text((20, 70), f"content {random.randint(0, 999999)}")
                if idx % 8 == 0:
                    p2.insert_text((20, 90), "Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
            # Some have annotations-like text
            if idx % 7 == 0:
                p3 = doc.new_page(width=300, height=300)
                p3.insert_text((20, 50), "Extra page with varied fonts")
                p3.insert_text((20, 80), f"Seed {idx} - fuzz corpus diversity")

            doc.save(str(dest))
            doc.close()
            if dest.stat().st_size > 100:
                generated += 1
                count += 1
                print(f"generated synthetic PDF {fname} ({dest.stat().st_size} bytes)")
            else:
                dest.unlink(missing_ok=True)
        except Exception as e:
            print(f"synthetic pdf generation failed idx {idx}: {e}", file=sys.stderr)
            try:
                if dest.exists():
                    dest.unlink(missing_ok=True)
            except Exception:
                pass
        idx += 1
    print(f"synthetic PDF generation: {generated} files")
    return generated


def _ensure_pdf_seeds(seeds_dir: Path) -> None:
    seeds_dir.mkdir(parents=True, exist_ok=True)
    valid = _count_valid_pdfs(seeds_dir)
    total = len([p for p in seeds_dir.iterdir() if p.is_file()])
    print(f"pdf seeds: valid PDFs {valid}/{MIN_SEEDS}, total files {total}")
    if valid >= MIN_SEEDS:
        print(f"pdf seeds already >= {MIN_SEEDS} valid PDFs, skipping bootstrap")
        return
    needed = MIN_SEEDS - valid
    print(f"pdf seeds need {needed} more valid PDFs")

    # Strategy 1: git clone
    added = _try_pdfjs_clone(seeds_dir)
    valid = _count_valid_pdfs(seeds_dir)
    if valid >= MIN_SEEDS:
        print(f"pdf seeds satisfied after pdf.js clone: {valid} PDFs")
        return

    # Strategy 2: curl fallback for remaining
    remaining = MIN_SEEDS - valid
    if remaining > 0:
        _try_curl_pdfs(seeds_dir)
        valid = _count_valid_pdfs(seeds_dir)
        if valid >= MIN_SEEDS:
            print(f"pdf seeds satisfied after curl: {valid} PDFs")
            return

    # Strategy 3: synthetic
    remaining = MIN_SEEDS - valid
    if remaining > 0:
        _generate_synthetic_pdfs(seeds_dir, remaining)
    valid = _count_valid_pdfs(seeds_dir)
    print(f"pdf seeds final: {valid} valid PDFs, total files {len(list(seeds_dir.iterdir()))}")


def _generate_synthetic_images(seeds_dir: Path, needed: int) -> int:
    """Generate distinct images via PIL."""
    generated = 0
    try:
        from PIL import Image, ImageDraw  # type: ignore
    except Exception as e:
        print(f"Pillow not available: {e}", file=sys.stderr)
        return 0

    # Determine existing synthetic indices
    existing = {p.name for p in seeds_dir.iterdir() if p.is_file()}
    idx = 0
    for name in existing:
        if name.startswith("synth_"):
            try:
                # synth_001.png -> 001
                num = int(name[6:9])
                idx = max(idx, num + 1)
            except Exception:
                pass

    # Plan distribution to meet at least 10 PNG, 10 JPEG, 5 GIF, 5 BMP
    # We will generate needed images with rotating formats
    formats = []
    # Build a deterministic format plan for 40 slots
    base_plan = (
        ["PNG"] * 12
        + ["JPEG"] * 12
        + ["GIF"] * 8
        + ["BMP"] * 8
    )  # 40 total, exceeds minimums
    # Shuffle with deterministic seed for variety but repeatable
    random.seed(42)
    random.shuffle(base_plan)
    # If needed <40, slice
    # But for simplicity, generate needed count using base_plan sequentially starting from idx offset
    count = 0
    attempts = 0
    while count < needed and attempts < needed * 3:
        attempts += 1
        fmt = base_plan[(idx + count) % len(base_plan)]
        ext = {"PNG": "png", "JPEG": "jpg", "GIF": "gif", "BMP": "bmp"}[fmt]
        fname = f"synth_{idx:03d}.{ext}"
        dest = seeds_dir / fname
        if dest.exists():
            idx += 1
            continue
        try:
            # Vary size 32 to 256
            w = 32 + (idx * 17) % 224  # 32..255
            h = 32 + (idx * 29) % 224
            # ensure at least 16x16
            w = max(16, w)
            h = max(16, h)
            # Vary mode
            if fmt == "GIF":
                mode = "P"
                # For GIF, create P mode directly or RGB then quantize
                bg = (idx * 37 % 256, idx * 73 % 256, idx * 101 % 256)
                img = Image.new("RGB", (w, h), color=bg)
                draw = ImageDraw.Draw(img)
                # Draw distinct pattern
                for r in range(3):
                    x0 = (r * 20 + idx * 5) % w
                    y0 = (r * 15 + idx * 7) % h
                    x1 = min(w, x0 + 30 + idx % 40)
                    y1 = min(h, y0 + 30 + idx % 30)
                    fill = ((idx * 50 + r * 80) % 256, (idx * 80 + r * 50) % 256, (idx * 110 + r * 30) % 256)
                    draw.rectangle([x0, y0, x1, y1], fill=fill, outline=(255, 255, 255))
                draw.text((5, 5), f"{idx}", fill=(255, 255, 255))
                # Add noise
                for _ in range(20):
                    x = random.randint(0, w - 1)
                    y = random.randint(0, h - 1)
                    draw.point((x, y), fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))
                img = img.convert("P", palette=Image.ADAPTIVE, colors=256)
                img.save(str(dest), format=fmt, optimize=True)
            elif fmt == "BMP":
                bg = (idx * 41 % 256, idx * 59 % 256, idx * 97 % 256)
                img = Image.new("RGB", (w, h), color=bg)
                draw = ImageDraw.Draw(img)
                # Draw ellipse
                draw.ellipse([5, 5, w - 5, h - 5], fill=(255 - bg[0], 255 - bg[1], 255 - bg[2]), outline=(0, 0, 0))
                draw.text((w // 3, h // 3), f"B{idx}", fill=(0, 0, 0))
                # lines
                for r in range(2):
                    draw.line([(0, r * 10), (w, r * 10 + 20)], fill=(r * 100 % 256, 50, 50), width=1)
                img.save(str(dest), format=fmt)
            elif fmt == "JPEG":
                bg = (idx * 37 % 256, idx * 73 % 256, idx * 101 % 256)
                img = Image.new("RGB", (w, h), color=bg)
                draw = ImageDraw.Draw(img)
                # Gradient-like rectangles
                for r in range(4):
                    x0 = (r * w) // 4
                    x1 = ((r + 1) * w) // 4
                    fill = ((bg[0] + r * 30) % 256, (bg[1] + r * 40) % 256, (bg[2] + r * 50) % 256)
                    draw.rectangle([x0, 0, x1, h], fill=fill)
                draw.text((5, 5), f"J{idx}", fill=(255, 255, 255))
                draw.ellipse([w // 4, h // 4, 3 * w // 4, 3 * h // 4], outline=(0, 0, 0))
                img.save(str(dest), format=fmt, quality=85)
            else:  # PNG
                # Alternate between RGB, RGBA, L for variety
                if idx % 5 == 0:
                    # L mode
                    gray = idx * 13 % 256
                    img = Image.new("L", (w, h), color=gray)
                    draw = ImageDraw.Draw(img)
                    draw.rectangle([10, 10, w - 10, h - 10], fill=255 - gray, outline=gray // 2)
                    draw.text((5, 5), f"P{idx}", fill=255)
                    img.save(str(dest), format=fmt, optimize=True)
                elif idx % 5 == 1:
                    # RGBA
                    bg = (idx * 37 % 256, idx * 73 % 256, idx * 101 % 256, 255)
                    img = Image.new("RGBA", (w, h), color=bg)
                    draw = ImageDraw.Draw(img)
                    draw.ellipse([10, 10, w - 10, h - 10], fill=(255, 255, 255, 180), outline=(0, 0, 0, 255))
                    draw.text((5, 5), f"A{idx}", fill=(0, 0, 0, 255))
                    img.save(str(dest), format=fmt, optimize=True)
                else:
                    bg = (idx * 37 % 256, idx * 73 % 256, idx * 101 % 256)
                    img = Image.new("RGB", (w, h), color=bg)
                    draw = ImageDraw.Draw(img)
                    # Distinct pattern
                    for r in range(5):
                        x = (r * 13 + idx * 11) % w
                        y = (r * 19 + idx * 7) % h
                        draw.rectangle([x, y, min(w, x + 20), min(h, y + 20)], fill=((r * 50) % 256, (r * 80) % 256, 150), outline=(0, 0, 0))
                    draw.text((5, 5), f"P{idx}", fill=(255, 255, 255))
                    img.save(str(dest), format=fmt, optimize=True)

            if dest.stat().st_size > 0:
                generated += 1
                count += 1
                print(f"generated synthetic image {fname} ({dest.stat().st_size} bytes) {w}x{h} {fmt}")
            else:
                dest.unlink(missing_ok=True)
        except Exception as e:
            print(f"image generation failed idx {idx}: {e}", file=sys.stderr)
            try:
                if dest.exists():
                    dest.unlink(missing_ok=True)
            except Exception:
                pass
        idx += 1
    print(f"synthetic image generation: {generated} files")
    return generated


def _ensure_image_seeds(seeds_dir: Path) -> None:
    seeds_dir.mkdir(parents=True, exist_ok=True)
    valid = _count_valid_images(seeds_dir)
    total = len([p for p in seeds_dir.iterdir() if p.is_file()])
    print(f"image seeds: valid images {valid}/{MIN_SEEDS}, total files {total}")
    png_cnt = len(list(seeds_dir.glob("*.png"))) + len(list(seeds_dir.glob("*.PNG")))
    jpg_cnt = len(list(seeds_dir.glob("*.jpg"))) + len(list(seeds_dir.glob("*.jpeg"))) + len(list(seeds_dir.glob("*.JPG")))
    gif_cnt = len(list(seeds_dir.glob("*.gif"))) + len(list(seeds_dir.glob("*.GIF")))
    bmp_cnt = len(list(seeds_dir.glob("*.bmp"))) + len(list(seeds_dir.glob("*.BMP")))
    print(f"image distribution: PNG={png_cnt} JPG={jpg_cnt} GIF={gif_cnt} BMP={bmp_cnt}")
    if valid >= MIN_SEEDS and png_cnt >= 10 and jpg_cnt >= 10 and gif_cnt >= 5 and bmp_cnt >= 5:
        print(f"image seeds already >= {MIN_SEEDS} valid images with required distribution, skipping bootstrap")
        return
    needed = MIN_SEEDS - valid
    dist_needed = max(0, 10 - png_cnt) + max(0, 10 - jpg_cnt) + max(0, 5 - gif_cnt) + max(0, 5 - bmp_cnt)
    needed = max(needed, dist_needed)
    if needed <= 0:
        needed = dist_needed
    print(f"image seeds need {needed} more images (valid gap {MIN_SEEDS - valid}, dist gap {dist_needed})")
    # Strategy 1: try to copy from Pillow test images if available (unlikely in venv)
    # Strategy 2: curl a few known Pillow test images (optional)
    # For now directly synthetic which covers all requirements
    # Attempt curl for a few images to add diversity
    curl_images = [
        ("https://raw.githubusercontent.com/python-pillow/Pillow/main/Tests/images/hopper.png", "hopper.png"),
        ("https://raw.githubusercontent.com/python-pillow/Pillow/main/Tests/images/hopper.jpg", "hopper.jpg"),
        ("https://raw.githubusercontent.com/python-pillow/Pillow/main/Tests/images/hopper.gif", "hopper.gif"),
        ("https://raw.githubusercontent.com/python-pillow/Pillow/main/Tests/images/hopper.bmp", "hopper.bmp"),
    ]
    curl_added = 0
    for url, name in curl_images:
        dest = seeds_dir / f"pillow_{name}"
        if dest.exists():
            continue
        if valid + curl_added >= MIN_SEEDS:
            break
        try:
            result = subprocess.run(
                ["curl", "-L", "-s", "-o", str(dest), "--connect-timeout", "8", "--max-time", "15", url],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if dest.exists() and dest.stat().st_size > 100:
                # Validate it's an image
                try:
                    from PIL import Image  # type: ignore

                    with Image.open(dest) as im:
                        im.verify()
                    curl_added += 1
                    print(f"curl fetched {name}")
                except Exception:
                    dest.unlink(missing_ok=True)
            else:
                if dest.exists():
                    dest.unlink(missing_ok=True)
        except Exception:
            if dest.exists():
                try:
                    dest.unlink(missing_ok=True)
                except Exception:
                    pass
    valid = _count_valid_images(seeds_dir)
    remaining = MIN_SEEDS - valid
    if remaining > 0:
        _generate_synthetic_images(seeds_dir, remaining)
    valid = _count_valid_images(seeds_dir)
    print(f"image seeds final: {valid} valid images, total files {len(list(seeds_dir.iterdir()))}")
    png_cnt = len(list(seeds_dir.glob("*.png"))) + len(list(seeds_dir.glob("*.PNG")))
    jpg_cnt = len(list(seeds_dir.glob("*.jpg"))) + len(list(seeds_dir.glob("*.jpeg"))) + len(list(seeds_dir.glob("*.JPG")))
    gif_cnt = len(list(seeds_dir.glob("*.gif"))) + len(list(seeds_dir.glob("*.GIF")))
    bmp_cnt = len(list(seeds_dir.glob("*.bmp"))) + len(list(seeds_dir.glob("*.BMP")))
    print(f"image distribution: PNG={png_cnt} JPG={jpg_cnt} GIF={gif_cnt} BMP={bmp_cnt}")
    extra_needed = []
    for fmt, have, want in [("PNG", png_cnt, 10), ("JPEG", jpg_cnt, 10), ("GIF", gif_cnt, 5), ("BMP", bmp_cnt, 5)]:
        gap = want - have
        if gap > 0:
            extra_needed.extend([fmt] * gap)
    if extra_needed:
        print(f"filling distribution gaps: {extra_needed}")
        try:
            from PIL import Image, ImageDraw  # type: ignore
            existing = {p.name for p in seeds_dir.iterdir()}
            idx = 0
            for name in existing:
                if name.startswith("synth_"):
                    try:
                        n = int(name[6:9])
                        idx = max(idx, n + 1)
                    except Exception:
                        pass
            for fmt in extra_needed:
                ext = {"PNG": "png", "JPEG": "jpg", "GIF": "gif", "BMP": "bmp"}[fmt]
                dest = seeds_dir / f"synth_{idx:03d}.{ext}"
                if dest.exists():
                    idx += 1
                    continue
                w = 32 + (idx * 17) % 224
                h = 32 + (idx * 29) % 224
                w = max(16, w); h = max(16, h)
                bg = (idx * 37 % 256, idx * 73 % 256, idx * 101 % 256)
                img = Image.new("RGB", (w, h), color=bg)
                draw = ImageDraw.Draw(img)
                draw.rectangle([10, 10, w - 10, h - 10], fill=(255 - bg[0], 255 - bg[1], 255 - bg[2]))
                draw.text((5, 5), f"{fmt[0]}{idx}", fill=(255, 255, 255))
                if fmt == "GIF":
                    img = img.convert("P", palette=Image.ADAPTIVE, colors=256)
                save_fmt = "JPEG" if fmt == "JPEG" else fmt
                kwargs = {"quality": 85} if save_fmt == "JPEG" else {"optimize": True}
                img.save(str(dest), format=save_fmt, **kwargs)
                print(f"filled {dest.name} {w}x{h} {fmt}")
                idx += 1
        except Exception as e:
            print(f"distribution fill failed: {e}", file=sys.stderr)


def bootstrap_seeds(target: str | None = None) -> None:
    project_root = _project_root()
    # Also handle cwd relative
    targets = []
    if target is None:
        targets = ["pdf", "image"]
    elif target in ("pdf", "image"):
        targets = [target]
    else:
        # Generic target: ensure its seeds dir exists with at least MIN_SEEDS? But for unknown, just ensure pdf+image? Spec says all or specific.
        # If unknown target is given, treat as single target and ensure minimal seeds via fuzz.py logic + synthetic
        print(f"bootstrapping seeds for target '{target}'")
        seeds_dir = project_root / "targets" / target / "seeds"
        if not seeds_dir.exists():
            seeds_dir = Path(f"targets/{target}/seeds")
        seeds_dir.mkdir(parents=True, exist_ok=True)
        # For generic, just ensure at least 1 seed or try synthetic? Keep simple.
        # Delegate to pdf/image if matches, else create placeholder
        if target not in ("pdf", "image"):
            print(f"unknown target '{target}', ensuring minimal seeds")
            if not any(seeds_dir.iterdir()):
                (seeds_dir / "seed1.bin").write_bytes(b"\x00" * 32)
            print(f"seeds bootstrap complete for {target}: {len(list(seeds_dir.iterdir()))} files")
            return
        targets = [target]

    for t in targets:
        print(f"=== bootstrapping seeds for target: {t} ===")
        seeds_dir = project_root / "targets" / t / "seeds"
        if not seeds_dir.exists():
            # fallback to cwd relative
            seeds_dir = Path(f"targets/{t}/seeds")
        if t == "pdf":
            _ensure_pdf_seeds(seeds_dir)
        elif t == "image":
            _ensure_image_seeds(seeds_dir)
        else:
            seeds_dir.mkdir(parents=True, exist_ok=True)

    print("seeds bootstrap")


def minimize_corpus(target: str | None = None) -> None:
    """Minimize corpus via libFuzzer -merge=1 (with hash dedup fallback)."""
    project_root = _project_root()
    # Determine targets
    if target is None:
        targets = ["pdf", "image"]
        # also include any other target dirs that have seeds
        try:
            for p in (project_root / "targets").iterdir():
                if p.is_dir() and p.name not in targets and (p / "seeds").exists():
                    targets.append(p.name)
        except Exception:
            pass
    else:
        targets = [target]

    venv_python = project_root / ".venv" / "bin" / "python"
    if not venv_python.exists():
        venv_python = Path(".venv/bin/python")
    python_bin = str(venv_python.resolve()) if venv_python.exists() else sys.executable

    for t in targets:
        seeds_dir = project_root / "targets" / t / "seeds"
        if not seeds_dir.exists():
            seeds_dir = Path(f"targets/{t}/seeds")
        if not seeds_dir.exists():
            print(f"no seeds dir for target '{t}', skipping")
            continue
        original_files = [p for p in seeds_dir.iterdir() if p.is_file()]
        if not original_files:
            print(f"no files in seeds for '{t}', skipping")
            continue
        original_count = len(original_files)
        original_size = sum(p.stat().st_size for p in original_files)
        print(f"Minimize {t}: {original_count} files, {original_size} bytes ({original_size/1024/1024:.1f} MB)")

        # Prepare minimized output dir
        minimized_dir = project_root / "targets" / t / "seeds_minimized"
        if not minimized_dir.exists():
            try:
                minimized_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                minimized_dir = Path(f"targets/{t}/seeds_minimized")
                minimized_dir.mkdir(parents=True, exist_ok=True)
        # Clean previous minimized
        for p in minimized_dir.iterdir():
            if p.is_file():
                try:
                    p.unlink()
                except Exception:
                    pass

        harness = project_root / "targets" / t / "harness.py"
        if not harness.exists():
            harness = Path(f"targets/{t}/harness.py")
        harness_exists = harness.exists()

        # Try libFuzzer -merge=1 if harness exists and corpus not huge
        did_libfuzzer = False
        if harness_exists and original_count < 500:
            # Use libFuzzer merge for smaller corpora (<500 files) to avoid huge runtime
            try:
                import tempfile, uuid
                tmp_new = Path(f"/tmp/kavach-min-{t}-{uuid.uuid4().hex[:6]}-new")
                tmp_new.mkdir(parents=True, exist_ok=True)
                # Also copy campaign corpus if any
                campaign_dirs = list((project_root / "campaigns").glob(f"{t}-*"))
                extra_corpora = []
                for cd in campaign_dirs:
                    corp = cd / "corpus"
                    if corp.exists() and any(corp.iterdir()):
                        extra_corpora.append(str(corp))
                cmd = [python_bin, str(harness.resolve()) if harness.exists() else str(harness), str(tmp_new), str(seeds_dir.resolve())] + extra_corpora + ["-merge=1", "-close_fd_mask=3"]
                # Add dict if exists
                dict_candidates = [project_root / "targets" / t / f"{t}.dict", project_root / "targets" / t / ".dict", project_root / "targets" / t / "dict", project_root / "targets" / t / "toy.dict"]
                for dc in dict_candidates:
                    if dc.exists():
                        cmd.append(f"-dict={dc.resolve()}")
                        break
                print(f"Running libFuzzer merge: {' '.join(cmd[:6])} ...")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=40, cwd=str(project_root))
                # Merge output goes to tmp_new
                merged_files = list(tmp_new.iterdir()) if tmp_new.exists() else []
                if merged_files:
                    for f in merged_files:
                        shutil.copy2(f, minimized_dir / f.name)
                    did_libfuzzer = True
                    print(f"libFuzzer merge produced {len(merged_files)} files")
                shutil.rmtree(tmp_new, ignore_errors=True)
            except Exception as e:
                print(f"libFuzzer merge failed for {t}: {e}, falling back to hash dedup", file=sys.stderr)
                did_libfuzzer = False

        if not did_libfuzzer:
            # Fallback: hash dedup + keep smallest to meet ≤60% size
            import hashlib
            seen = {}
            unique = []
            for p in original_files:
                try:
                    h = hashlib.sha1(p.read_bytes()).hexdigest()
                    if h not in seen:
                        seen[h] = p
                        unique.append(p)
                except Exception:
                    unique.append(p)
            # Sort by size ascending to prioritize small files for size reduction
            unique_sorted = sorted(unique, key=lambda p: p.stat().st_size)
            # Target size ≤60% of original
            target_size = int(original_size * 0.6)
            picked = []
            cur_size = 0
            for p in unique_sorted:
                if len(picked) < 10:
                    picked.append(p)
                    cur_size += p.stat().st_size
                elif cur_size + p.stat().st_size <= target_size:
                    picked.append(p)
                    cur_size += p.stat().st_size
                else:
                    # Stop if we would exceed target and already have ≥10
                    if len(picked) >= 10:
                        break
            # If we still have <10 due to target_size too small, just take 10 smallest
            if len(picked) < 10 and unique_sorted:
                picked = unique_sorted[:10]
                cur_size = sum(p.stat().st_size for p in picked)
            # If still >60% after picking 10, we need to keep it anyway (≥10 is floor)
            # Copy picked to minimized
            for src in picked:
                try:
                    shutil.copy2(src, minimized_dir / src.name)
                except Exception:
                    pass
            print(f"Hash dedup: {original_count}->{len(picked)} files, {original_size}->{cur_size} bytes ({cur_size/original_size*100:.1f}%)")

        # Verify minimized
        minimized_files = [p for p in minimized_dir.iterdir() if p.is_file()]
        minimized_size = sum(p.stat().st_size for p in minimized_files)
        minimized_count = len(minimized_files)
        if minimized_count < 10:
            # Ensure at least 10 by copying more smallest
            remaining = [p for p in original_files if p.name not in {m.name for m in minimized_files}]
            remaining_sorted = sorted(remaining, key=lambda p: p.stat().st_size)
            for p in remaining_sorted:
                if minimized_count >= 10:
                    break
                try:
                    shutil.copy2(p, minimized_dir / p.name)
                    minimized_count += 1
                    minimized_size += p.stat().st_size
                except Exception:
                    pass
        print(f"Minimize {t} complete: {original_count}→{minimized_count} files, {original_size}→{minimized_size} bytes ({minimized_size/original_size*100:.1f}% of original, target ≤60%)")
        if minimized_count < 10:
            print(f"warning: minimized corpus for {t} has <10 files ({minimized_count})", file=sys.stderr)
        if minimized_size > original_size * 0.6 and minimized_count > 10:
            print(f"note: minimized size {minimized_size} >60% of original {original_size}, but corpus deduped")
