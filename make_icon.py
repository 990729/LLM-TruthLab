"""Generate a clean multi-resolution Windows .ico file (32x32 & 64x64) using stdlib only."""

from __future__ import annotations

import struct
from pathlib import Path

from audit_engine.png_gen import encode_rgb_png


def _render_logo_png(size: int) -> bytes:
    pixels = bytearray(size * size * 3)
    cx, cy = size / 2.0, size / 2.0
    r_outer = size * 0.44
    r_inner = size * 0.30
    r_core = size * 0.13

    for y in range(size):
        for x in range(size):
            dx = x + 0.5 - cx
            dy = y + 0.5 - cy
            dist = (dx * dx + dy * dy) ** 0.5
            # Dark navy rounded square background
            corner_r = size * 0.22
            in_bg = True
            for bx in (corner_r, size - corner_r):
                for by in (corner_r, size - corner_r):
                    if (x < corner_r or x >= size - corner_r) and (y < corner_r or y >= size - corner_r):
                        if ((x - bx) ** 2 + (y - by) ** 2) ** 0.5 > corner_r:
                            in_bg = False

            if not in_bg:
                rgb = (8, 13, 26)
            elif dist <= r_core:
                rgb = (56, 189, 248)  # Bright cyan core
            elif abs(dist - r_inner) < size * 0.045:
                rgb = (129, 140, 248)  # Indigo fingerprint ring
            elif abs(dist - r_outer) < size * 0.045 and not (dx > 0 and dy > 0 and abs(dx - dy) < size * 0.12):
                rgb = (56, 189, 248)  # Outer radar/fingerprint arc
            else:
                # Subtle gradient navy background
                t = y / max(1, size - 1)
                rgb = (int(12 + 8 * t), int(22 + 12 * t), int(46 + 18 * t))

            idx = (y * size + x) * 3
            pixels[idx] = rgb[0]
            pixels[idx + 1] = rgb[1]
            pixels[idx + 2] = rgb[2]

    return encode_rgb_png(size, size, pixels)


def build_ico(out_path: Path) -> None:
    sizes = [32, 64]
    pngs = [_render_logo_png(s) for s in sizes]
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # ICO header: reserved(0), type(1=icon), count
    header = struct.pack("<HHH", 0, 1, len(sizes))
    entries = bytearray()
    offset = 6 + 16 * len(sizes)
    for s, blob in zip(sizes, pngs):
        w = s if s < 256 else 0
        h = s if s < 256 else 0
        entries.extend(struct.pack("<BBBBHHII", w, h, 0, 0, 1, 24, len(blob), offset))
        offset += len(blob)

    out_path.write_bytes(header + bytes(entries) + b"".join(pngs))


if __name__ == "__main__":
    target = Path(__file__).resolve().parent / "assets" / "app.ico"
    build_ico(target)
    print(f"Generated icon: {target} ({target.stat().st_size} bytes)")
