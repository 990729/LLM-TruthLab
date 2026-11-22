"""Pure-Python stdlib PNG generator for dynamic multimodal vision probes.

Generates a crisp bitmap image containing a dynamically generated random code
and a colored geometric shape with zero external imaging dependencies (no Pillow).
"""

from __future__ import annotations

import base64
import random
import struct
import zlib
from typing import Any

# Clean 5x7 pixel bitmap font for unambiguous alphanumeric characters
_FONT_5X7: dict[str, list[str]] = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "G": ["01111", "10000", "10000", "10111", "10001", "10001", "01111"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "J": ["00111", "00010", "00010", "00010", "10010", "10010", "01100"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "N": ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "Q": ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "W": ["10001", "10001", "10001", "10101", "10101", "11011", "10001"],
    "X": ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    "Z": ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
    "0": ["01110", "10011", "10101", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00110", "01000", "10000", "11111"],
    "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    "6": ["01110", "10000", "11110", "10001", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
}

_COLORS: dict[str, tuple[int, int, int]] = {
    "red": (220, 38, 38),
    "blue": (37, 99, 235),
    "green": (22, 163, 74),
}


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    chunk = chunk_type + data
    crc = zlib.crc32(chunk) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk + struct.pack(">I", crc)


def encode_rgb_png(width: int, height: int, pixels: bytearray) -> bytes:
    """Encode a flat RGB bytearray (width * height * 3) into a valid PNG."""
    raw_rows = bytearray()
    row_stride = width * 3
    for y in range(height):
        raw_rows.append(0)  # Filter type 0 (None)
        start = y * row_stride
        raw_rows.extend(pixels[start : start + row_stride])

    compressed = zlib.compress(bytes(raw_rows), level=6)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", compressed)
        + _png_chunk(b"IEND", b"")
    )


def generate_vision_probe_image(rng: random.Random | None = None) -> dict[str, str]:
    """Create a 320x120 high-contrast PNG with a random 4-char code & colored shape.

    Returns dict with: code, color_name, shape_name, png_b64, data_url.
    """
    r = rng or random.Random()
    alphabet = [c for c in _FONT_5X7.keys() if c not in {"O", "0", "1", "I"}]
    code = "".join(r.choice(alphabet) for _ in range(4))
    color_name = r.choice(list(_COLORS.keys()))
    shape_name = r.choice(["circle", "square", "triangle"])
    shape_rgb = _COLORS[color_name]

    width, height = 320, 120
    # Clean off-white background
    pixels = bytearray([248, 250, 252] * (width * height))

    def set_px(x: int, y: int, rgb: tuple[int, int, int]) -> None:
        if 0 <= x < width and 0 <= y < height:
            idx = (y * width + x) * 3
            pixels[idx] = rgb[0]
            pixels[idx + 1] = rgb[1]
            pixels[idx + 2] = rgb[2]

    # Subtle border frame
    border = (203, 213, 225)
    for x in range(width):
        for y in (0, 1, height - 2, height - 1):
            set_px(x, y, border)
    for y in range(height):
        for x in (0, 1, width - 2, width - 1):
            set_px(x, y, border)

    # Draw solid geometric shape on the left (center ~ 60, 60, radius 32)
    cx, cy, rad = 58, 60, 30
    if shape_name == "circle":
        r2 = rad * rad
        for y in range(cy - rad, cy + rad + 1):
            for x in range(cx - rad, cx + rad + 1):
                if (x - cx) ** 2 + (y - cy) ** 2 <= r2:
                    set_px(x, y, shape_rgb)
    elif shape_name == "square":
        half = 27
        for y in range(cy - half, cy + half + 1):
            for x in range(cx - half, cx + half + 1):
                set_px(x, y, shape_rgb)
    else:  # upward equilateral-ish triangle
        top_y, bot_y = cy - 28, cy + 28
        for y in range(top_y, bot_y + 1):
            progress = (y - top_y) / max(1, (bot_y - top_y))
            half_w = int(progress * 32)
            for x in range(cx - half_w, cx + half_w + 1):
                set_px(x, y, shape_rgb)

    # Draw large crisp dark-navy 4-char code on the right
    text_rgb = (15, 23, 42)
    scale = 6  # each glyph is 30x42 px
    start_x = 122
    start_y = 39
    char_advance = 44

    for idx, ch in enumerate(code):
        glyph = _FONT_5X7[ch]
        gx0 = start_x + idx * char_advance
        for row_i, row_str in enumerate(glyph):
            for col_i, bit in enumerate(row_str):
                if bit == "1":
                    for dy in range(scale):
                        for dx in range(scale):
                            set_px(gx0 + col_i * scale + dx, start_y + row_i * scale + dy, text_rgb)

    png_bytes = encode_rgb_png(width, height, pixels)
    png_b64 = base64.b64encode(png_bytes).decode("ascii")
    return {
        "code": code,
        "color_name": color_name,
        "shape_name": shape_name,
        "png_b64": png_b64,
        "data_url": f"data:image/png;base64,{png_b64}",
    }


def _draw_text(
    pixels: bytearray,
    width: int,
    height: int,
    x0: int,
    y0: int,
    text: str,
    rgb: tuple[int, int, int],
    scale: int = 2,
) -> None:
    adv = 6 * scale
    for idx, ch in enumerate(text.upper()):
        glyph = _FONT_5X7.get(ch)
        if not glyph:
            continue
        gx = x0 + idx * adv
        for r_i, row_str in enumerate(glyph):
            for c_i, bit in enumerate(row_str):
                if bit == "1":
                    for dy in range(scale):
                        for dx in range(scale):
                            px, py = gx + c_i * scale + dx, y0 + r_i * scale + dy
                            if 0 <= px < width and 0 <= py < height:
                                p = (py * width + px) * 3
                                pixels[p] = rgb[0]
                                pixels[p + 1] = rgb[1]
                                pixels[p + 2] = rgb[2]


def generate_chart_vision_image(rng: random.Random | None = None) -> dict[str, Any]:
    """Generate a 400x240 anti-OCR bar chart PNG where heights are ONLY encoded visually.

    Defeats OCR-to-text middleware relays because bar values are NOT printed as text.
    """
    r = rng or random.Random()
    labels = ["A", "B", "C", "D"]
    # Well-separated heights for unambiguous visual reading
    heights = [20, 45, 70, 95]
    r.shuffle(heights)
    color_palette = [
        ("red", (220, 38, 38)),
        ("blue", (37, 99, 235)),
        ("green", (22, 163, 74)),
        ("orange", (234, 88, 12)),
    ]
    r.shuffle(color_palette)

    width, height = 400, 240
    pixels = bytearray([250, 251, 253] * (width * height))

    def fill_rect(x1: int, y1: int, x2: int, y2: int, rgb: tuple[int, int, int]) -> None:
        for y in range(max(0, y1), min(height, y2)):
            for x in range(max(0, x1), min(width, x2)):
                p = (y * width + x) * 3
                pixels[p] = rgb[0]
                pixels[p + 1] = rgb[1]
                pixels[p + 2] = rgb[2]

    # Chart geometry: y=0 at bottom y_base=200, y=100 at top y_top=25 (height=175 px)
    x_left, x_right = 62, 376
    y_top, y_base = 25, 200
    plot_h = y_base - y_top  # 175 px

    # Horizontal gridlines & Y-axis ticks (0, 20, 40, 60, 80, 100)
    grid_rgb = (210, 218, 228)
    axis_rgb = (30, 41, 59)
    for tick in (0, 20, 40, 60, 80, 100):
        gy = y_base - int((tick / 100.0) * plot_h)
        fill_rect(x_left, gy, x_right, gy + 1, axis_rgb if tick == 0 else grid_rgb)
        lbl = str(tick)
        lx = x_left - 8 - len(lbl) * 12
        _draw_text(pixels, width, height, lx, gy - 6, lbl, axis_rgb, scale=2)

    # Y-axis vertical spine
    fill_rect(x_left, y_top, x_left + 2, y_base + 1, axis_rgb)

    # Draw 4 colored bars (NO numeric values printed on top!)
    bar_w = 46
    slot_w = (x_right - x_left) // 4
    bars_info: list[dict[str, Any]] = []
    for idx, lbl in enumerate(labels):
        val = heights[idx]
        cname, crgb = color_palette[idx]
        bx1 = x_left + idx * slot_w + (slot_w - bar_w) // 2
        bh = int((val / 100.0) * plot_h)
        by1 = y_base - bh
        fill_rect(bx1, by1, bx1 + bar_w, y_base, crgb)
        _draw_text(pixels, width, height, bx1 + bar_w // 2 - 6, y_base + 10, lbl, axis_rgb, scale=3)
        bars_info.append({"label": lbl, "value": val, "color": cname})

    tallest = max(bars_info, key=lambda b: b["value"])
    shortest = min(bars_info, key=lambda b: b["value"])

    png_bytes = encode_rgb_png(width, height, pixels)
    png_b64 = base64.b64encode(png_bytes).decode("ascii")
    return {
        "bars": bars_info,
        "tallest_label": tallest["label"],
        "tallest_color": tallest["color"],
        "tallest_value": tallest["value"],
        "shortest_label": shortest["label"],
        "shortest_value": shortest["value"],
        "png_b64": png_b64,
        "data_url": f"data:image/png;base64,{png_b64}",
    }


def generate_hires_micro_image(rng: random.Random | None = None) -> dict[str, Any]:
    """Generate a 1024x1024 PNG with tiny crisp scale=2 corner micro-codes.

    Catches shady relays that silently downscale images to 256/512px thumbnails
    or force detail='low' to save vision tokens while charging full price.
    """
    r = rng or random.Random()
    alphabet = [c for c in _FONT_5X7.keys() if c not in {"O", "0", "1", "I"}]
    tl_code = "".join(r.choice(alphabet) for _ in range(3))
    br_code = "".join(r.choice(alphabet) for _ in range(3))

    width, height = 1024, 1024
    pixels = bytearray(b"\xf8\xfa\xfc" * (width * height))

    def fill_rect(x1: int, y1: int, x2: int, y2: int, rgb: tuple[int, int, int]) -> None:
        r0, g0, b0 = rgb
        x1c, x2c = max(0, x1), min(width, x2)
        y1c, y2c = max(0, y1), min(height, y2)
        if x1c >= x2c or y1c >= y2c:
            return
        row_bytes = bytes((r0, g0, b0)) * (x2c - x1c)
        for y in range(y1c, y2c):
            st = (y * width + x1c) * 3
            pixels[st : st + len(row_bytes)] = row_bytes

    # Subtle outer frame
    border = (203, 213, 225)
    fill_rect(0, 0, width, 4, border)
    fill_rect(0, height - 4, width, height, border)
    fill_rect(0, 0, 4, height, border)
    fill_rect(width - 4, 0, width, height, border)

    # Large low-distraction center marker
    fill_rect(380, 440, 644, 584, (241, 245, 249))
    _draw_text(pixels, width, height, 446, 474, "HD", (148, 163, 184), scale=10)

    # High-contrast crisp micro-badges (scale=2 -> 10x14 px per char) in opposite corners
    ink = (15, 23, 42)
    fill_rect(18, 18, 72, 46, (255, 255, 255))
    _draw_text(pixels, width, height, 24, 24, tl_code, ink, scale=2)

    fill_rect(width - 74, height - 48, width - 18, height - 18, (255, 255, 255))
    _draw_text(pixels, width, height, width - 66, height - 40, br_code, ink, scale=2)

    # Fast deflate encoding for 1024x1024 flat canvas (~4KB)
    raw_rows = bytearray()
    row_stride = width * 3
    for y in range(height):
        raw_rows.append(0)
        st = y * row_stride
        raw_rows.extend(pixels[st : st + row_stride])
    compressed = zlib.compress(bytes(raw_rows), level=3)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", compressed)
        + _png_chunk(b"IEND", b"")
    )
    png_b64 = base64.b64encode(png_bytes).decode("ascii")
    return {
        "width": width,
        "height": height,
        "tl_code": tl_code,
        "br_code": br_code,
        "png_b64": png_b64,
        "data_url": f"data:image/png;base64,{png_b64}",
    }
