"""Pure-Python stdlib minimal valid PDF 1.4 generator for dynamic native PDF probes.

Generates an uncacheable single-page PDF containing a freshly randomized
verification passcode and token sum, with zero third-party PDF dependencies.
"""

from __future__ import annotations

import base64
import random


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def generate_probe_pdf(rng: random.Random | None = None) -> dict[str, str | int]:
    """Generate a valid PDF 1.4 document in memory containing dynamic secrets."""
    r = rng or random.Random()
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = f"PDF-{''.join(r.choice(alphabet) for _ in range(4))}-{r.randint(10, 99)}"
    num_a = r.randint(14, 49)
    num_b = r.randint(11, 39)
    expected_sum = num_a + num_b

    lines = [
        "LLM-TruthLab Dynamic Native PDF Verification Document",
        f"Verification Code: {code}",
        f"Audit Arithmetic: {num_a} + {num_b}",
        "If you can read this PDF natively, return the exact code and sum.",
    ]

    stream_cmds = ["BT", "/F1 14 Tf", "50 740 Td", "22 TL"]
    for idx, ln in enumerate(lines):
        esc = _pdf_escape(ln)
        if idx == 0:
            stream_cmds.append(f"({esc}) Tj")
        else:
            stream_cmds.append(f"T* ({esc}) Tj")
    stream_cmds.append("ET")
    stream_bytes = ("\n".join(stream_cmds) + "\n").encode("latin-1")

    objects: list[bytes] = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        (
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
        ),
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        (
            f"5 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"endstream\nendobj\n"
        ),
    ]

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode("ascii")
    out.extend(trailer)

    pdf_bytes = bytes(out)
    return {
        "code": code,
        "num_a": num_a,
        "num_b": num_b,
        "expected_sum": expected_sum,
        "pdf_b64": base64.b64encode(pdf_bytes).decode("ascii"),
        "byte_size": len(pdf_bytes),
    }
