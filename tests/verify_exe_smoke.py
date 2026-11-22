"""End-to-end smoke verification of the compiled standalone v3.0 dist/LLM-TruthLab.exe."""

from __future__ import annotations

import json
import re
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _MiniMockRelay(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(ln).decode("utf-8"))
        if req.get("temperature") == 99.0 or req.get("top_logprobs") == 99:
            body = json.dumps(
                {"error": {"message": "Invalid param", "type": "invalid_request_error", "param": "temperature", "code": "invalid_value"}}
            ).encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if req.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            chunk = {
                "id": "chatcmpl-exe-smoke",
                "object": "chat.completion.chunk",
                "model": req.get("model", "gpt-4o"),
                "system_fingerprint": "fp_smoke_01",
                "choices": [{"index": 0, "delta": {"content": "TCP slow start increases cwnd."}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8},
            }
            self.wfile.write(f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n".encode("utf-8"))
            return

        txt = str((req.get("messages") or [{}])[-1].get("content", ""))
        if "string-serialization unit test" in txt:
            ans = '{"echo": ["DeepSeek", "Qwen", "OpenAI", "Anthropic", "Claude", "Gemini"]}'
        elif "CRITICAL BEACON ALPHA" in txt:
            mh = re.search(r"HEAD-\d{4}-[A-Z]", txt)
            mm = re.search(r"MID-\d{4}-[A-Z]", txt)
            mt = re.search(r"TAIL-\d{4}-[A-Z]", txt)
            ans = json.dumps({
                "head": mh.group(0) if mh else "",
                "mid": mm.group(0) if mm else "",
                "tail": mt.group(0) if mt else "",
            })
        else:
            ans = "42"

        resp = {
            "id": "chatcmpl-exe-smoke",
            "model": req.get("model", "gpt-4o"),
            "system_fingerprint": "fp_smoke_01",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": ans}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": max(12, len(txt) // 4), "completion_tokens": 10},
        }
        body = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _run_exe_safe(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
        raise AssertionError(f"EXE command timed out after {timeout}s: {' '.join(cmd)}")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    exe = root / "dist" / "LLM-TruthLab.exe"
    assert exe.is_file(), f"Missing compiled EXE: {exe}"

    # 1. Verify --server-only mode serves v3.0 bundled web/index.html & /api/health
    port = _free_port()
    proc = subprocess.Popen([str(exe), "--server-only", "--port", str(port)])
    try:
        health = None
        for _ in range(40):
            try:
                r = httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=1.0)
                if r.status_code == 200 and r.json().get("ok"):
                    health = r.json()
                    break
            except Exception:
                time.sleep(0.25)
        assert health is not None and health.get("version") == "11.2.0", f"Unexpected health: {health}"

        r_idx = httpx.get(f"http://127.0.0.1:{port}/", timeout=2.0)
        assert r_idx.status_code == 200
        for marker in ("LLM-TruthLab v11.0", "viewArena", "viewBatch", "viewProxy", "viewMonitor", "viewHistory", "compareHistoryBtn", "applyPreset", "copyMdBtn", "saveBookmarkBtn", "batchPasteBtn", "openGuideBtn", "exportPosterBtn", "runDemoBtn", "backupZipBtn", "importZipBtn", "chkStealth", "chkPlainSummary", "plainSummaryCard", "budgetCap", "chkAnonymize"):
            assert marker in r_idx.text, f"Missing UI marker {marker}"
        print("[OK] v11.0 EXE embedded HTTP server & minimalist luxury 6-workspace UI verified!")
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    # 2. Verify --cli end-to-end execution including --context-cliff & attribution export
    mock = ThreadingHTTPServer(("127.0.0.1", 0), _MiniMockRelay)
    m_port = mock.server_address[1]
    mt = threading.Thread(target=mock.serve_forever, daemon=True)
    mt.start()
    try:
        with tempfile.TemporaryDirectory() as td:
            html_out = Path(td) / "report.html"
            json_out = Path(td) / "report.json"
            rc, _, err = _run_exe_safe(
                [
                    str(exe),
                    "--cli",
                    "--url",
                    f"http://127.0.0.1:{m_port}/v1",
                    "--key",
                    "sk-smoke-v3-secret",
                    "--model",
                    "gpt-4o",
                    "--mode",
                    "quick",
                    "--no-vision",
                    "--no-long-context",
                    "--context-cliff",
                    "--context-max-k",
                    "4",
                    "--out",
                    str(html_out),
                    "--json",
                    str(json_out),
                ],
                timeout=45,
            )
            assert rc == 0, f"EXE CLI failed (code={rc}): {err}"
            assert html_out.is_file() and html_out.stat().st_size > 3000
            assert json_out.is_file()
            data = json.loads(json_out.read_text(encoding="utf-8"))
            assert data["iq"] is not None and len(data["iq"]["dimension_scores"]) >= 7
            assert data["attribution"]["candidates"]
            assert data["context_cliff"]["max_verified_k"] == 4
            html_txt = html_out.read_text(encoding="utf-8")
            assert "sk-smoke-v3-secret" not in html_txt
            assert "底层真实模型家族归因推演" in html_txt
            assert "上下文断崖记忆热力表" in html_txt
            print(
                f"[OK] v10.0 EXE --cli full audit verified! Verdict={data['verdict']['authenticity_code']}, "
                f"IQ dims={len(data['iq']['dimension_scores'])}, ContextCliff=4K PASS, HTML={html_out.stat().st_size} bytes"
            )

            # 3. Verify --cli --ab dual-endpoint alias check on compiled EXE!
            ab_html = Path(td) / "arena.html"
            rc_ab, _, err_ab = _run_exe_safe(
                [
                    str(exe),
                    "--cli",
                    "--ab",
                    "--url",
                    f"http://127.0.0.1:{m_port}/v1",
                    "--key",
                    "sk-ab",
                    "--model",
                    "claude-opus-4-6",
                    "--model-b",
                    "claude-sonnet-4-5",
                    "--mode",
                    "quick",
                    "--no-iq",
                    "--out",
                    str(ab_html),
                ],
                timeout=35,
            )
            assert rc_ab == 0, f"EXE --cli --ab failed (code={rc_ab}): {err_ab}"
            assert ab_html.is_file() and "别名套娃" in ab_html.read_text(encoding="utf-8")
            print(f"[OK] v10.0 EXE --cli --ab alias-fraud HTML export verified ({ab_html.stat().st_size} bytes)!")
    finally:
        mock.shutdown()
        mock.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
