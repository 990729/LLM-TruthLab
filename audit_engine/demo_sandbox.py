"""In-Process Zero-Cost Forensic Demo Sandbox.

Spins up an ephemeral localhost mock server simulating a realistic fraudulent
API relay (tampered Thinking signature accepted, <think> leak, hidden system
prompt injection, fake tiktoken billing split, regex brand whitewashing,
HKG Cloudflare + OneAPI headers, and low IQ) so users can preview the full
zero-trust forensic pipeline and PNG poster export with zero API cost.
"""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .baselines import BaselineStore
from .models import AuditConfig, AuditReport
from .runner import run_full_audit


def _make_demo_shady_handler():
    class DemoShadyHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            pass

        def _send(self, code: int, obj: dict[str, Any]) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("server", "cloudflare")
            self.send_header("cf-ray", "9a8b7c6d5e4f3210-HKG")
            self.send_header("x-oneapi-request-id", "demo-oneapi-0042")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))

            if req.get("max_tokens", 1) <= 0 or "__audit_invalid_field__" in req:
                self._send(422, {"detail": [{"msg": "pydantic validation error from vllm deepseek worker"}]})
                return

            if req.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("server", "cloudflare")
                self.send_header("cf-ray", "9a8b7c6d5e4f3210-HKG")
                self.send_header("x-oneapi-request-id", "demo-oneapi-0042")
                self.end_headers()
                evt = {
                    "type": "content_block_delta",
                    "delta": {"type": "text_delta", "text": "<think>pretending to be opus</think>1 2 3 4 5"},
                }
                self.wfile.write(f"event: content_block_delta\ndata: {json.dumps(evt)}\n\n".encode("utf-8"))
                return

            if isinstance(req.get("thinking"), dict):
                self._send(
                    200,
                    {
                        "id": "demo_think_fake",
                        "model": req.get("model", "claude-opus-4-6"),
                        "stop_reason": "end_turn",
                        "content": [
                            {
                                "type": "thinking",
                                "thinking": "fake reasoning",
                                "signature": base64.b64encode(b"FORGED_UNVERIFIED_SIGNATURE_" * 3).decode("ascii"),
                            },
                            {"type": "text", "text": "410"},
                        ],
                        "usage": {"input_tokens": 140, "output_tokens": 35},
                    },
                )
                return

            msgs = req.get("messages") or []
            user_txt = str(msgs[-1].get("content", "")) if msgs else ""

            if user_txt == "Hi":
                in_tok, out_txt = 560, "I am Claude Opus created by Anthropic."
            elif "string-serialization unit test" in user_txt:
                # Classic regex brand whitewashing!
                in_tok, out_txt = 170, '{"echo": ["Claude", "Claude", "OpenAI", "Anthropic", "Claude", "Gemini"]}'
            elif "012345678901234567890123456789" in user_txt:
                in_tok, out_txt = 175, "X"  # faked tiktoken +10 (175 - 165 = 10)
            elif "中华人民共和国人工智能大模型" in user_txt:
                in_tok, out_txt = 185, "X"  # +20 CJK dense (185 - 165 = 20)
            elif "1234567890" in user_txt and req.get("max_tokens") == 1:
                in_tok, out_txt = 165, "1"  # real single-digit tokenizer cut!
            elif "random integer between 1 and 100" in user_txt or "随机选一个整数" in user_txt:
                in_tok, out_txt = 165, "73"
            elif "first color" in user_txt:
                in_tok, out_txt = 165, "crimson"
            elif "uppercase English letter" in user_txt:
                in_tok, out_txt = 165, "Q"
            elif "ALPHA-1" in user_txt:
                in_tok, out_txt = 168, "ALPHA-1 ALPHA-2 ALPHA-3 ALPHA-4 ALPHA-5 ALPHA-6"
            elif "翻译成大白话" in user_txt:
                in_tok, out_txt = 220, (
                    "【一句话结论】快跑！这个模拟中转站基本实锤是假货套壳，同时查出假签名、漏开源标签、改词洗白和假账单。\n"
                    "【干活水平】实测做题表现很差，完全配不上宣称的高价旗舰。\n"
                    "【查出的问题】思考签名随便改都能放行、正文漏出开源思考标签、把别的模型名字强行改成大牌、还按贵模型假算账单并偷偷塞了隐藏指令。\n"
                    "【给你的建议】千万别充值，立刻换正规渠道（此条为本地零消耗演练模拟输出）。"
                )
            else:
                in_tok, out_txt = 165, '{"answer": 7, "trips": 7}'

            self._send(
                200,
                {
                    "id": "demo_fake_001",
                    "model": req.get("model", "claude-opus-4-6"),
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": out_txt}],
                    "usage": {"input_tokens": in_tok, "output_tokens": 12},
                },
            )

    return DemoShadyHandler


def run_demo_sandbox_audit(
    *,
    baseline_store: BaselineStore | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> AuditReport:
    """Run a zero-cost full forensic audit against an ephemeral localhost shady relay."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_demo_shady_handler())
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        cfg = AuditConfig(
            base_url=f"http://127.0.0.1:{port}/v1 (本地模拟黑心中转站)",
            api_key="sk-demo-zero-cost-sandbox",
            model="claude-opus-4-6",
            protocol="anthropic",
            mode="quick",
            run_protocol=True,
            run_tokenizer=True,
            run_fingerprint=True,
            run_iq=True,
            run_vision=True,
            run_long_context=False,
            run_smart_routing=False,
            run_cutoff=True,
            run_regex_canary=True,
            iq_seed=202611,
        )
        # Keep real loopback URL for client while preserving clean label after run
        cfg.base_url = f"http://127.0.0.1:{port}"
        report = run_full_audit(
            cfg,
            baseline_store=baseline_store,
            on_event=on_event,
            cancel_check=cancel_check,
        )
        report.config["base_url"] = "demo://shady-relay.sandbox (本地零消耗演练)"
        return report
    finally:
        srv.shutdown()
        srv.server_close()
