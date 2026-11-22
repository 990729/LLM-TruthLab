"""Comprehensive unit and mock-relay integration tests for LLM-TruthLab."""

from __future__ import annotations

import base64
import json
import random
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

from audit_engine.arena import run_ab_arena
from audit_engine.baselines import BaselineStore, jensen_shannon_divergence
from audit_engine.batch import run_batch_leaderboard
from audit_engine.client import RelayClient
from audit_engine.demo_sandbox import run_demo_sandbox_audit
from audit_engine.history import HistoryStore, compare_history_reports
from audit_engine.models import AuditConfig
from audit_engine.monitor import CanaryMonitor
from audit_engine.png_gen import generate_chart_vision_image, generate_vision_probe_image
from audit_engine.probes_advanced import (
    probe_concurrency_fallback,
    probe_knowledge_cutoff,
    probe_multiturn_agent_loop,
    probe_parameter_obedience,
    probe_regex_brand_masking,
    probe_sse_timing,
)
from audit_engine.net_forensics import analyze_network_headers
from audit_engine.pdf_gen import generate_probe_pdf
from audit_engine.pricing import estimate_audit_cost
from audit_engine.probes_billing import (
    audit_usage_physics_sanity,
    probe_assistant_prefill,
    probe_billing_multiplier,
    probe_chart_vision_anti_ocr,
    probe_client_cloaking,
    probe_native_pdf,
    probe_output_cap,
    probe_quantization_precision,
)
from audit_engine.probes_context import run_context_cliff_ladder
from audit_engine.probes_iq import (
    _build_anti_bias_crossing,
    _build_anti_bias_crystal,
    _build_anti_bias_pricing,
    _build_bilingual_nuance,
    _build_code_bugfix,
    _build_code_parser_challenge,
    _build_code_trace_recursion,
    _build_code_trace_state,
    _build_instruction_constraints,
    _build_knights_knaves,
    _build_logic_grid,
    _build_long_context_multihop,
    _build_math_bayes,
    _build_math_crt,
    _build_spatial_grid_sim,
)
from audit_engine.runner import run_full_audit
from audit_engine.verdict import render_arena_html, render_batch_html, render_html_report


# ======================================================================
# 1. Pure Unit Tests: PNG, JSD, and Dynamic IQ Generators (20 seeds!)
# ======================================================================


def test_png_generator_produces_valid_png():
    img = generate_vision_probe_image(random.Random(12345))
    raw = base64.b64decode(img["png_b64"])
    assert raw.startswith(b"\x89PNG\r\n\x1a\n")
    assert raw.endswith(b"IEND\xaeB`\x82")
    assert len(img["code"]) == 4
    assert img["color_name"] in ("red", "blue", "green")
    assert img["shape_name"] in ("circle", "square", "triangle")


def test_jsd_properties():
    a = {"42": 10, "73": 5, "17": 5}
    b = {"42": 10, "73": 5, "17": 5}
    c = {"99": 20}
    assert jensen_shannon_divergence(a, b) == pytest.approx(0.0, abs=1e-9)
    assert jensen_shannon_divergence(a, c) == pytest.approx(1.0, abs=1e-9)
    mid = jensen_shannon_divergence({"a": 8, "b": 2}, {"a": 5, "b": 5})
    assert 0.0 < mid < 0.3


def test_all_dynamic_iq_generators_across_20_seeds():
    """Ensure every dynamic IQ generator creates mathematically unique, gradable problems."""
    for seed in range(100, 120):
        rng = random.Random(seed)
        q1 = _build_anti_bias_crystal(rng)
        assert q1["grader"](json.dumps({"answer": q1["expected"]}))[0] == 1.0
        assert q1["grader"](json.dumps({"answer": q1["expected"] + 1}))[0] == 0.0

        q2 = _build_anti_bias_crossing(rng)
        assert q2["grader"]('{"trips": 1}')[0] == 1.0
        assert q2["grader"]('{"trips": 7}')[0] == 0.0

        q3 = _build_anti_bias_pricing(rng)
        assert q3["grader"](json.dumps({"cost": q3["expected"]}))[0] == 1.0

        q4 = _build_logic_grid(rng)
        assert q4["grader"](json.dumps(q4["expected"]))[0] == 1.0

        q5 = _build_knights_knaves(rng)
        assert q5["grader"](json.dumps(q5["expected"]))[0] == 1.0

        q6 = _build_math_crt(rng)
        assert q6["grader"](json.dumps({"x": q6["expected"]}))[0] == 1.0

        q7 = _build_math_bayes(rng)
        assert q7["grader"](json.dumps({"answer": q7["expected"]}))[0] == 1.0

        q8 = _build_code_trace_state(rng)
        assert q8["grader"](json.dumps({"result": q8["expected"]}))[0] == 1.0

        q9 = _build_code_trace_recursion(rng)
        assert q9["grader"](json.dumps({"result": q9["expected"]}))[0] == 1.0

        q10 = _build_instruction_constraints(rng)
        # Construct a valid passing answer dynamically for the chosen acrostic & forbidden letter
        acrostic = q10["expected"]["acrostic"]
        forbid = q10["expected"]["forbidden_letter"]
        wcount = q10["expected"]["summary_words"]
        # Pick simple valid words starting with each letter without forbidden letter
        word_bank = {
            "S": ["sun", "sky"], "P": ["pig", "pod"], "A": ["ant", "arm"], "R": ["rod", "rim"], "K": ["kit", "keg"],
            "C": ["cat", "cog"], "L": ["log", "lap"], "O": ["owl", "orb"], "U": ["urn", "ump"], "D": ["dog", "dam"],
            "F": ["fox", "fin"], "T": ["top", "tin"], "B": ["bus", "bin"], "I": ["ink", "imp"], "N": ["nut", "nap"],
        }
        items = [next(w for w in word_bank[ch] if forbid not in w) for ch in acrostic]
        assert all(forbid not in w for w in items)
        good_json = json.dumps({
            "items": items,
            "checksum": sum(len(w) for w in items),
            "summary": " ".join(["word"] * wcount),
        })
        assert q10["grader"](good_json)[0] == 1.0

        q11 = _build_long_context_multihop(rng, "quick")
        assert q11["grader"](json.dumps(q11["expected"]))[0] == 1.0

        q12 = _build_spatial_grid_sim(rng)
        assert q12["grader"](json.dumps(q12["expected"]))[0] == 1.0
        assert q12["grader"]('{"x": -1, "y": -1, "facing": "N"}')[0] == 0.0

        q13 = _build_code_bugfix(rng)
        good_code = (
            "```python\n"
            "def solve_intervals(intervals, max_gap, min_len):\n"
            "    valid = sorted(([a, b] for a, b in intervals if a <= b), key=lambda x: (x[0], x[1]))\n"
            "    if not valid:\n"
            "        return []\n"
            "    merged = [valid[0][:]]\n"
            "    for s, e in valid[1:]:\n"
            "        if s <= merged[-1][1] + max_gap:\n"
            "            merged[-1][1] = max(merged[-1][1], e)\n"
            "        else:\n"
            "            merged.append([s, e])\n"
            "    return [iv for iv in merged if iv[1] - iv[0] >= min_len]\n"
            "```"
        )
        assert q13["grader"](good_code)[0] == 1.0
        # Malicious import MUST be blocked by AST safety gate!
        bad_sec_score, bad_sec_note = q13["grader"]("```python\nimport os\ndef solve_intervals(a,b,c): return []\n```")
        assert bad_sec_score == 0.0
        assert "禁止" in bad_sec_note


# ======================================================================
# 2. Mock Relay Servers for End-to-End Integration Testing
# ======================================================================


class _MockServer:
    def __init__(self, handler_cls):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _make_authentic_anthropic_handler():
    valid_sig = base64.b64encode(b"AUTHENTIC_ANTHROPIC_CRYPTO_SIGNATURE_PAYLOAD_V4_" * 3).decode("ascii")
    cache_seen = {"count": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, code: int, obj: dict[str, Any], headers: dict[str, str] | None = None):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("anthropic-organization-id", "org_test_real")
            if headers:
                for k, v in headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))

            # Reject illegal params with Anthropic native schema
            if req.get("max_tokens", 1) <= 0 or "__audit_invalid_field__" in req:
                self._send(
                    400,
                    {"type": "error", "error": {"type": "invalid_request_error", "message": "Invalid parameter"}},
                )
                return

            msgs = req.get("messages") or []
            # Check thinking signature verification on Turn 2 replay!
            for m in msgs:
                if m.get("role") == "assistant" and isinstance(m.get("content"), list):
                    for blk in m["content"]:
                        if isinstance(blk, dict) and blk.get("type") == "thinking":
                            if blk.get("signature") != valid_sig:
                                self._send(
                                    400,
                                    {
                                        "type": "error",
                                        "error": {
                                            "type": "invalid_request_error",
                                            "message": "Invalid signature in thinking block",
                                        },
                                    },
                                )
                                return

            # Streaming SSE
            if req.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("anthropic-organization-id", "org_test_real")
                self.end_headers()
                evts = [
                    ("message_start", {"type": "message_start", "message": {"id": "msg_01realstream", "model": req["model"], "usage": {"input_tokens": 14}}}),
                    ("content_block_delta", {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "1 2 3 4 5"}}),
                    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 8}}),
                    ("message_stop", {"type": "message_stop"}),
                ]
                for ename, edata in evts:
                    self.wfile.write(f"event: {ename}\ndata: {json.dumps(edata)}\n\n".encode("utf-8"))
                return

            # Extended Thinking Turn 1
            if isinstance(req.get("thinking"), dict) and req["thinking"].get("type") == "enabled":
                self._send(
                    200,
                    {
                        "id": "msg_01thinking",
                        "model": req["model"],
                        "stop_reason": "end_turn",
                        "content": [
                            {"type": "thinking", "thinking": "17*23=391, +19=410", "signature": valid_sig},
                            {"type": "text", "text": "410"},
                        ],
                        "usage": {"input_tokens": 22, "output_tokens": 35},
                    },
                )
                return

            # Tool Use
            if req.get("tools"):
                self._send(
                    200,
                    {
                        "id": "msg_01tool",
                        "model": req["model"],
                        "stop_reason": "tool_use",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu_01real",
                                "name": "verify_vault_code",
                                "input": {"vault_id": 742, "priority": "CRITICAL", "tag": "audit-k9"},
                            }
                        ],
                        "usage": {"input_tokens": 45, "output_tokens": 32},
                    },
                )
                return

            # Prompt cache test
            sys_blk = req.get("system")
            if isinstance(sys_blk, list) and sys_blk and isinstance(sys_blk[0], dict) and sys_blk[0].get("cache_control"):
                cache_seen["count"] += 1
                is_second = cache_seen["count"] >= 2
                self._send(
                    200,
                    {
                        "id": "msg_01cache",
                        "model": req["model"],
                        "stop_reason": "end_turn",
                        "content": [{"type": "text", "text": "075"}],
                        "usage": {
                            "input_tokens": 20,
                            "output_tokens": 4,
                            "cache_creation_input_tokens": 0 if is_second else 1350,
                            "cache_read_input_tokens": 1350 if is_second else 0,
                        },
                    },
                )
                return

            # Extract user text
            user_txt = ""
            if msgs:
                c = msgs[-1].get("content")
                user_txt = c if isinstance(c, str) else json.dumps(c)

            # Tokenizer differentials (realistic Claude-BPE counts)
            if "012345678901234567890123456789" in user_txt:
                in_tok, out_txt = 24, "X"  # base=13 + 11
            elif "中华人民共和国人工智能大模型" in user_txt:
                in_tok, out_txt = 61, "X"  # base=13 + 48
            elif "|" + (" " * 32) + "|" in user_txt:
                in_tok, out_txt = 19, "X"  # base=13 + 6
            elif "__init__ asyncio" in user_txt:
                in_tok, out_txt = 27, "X"
            elif "1234567890" in user_txt and req.get("max_tokens") == 1:
                in_tok, out_txt = 22, "123"
            elif "中华人民共和国" in user_txt and req.get("max_tokens") == 1:
                in_tok, out_txt = 20, "中"
            elif user_txt == "Hi":
                in_tok, out_txt = 10, "Hello"
            elif "The quick brown fox" in user_txt:
                in_tok, out_txt = 30, "The quick brown fox jumps over the lazy dog near the river bank.\n" * 3
            elif "random integer between 1 and 100" in user_txt:
                in_tok, out_txt = 18, "42"
            elif "随机选一个整数" in user_txt:
                in_tok, out_txt = 18, "42"
            elif "first color" in user_txt:
                in_tok, out_txt = 16, "blue"
            elif "uppercase English letter" in user_txt:
                in_tok, out_txt = 16, "K"
            elif "prime number" in user_txt:
                in_tok, out_txt = 16, "37"
            elif "fair coin" in user_txt:
                in_tok, out_txt = 16, "Heads"
            elif "ALPHA-1" in user_txt:
                in_tok, out_txt = 20, "ALPHA-1 ALPHA-2 ALPHA-3 "
            elif "capital of France" in user_txt:
                sys_str = str(req.get("system") or "")
                import re as _re
                m_tag = _re.search(r"\[SYS_\d+Q\]", sys_str)
                in_tok, out_txt = 20, f"{m_tag.group(0) if m_tag else ''} Paris is France's capital."
            elif "GPT-4o" in user_txt:
                in_tok, out_txt = 20, '{"answer": "May 2024"}'
            elif "November 2024" in user_txt:
                in_tok, out_txt = 20, '{"answer": "Trump"}'
            elif "DeepSeek-R1" in user_txt:
                in_tok, out_txt = 20, '{"answer": "DeepSeek"}'
            elif "Pope of the Catholic Church" in user_txt:
                in_tok, out_txt = 20, '{"answer": "Leo XIV"}'
            elif "string-serialization unit test" in user_txt:
                in_tok, out_txt = 25, '{"echo": ["DeepSeek", "Qwen", "OpenAI", "Anthropic", "Claude", "Gemini"]}'
            else:
                in_tok, out_txt = 13, "OK"

            self._send(
                200,
                {
                    "id": "msg_01normal",
                    "model": req["model"],
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": out_txt}],
                    "usage": {"input_tokens": in_tok, "output_tokens": max(2, len(out_txt.split()))},
                },
            )

    return Handler


def _make_shady_fake_relay_handler():
    """Simulates a fraudulent relay claiming claude-opus-4-6 while running a spoofed model."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, code: int, obj: dict[str, Any]):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("x-oneapi-request-id", "fake-relay-999")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))

            # Leaks vllm/deepseek error on bad param
            if req.get("max_tokens", 1) <= 0 or "__audit_invalid_field__" in req:
                self._send(422, {"detail": [{"msg": "pydantic validation error from vllm deepseek worker"}]})
                return

            if req.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                # Leaks <think> tag inside text!
                evt = {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "<think>hmm</think>1 2 3 4 5"}}
                self.wfile.write(f"event: content_block_delta\ndata: {json.dumps(evt)}\n\n".encode("utf-8"))
                return

            # Accepts tampered thinking signature with HTTP 200!! (Caught by L1 crypto tamper test)
            if isinstance(req.get("thinking"), dict):
                self._send(
                    200,
                    {
                        "id": "fake_think_id",
                        "model": req["model"],
                        "stop_reason": "end_turn",
                        "content": [
                            {"type": "thinking", "thinking": "fake", "signature": base64.b64encode(b"FAKE_SIG_NOT_VERIFIED_AT_ALL_" * 3).decode()},
                            {"type": "text", "text": "410"},
                        ],
                        "usage": {"input_tokens": 120, "output_tokens": 40},
                    },
                )
                return

            msgs = req.get("messages") or []
            user_txt = str(msgs[-1].get("content", "")) if msgs else ""

            # Fake tiktoken billing (reports 10 tokens for 30 digits) BUT real output cuts 1 digit!
            if user_txt == "Hi":
                in_tok, out_txt = 560, "I am Claude"  # Extreme hidden system prompt injection!
            elif "012345678901234567890123456789" in user_txt:
                in_tok, out_txt = 165, "X"  # base=155 + 10 (faked tiktoken)
            elif "中华人民共和国人工智能大模型" in user_txt:
                in_tok, out_txt = 175, "X"  # +20 (CJK dense!)
            elif "1234567890" in user_txt and req.get("max_tokens") == 1:
                in_tok, out_txt = 160, "1"  # Real model is single-digit tokenizer!
            else:
                in_tok, out_txt = 155, "I don't know, maybe 7?"  # Fails IQ & vision & tools!

            self._send(
                200,
                {
                    "id": "custom_999",
                    "model": req["model"],
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": out_txt}],
                    "usage": {"input_tokens": in_tok, "output_tokens": 8},
                },
            )

    return Handler


def test_authentic_anthropic_relay_verified_strong(tmp_path: Path):
    srv = _MockServer(_make_authentic_anthropic_handler())
    try:
        cfg = AuditConfig(
            base_url=srv.url,
            api_key="sk-ant-test",
            model="claude-sonnet-4-5",
            protocol="anthropic",
            mode="quick",
            run_vision=False,  # tested separately
            run_iq=False,
        )
        store = BaselineStore(tmp_path)
        report = run_full_audit(cfg, baseline_store=store)
        assert report.verdict.authenticity_code == "VERIFIED_STRONG"
        assert report.verdict.trust_score >= 85
        crypto_ev = next(e for e in report.evidences if e.id == "crypto_thinking_signature")
        assert crypto_ev.status == "PASS"

        # Verify standalone HTML report renders cleanly and masks API key
        html_out = render_html_report(report)
        assert "硬核验真 · 确认真源" in html_out
        assert "sk-ant-test" not in html_out
    finally:
        srv.close()


def test_shady_fake_relay_caught_red_handed(tmp_path: Path):
    srv = _MockServer(_make_shady_fake_relay_handler())
    try:
        cfg = AuditConfig(
            base_url=srv.url,
            api_key="sk-fake",
            model="claude-opus-4-6",
            protocol="anthropic",
            mode="quick",
            run_vision=True,
            run_iq=True,
            run_long_context=False,
            iq_seed=424242,
        )
        store = BaselineStore(tmp_path)
        report = run_full_audit(cfg, baseline_store=store)

        assert report.verdict.authenticity_code == "LIKELY_FAKE_OR_WATERED"
        assert report.verdict.trust_score <= 30

        by_id = {e.id: e for e in report.evidences}
        # Verify EVERY independent forensic trap fired!
        assert by_id["crypto_thinking_signature"].status == "FAIL"
        assert by_id["proto_sse_metadata"].status == "FAIL"
        assert by_id["proto_error_schema"].status == "FAIL"
        assert by_id["proto_hidden_sysprompt"].status == "FAIL"
        assert by_id["tok_fake_billing_split"].status == "FAIL"
        assert by_id["cap_tool_use"].status == "FAIL"
        assert by_id["cap_vision_dynamic"].status == "FAIL"
        assert by_id["iq_tier_audit"].status == "FAIL"
        assert report.iq is not None and report.iq.total_score < 30.0
    finally:
        srv.close()


def _make_openai_distribution_handler(num_ans: str, color_ans: str, letter_ans: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            msgs = req.get("messages") or []
            txt = str(msgs[-1].get("content", "")) if msgs else ""
            if "random integer between 1 and 100" in txt or "随机选一个整数" in txt:
                ans = num_ans
            elif "first color" in txt:
                ans = color_ans
            elif "uppercase English letter" in txt:
                ans = letter_ans
            elif "prime number" in txt:
                ans = "37" if num_ans == "42" else "73"
            else:
                ans = "OK"

            resp = {
                "id": "chatcmpl-test01",
                "model": req.get("model", "gpt-5"),
                "system_fingerprint": "fp_stable01",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": ans}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 2},
            }
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def test_baseline_save_and_jsd_match_vs_mismatch(tmp_path: Path):
    official_srv = _MockServer(_make_openai_distribution_handler("42", "blue", "K"))
    swapped_srv = _MockServer(_make_openai_distribution_handler("88", "crimson", "Z"))
    store = BaselineStore(tmp_path)
    try:
        # Step 1: Audit official endpoint & record baseline
        cfg_off = AuditConfig(
            base_url=official_srv.url,
            api_key="sk-off",
            model="gpt-5",
            protocol="openai_chat",
            mode="quick",
            run_protocol=False,
            run_tokenizer=False,
            run_fingerprint=True,
            run_smart_routing=False,
            run_cutoff=False,
            run_iq=False,
        )
        rep_off = run_full_audit(cfg_off, baseline_store=store)
        assert rep_off.verdict.authenticity_code == "CONSISTENT_UNPROVEN"  # Zero-trust before baseline!
        saved = store.save_from_report(rep_off.to_dict(), name="GPT-5 Official")
        assert len(store.list_baselines()) == 1

        # Step 2: Re-test same backend -> Strong Match!
        rep_same = run_full_audit(cfg_off, baseline_store=store)
        assert rep_same.verdict.authenticity_code == "VERIFIED_STRONG"
        assert rep_same.fingerprint.baseline_matches[0]["verdict"] == "MATCH_STRONG"
        assert rep_same.fingerprint.baseline_matches[0]["mean_jsd"] == pytest.approx(0.0, abs=0.01)

        # Step 3: Test swapped backend -> Caught via JSD Mismatch!
        cfg_swap = AuditConfig(
            base_url=swapped_srv.url,
            api_key="sk-swap",
            model="gpt-5",
            protocol="openai_chat",
            mode="quick",
            run_protocol=False,
            run_tokenizer=False,
            run_fingerprint=True,
            run_smart_routing=False,
            run_cutoff=False,
            run_iq=False,
            compare_baseline_id=saved["id"],
        )
        rep_swap = run_full_audit(cfg_swap, baseline_store=store)
        assert rep_swap.verdict.authenticity_code == "LIKELY_FAKE_OR_WATERED"
        assert rep_swap.fingerprint.baseline_matches[0]["verdict"] == "MISMATCH"
        assert rep_swap.fingerprint.baseline_matches[0]["mean_jsd"] >= 0.8
    finally:
        official_srv.close()
        swapped_srv.close()


def test_local_http_server_smoke(tmp_path: Path):
    """Verify app.py HTTP handler serves UI, enforces token auth, and manages baselines."""
    import app as app_mod

    state = app_mod.AppState(app_token="secret_tok_123")
    state.baseline_store = BaselineStore(tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app_mod.make_handler(state))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        r_html = httpx.get(f"{base}/")
        assert r_html.status_code == 200
        assert "LLM-TruthLab" in r_html.text

        # Missing token rejected
        r_no_tok = httpx.get(f"{base}/api/baselines")
        assert r_no_tok.status_code == 403

        # Valid token succeeds
        r_ok = httpx.get(f"{base}/api/baselines", headers={"X-App-Token": "secret_tok_123"})
        assert r_ok.status_code == 200
        assert r_ok.json()["baselines"] == []
    finally:
        srv.shutdown()
        srv.server_close()


# ======================================================================
# 3. v2.0 Tests: Fake-SSE, Param Obedience, Cutoff, Context Cliff, Arena, Monitor, History
# ======================================================================


def test_v2_fake_stream_param_disobedience_and_stale_cutoff():
    class HostileRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            if req.get("stream"):
                # Simulate Fake SSE: buffer 0.65s, then dump 16 chunks instantaneously!
                time.sleep(0.65)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for i in range(16):
                    chunk = {
                        "id": "chatcmpl-fakestream",
                        "object": "chat.completion.chunk",
                        "model": req.get("model", "gpt-5"),
                        "choices": [{"index": 0, "delta": {"content": f"word{i} "}, "finish_reason": None}],
                    }
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
                self.wfile.write(b"data: [DONE]\n\n")
                return

            msgs = req.get("messages") or []
            user_txt = str(msgs[-1].get("content", ""))
            # Disobey stop=["ALPHA-4"], ignore system prefix, return UNKNOWN for all cutoff milestones
            if "ALPHA-1" in user_txt:
                ans = "ALPHA-1 ALPHA-2 ALPHA-3 ALPHA-4 ALPHA-5 ALPHA-6"
            elif "capital of France" in user_txt:
                ans = "Paris is capital"  # ignored system rule!
            elif "UNKNOWN" in user_txt:
                ans = '{"answer": "UNKNOWN"}'
            else:
                ans = "not json at all"

            body = json.dumps({
                "id": "chatcmpl-hostile",
                "model": req.get("model", "gpt-5"),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": ans}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 10},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(HostileRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-x", model="gpt-5", protocol="openai_chat", mode="quick")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            sse_ev, sm = probe_sse_timing(client, cfg)
            assert sm["fake_stream_suspected"] is True
            assert sse_ev.status == "WARN"
            assert "假流式" in sse_ev.summary

            po_evs = probe_parameter_obedience(client, cfg)
            assert po_evs[0].status == "FAIL"

            cut_ev, cut_info = probe_knowledge_cutoff(client, cfg)
            assert cut_ev.status == "FAIL"
            assert cut_info["stale_model_suspected"] is True
        finally:
            client.close()
    finally:
        srv.close()


def test_v2_context_cliff_catches_silent_head_clipping():
    import re as _re

    class ClippingRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            txt = str((req.get("messages") or [{}])[-1].get("content", ""))
            est_tok = len(txt) // 4
            m_head = _re.search(r"HEAD-\d{4}-[A-Z]", txt)
            m_mid = _re.search(r"MID-\d{4}-[A-Z]", txt)
            m_tail = _re.search(r"TAIL-\d{4}-[A-Z]", txt)

            if est_tok < 8000:
                ans = json.dumps({
                    "head": m_head.group(0) if m_head else "",
                    "mid": m_mid.group(0) if m_mid else "",
                    "tail": m_tail.group(0) if m_tail else "",
                })
                rep_in = est_tok
            else:
                # Silently truncate head and cap input tokens at 4096!
                ans = json.dumps({
                    "head": "FORGOTTEN",
                    "mid": m_mid.group(0) if m_mid else "",
                    "tail": m_tail.group(0) if m_tail else "",
                })
                rep_in = 4096

            body = json.dumps({
                "id": "chatcmpl-clip",
                "model": req.get("model", "claude-sonnet-4-5"),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": ans}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": rep_in, "completion_tokens": 20},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(ClippingRelay)
    try:
        cfg = AuditConfig(
            base_url=srv.url,
            api_key="sk-clip",
            model="claude-sonnet-4-5",
            protocol="openai_chat",
            context_cliff_max_k=16,
        )
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev, cliff = run_context_cliff_ladder(client, cfg)
            assert ev.status == "FAIL"
            assert cliff["max_verified_k"] == 4
            assert cliff["rows"][1]["head_ok"] is False
            assert cliff["rows"][1]["silent_clip_suspected"] is True
        finally:
            client.close()
    finally:
        srv.close()


def test_v2_ab_arena_catches_alias_fraud_and_swapped_relay(tmp_path: Path):
    srv_a = _MockServer(_make_openai_distribution_handler("42", "blue", "K"))
    srv_b_diff = _MockServer(_make_openai_distribution_handler("91", "purple", "Q"))
    store = BaselineStore(tmp_path)
    try:
        # Case 1: Same relay claims claude-opus-4-6 AND claude-sonnet-4-5, both point to SAME backend -> ALIAS FRAUD!
        cfg1 = AuditConfig(
            base_url=srv_a.url, api_key="sk-1", model="claude-opus-4-6", protocol="openai_chat", mode="quick",
            run_protocol=False, run_tokenizer=False, run_fingerprint=True, run_iq=False, run_smart_routing=False, run_cutoff=False,
        )
        cfg2 = AuditConfig(
            base_url=srv_a.url, api_key="sk-1", model="claude-sonnet-4-5", protocol="openai_chat", mode="quick",
            run_protocol=False, run_tokenizer=False, run_fingerprint=True, run_iq=False, run_smart_routing=False, run_cutoff=False,
        )
        res_alias = run_ab_arena(cfg1, cfg2, baseline_store=store)
        assert res_alias["comparison"]["relation_code"] == "ALIAS_FRAUD_DETECTED"
        assert res_alias["comparison"]["mean_jsd"] == pytest.approx(0.0, abs=0.01)

        # Case 2: Both claim gpt-5 across two relays, different backends -> DIFFERENT_MODEL_FRAUD!
        cfg3 = AuditConfig(
            base_url=srv_a.url, api_key="sk-1", model="gpt-5", protocol="openai_chat", mode="quick",
            run_protocol=False, run_tokenizer=False, run_fingerprint=True, run_iq=False, run_smart_routing=False, run_cutoff=False,
        )
        cfg4 = AuditConfig(
            base_url=srv_b_diff.url, api_key="sk-2", model="gpt-5", protocol="openai_chat", mode="quick",
            run_protocol=False, run_tokenizer=False, run_fingerprint=True, run_iq=False, run_smart_routing=False, run_cutoff=False,
        )
        res_diff = run_ab_arena(cfg3, cfg4, baseline_store=store)
        assert res_diff["comparison"]["relation_code"] == "DIFFERENT_MODEL_FRAUD"
        assert res_diff["comparison"]["mean_jsd"] >= 0.8
    finally:
        srv_a.close()
        srv_b_diff.close()


def test_v2_canary_monitor_detects_midrun_backend_switch():
    state = {"phase": 1}

    class SwitchingRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            p = state["phase"]
            rid = "chatcmpl-real01" if p == 1 else "vllm-switched99"
            model_ret = "gpt-5" if p == 1 else "deepseek-chat"
            fp = "fp_real_1" if p == 1 else "fp_fake_2"
            if req.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                txt = "DNS maps names." if p == 1 else "<think>oops</think>DNS maps names."
                c = {"id": rid, "model": model_ret, "system_fingerprint": fp, "choices": [{"index": 0, "delta": {"content": txt}, "finish_reason": "stop"}]}
                self.wfile.write(f"data: {json.dumps(c)}\n\ndata: [DONE]\n\n".encode("utf-8"))
                return
            txt = str((req.get("messages") or [{}])[-1].get("content", ""))
            if "random integer" in txt:
                ans = "42" if p == 1 else "99"
            elif "color" in txt:
                ans = "blue" if p == 1 else "orange"
            else:
                ans = "OK"
            body = json.dumps({
                "id": rid, "model": model_ret, "system_fingerprint": fp,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": ans}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(SwitchingRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-mon", model="gpt-5", protocol="openai_chat")
        mon = CanaryMonitor()
        t1 = mon.run_single_tick(cfg)
        assert t1["ok"] is True
        assert t1["returned_model"] == "gpt-5"

        # Now relay silently switches backend on Tick 2!
        state["phase"] = 2
        t2 = mon.run_single_tick(cfg)
        assert t2["ok"] is True
        joined = " | ".join(t2["alerts"])
        assert "模型名漂移" in joined
        assert "ID 前缀突变" in joined
        assert "<think>" in joined
        assert t2["jsd_vs_anchor"] >= 0.9
    finally:
        srv.close()


def test_v2_history_vault_roundtrip(tmp_path: Path):
    hstore = HistoryStore(tmp_path)
    sample = {
        "audit_id": "aud_hist001",
        "started_at": "2026-11-22T09:00:00Z",
        "duration_sec": 12.3,
        "config": {"base_url": "https://api.test.local", "model": "claude-opus-4-6", "mode": "standard", "api_key": "sk-1...abcd"},
        "verdict": {"detected_protocol": "anthropic", "authenticity_code": "VERIFIED_STRONG", "authenticity_label": "强证据支持真源", "trust_score": 92, "headline": "OK", "detected_tokenizer_family": "Claude-BPE"},
        "evidences": [],
        "fingerprint": {},
        "iq": {"total_score": 91.5, "iq_index": 138, "tier": "S", "tier_label": "S 级", "seed": 123456, "dimension_scores": {}, "questions": []},
        "attribution": {
            "top_suspect": {"family_label": "Anthropic Claude 系列", "confidence_pct": 85.0},
            "candidates": [{"family_label": "Anthropic Claude 系列", "confidence_pct": 85.0, "reasons": ["Thinking 签名通过"]}],
        },
        "telemetry": {"total_requests": 20, "ok_requests": 20, "input_tokens": 500, "output_tokens": 300},
    }
    hstore.save_report(sample)
    items = hstore.list_reports()
    assert len(items) == 1
    assert items[0]["audit_id"] == "aud_hist001"
    loaded = hstore.get_report("aud_hist001")
    assert loaded is not None and loaded["verdict"]["trust_score"] == 92
    # Render HTML directly from historical dict
    html_out = render_html_report(loaded)
    assert "底层真实模型家族归因推演" in html_out
    assert hstore.delete_report("aud_hist001") is True
    assert hstore.list_reports() == []


# ======================================================================
# 4. v3.0 Red-Team Tests: Regex Brand-Masking, Agent Loop, Concurrency Burst, Batch Matrix
# ======================================================================


def test_v3_regex_brand_masking_canary():
    class RegexWhitewashRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            # Simulate shady gateway running naive .replace("DeepSeek", "Claude").replace("Qwen", "Claude")!
            raw_reply = '{"echo": ["DeepSeek", "Qwen", "OpenAI", "Anthropic", "Claude", "Gemini"]}'
            whitewashed = raw_reply.replace("DeepSeek", "Claude").replace("Qwen", "Claude")
            body = json.dumps({
                "id": "chatcmpl-wash", "model": req.get("model", "claude-opus-4-6"),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": whitewashed}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 18},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(RegexWhitewashRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-w", model="claude-opus-4-6", protocol="openai_chat")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev = probe_regex_brand_masking(client, cfg)
            assert ev.status == "FAIL"
            assert ev.severity == "CRITICAL"
            assert "DeepSeek" in ev.summary
        finally:
            client.close()
    finally:
        srv.close()


def test_v3_multiturn_agent_tool_loop():
    class WorkingAgentRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            msgs = req.get("messages") or []
            if len(msgs) == 1:
                resp = {
                    "id": "chatcmpl-ag1", "model": req["model"],
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [{
                                "id": "call_ag_01",
                                "type": "function",
                                "function": {"name": "get_sector_metric", "arguments": '{"sector": "SEC-10"}'},
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                    "usage": {"prompt_tokens": 30, "completion_tokens": 15},
                }
            else:
                tool_data = json.loads(msgs[-1]["content"])
                calc = int(tool_data["reading"]) * 2 + 7
                resp = {
                    "id": "chatcmpl-ag2", "model": req["model"],
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": json.dumps({"computed": calc, "tag": tool_data["tag"]})},
                        "finish_reason": "stop",
                    }],
                    "usage": {"prompt_tokens": 55, "completion_tokens": 12},
                }
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(WorkingAgentRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-a", model="gpt-5", protocol="openai_chat")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev = probe_multiturn_agent_loop(client, cfg)
            assert ev.status == "PASS"
        finally:
            client.close()
    finally:
        srv.close()


def test_v3_concurrency_burst_catches_fallback_mixing():
    counter = {"n": 0}
    lock = threading.Lock()

    class FallbackPoolRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(ln)
            with lock:
                counter["n"] += 1
                idx = counter["n"]
            # First 3 hit real pool, overflow 4-5 silently fall back to cheaper deepseek vllm!
            if idx <= 3:
                resp = {
                    "id": f"chatcmpl-main{idx}", "model": "gpt-5", "system_fingerprint": "fp_main",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": '{"num": 500, "planet": "Mars"}'}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 10},
                }
            else:
                resp = {
                    "id": f"vllm-fallback{idx}", "model": "deepseek-chat", "system_fingerprint": "fp_cheap",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": '<think>calc</think>{"num": 500, "planet": "Mars"}'}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 15},
                }
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(FallbackPoolRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-c", model="gpt-5", protocol="openai_chat")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev = probe_concurrency_fallback(client, cfg)
            assert ev.status == "FAIL"
            assert "不同模型名" in ev.summary or "ID 前缀" in ev.summary
        finally:
            client.close()
    finally:
        srv.close()


def test_v3_batch_leaderboard_and_nxn_alias_matrix(tmp_path: Path):
    srv_same = _MockServer(_make_openai_distribution_handler("42", "blue", "K"))
    srv_other = _MockServer(_make_openai_distribution_handler("88", "crimson", "Z"))
    store = BaselineStore(tmp_path)
    try:
        targets = [
            {"label": "站A-Opus", "base_url": srv_same.url, "api_key": "sk-1", "model": "claude-opus-4-6", "protocol": "openai_chat"},
            {"label": "站A-Sonnet", "base_url": srv_same.url, "api_key": "sk-1", "model": "claude-sonnet-4-5", "protocol": "openai_chat"},
            {"label": "站B-GPT5", "base_url": srv_other.url, "api_key": "sk-2", "model": "gpt-5", "protocol": "openai_chat"},
        ]
        res = run_batch_leaderboard(targets, mode="quick", run_iq=False, run_protocol=False, baseline_store=store)
        assert len(res["leaderboard"]) == 3
        mat = res["matrix_jsd"]
        # Opus & Sonnet on srv_same have JSD ~ 0.0 -> alias alert fired!
        assert mat[0][1] == pytest.approx(0.0, abs=0.01)
        # Opus vs GPT-5 on srv_other have JSD >= 0.8!
        assert mat[0][2] >= 0.8
        assert any("疑似别名套娃" in a for a in res["alias_alerts"])
    finally:
        srv_same.close()
        srv_other.close()


# ======================================================================
# 5. v4.0 Tests: Input Billing Multiplier Fraud, Anti-Quantization Precision, History Diff & HTML Exports
# ======================================================================


def test_v4_billing_multiplier_fraud():
    class InflatedBillingRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            txt = str((req.get("messages") or [{}])[-1].get("content", ""))
            word_cnt = len(txt.split())
            # Secretly multiply prompt_tokens by 1.8x to overcharge user!
            fake_in = int(word_cnt * 1.85)
            body = json.dumps({
                "id": "chatcmpl-bill", "model": req["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": fake_in, "completion_tokens": 2},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(InflatedBillingRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-b", model="gpt-5", protocol="openai_chat")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev = probe_billing_multiplier(client, cfg)
            assert ev.status == "FAIL"
            assert "倍率注水" in ev.summary or "计费注水" in ev.summary
            assert ev.details["delta_300w"] > 445
        finally:
            client.close()
    finally:
        srv.close()


def test_v4_quantization_precision_probe():
    import re as _re

    class ExactPrecisionRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            txt = str((req.get("messages") or [{}])[-1].get("content", ""))
            m_str = _re.search(r'indexing on "([A-Z0-9]+)"', txt)
            m_pos = _re.findall(r"1-based position (\d+)", txt)
            m_ch = _re.search(r'times "([A-Z0-9])" appears', txt)
            m_json = _re.search(r"Given this JSON: (\{.*?\})\n", txt)
            m_port = _re.search(r"replica\.port` to (\d+)", txt)
            m_tag = _re.search(r'meta\.release` to "(v[\d.]+)"', txt)

            s = m_str.group(1)
            i1, i2 = int(m_pos[0]), int(m_pos[1])
            tch = m_ch.group(1)
            doc = json.loads(m_json.group(1))
            doc["cluster"]["nodes"]["replica"]["port"] = int(m_port.group(1))
            doc["cluster"]["meta"]["release"] = m_tag.group(1)

            ans = json.dumps({
                "task_a": {"c1": s[i1 - 1], "c2": s[i2 - 1], "cnt": s.count(tch)},
                "task_b": doc,
            })
            body = json.dumps({
                "id": "chatcmpl-prec", "model": req["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": ans}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 180, "completion_tokens": 110},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(ExactPrecisionRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-p", model="gpt-5", protocol="openai_chat")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev = probe_quantization_precision(client, cfg)
            assert ev.status == "PASS"
            assert ev.details["hits"] == 4
        finally:
            client.close()
    finally:
        srv.close()


def test_v4_history_diff_and_arena_batch_html_exports():
    rep_old = {
        "audit_id": "aud_week1",
        "started_at": "2026-11-15T10:00:00Z",
        "config": {"model": "claude-opus-4-6"},
        "verdict": {"trust_score": 92, "suspected_anomalies": []},
        "fingerprint": {
            "distributions": {"rand_num_en": {"42": 10}, "color_en": {"blue": 10}},
            "tokenizer_vector": {"deltas": {"digits_30": 10, "cjk_32": 48}},
        },
        "iq": {"total_score": 90.0, "dimension_scores": {"code_bugfix": {"label": "实战代码修Bug", "score_pct": 100.0}}},
    }
    rep_new = {
        "audit_id": "aud_week2",
        "started_at": "2026-11-22T10:00:00Z",
        "config": {"model": "claude-opus-4-6"},
        "verdict": {"trust_score": 45, "suspected_anomalies": ["[HIGH] 词表冲突"]},
        "fingerprint": {
            "distributions": {"rand_num_en": {"88": 10}, "color_en": {"red": 10}},
            "tokenizer_vector": {"deltas": {"digits_30": 30, "cjk_32": 20}},
        },
        "iq": {"total_score": 62.0, "dimension_scores": {"code_bugfix": {"label": "实战代码修Bug", "score_pct": 30.0}}},
    }
    diff = compare_history_reports(rep_old, rep_new)
    assert diff["trust_delta"] == -47
    assert diff["iq_delta"] == -28.0
    assert diff["jsd_drift"] >= 0.99
    assert len(diff["degradation_flags"]) >= 3

    arena_html = render_arena_html({
        "arena_id": "arena_demo", "shared_iq_seed": 123, "duration_sec": 5.2,
        "comparison": {"relation_code": "ALIAS_FRAUD_DETECTED", "relation_label": "别名套娃", "relation_summary": "same", "mean_jsd": 0.02, "per_task_jsd": {"color_en": 0.01}, "h2h_questions": []},
        "report_a": {"config": {"model": "opus"}, "verdict": {"trust_score": 50}},
        "report_b": {"config": {"model": "sonnet"}, "verdict": {"trust_score": 50}},
    })
    assert "别名套娃" in arena_html

    batch_html = render_batch_html({
        "batch_id": "batch_demo", "shared_iq_seed": 123, "duration_sec": 12.1,
        "alias_alerts": ["疑似别名套娃"],
        "labels": ["A", "B"], "matrix_jsd": [[0.0, 0.05], [0.05, 0.0]],
        "leaderboard": [{"label": "A", "model": "opus", "authenticity_label": "存疑", "composite_score": 55, "trust_score": 50, "iq_score": 60, "iq_tier": "B", "avg_latency_ms": 300, "top_suspect": "DeepSeek"}],
    })
    assert "N×N 两两单 Token JSD 热力矩阵" in batch_html


# ======================================================================
# 6. v5.0 Tests: Dynamic PDF Probe, Output Cap Clamping, Cost Estimator & UI JS Syntax Check
# ======================================================================


def test_v5_pdf_generator_and_native_pdf_probe():
    pdf = generate_probe_pdf(random.Random(777))
    raw = base64.b64decode(pdf["pdf_b64"])
    assert raw.startswith(b"%PDF-1.4")
    assert b"%%EOF" in raw
    assert str(pdf["code"]).encode("ascii") in raw

    class FakeAnthropicNoPdf(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(ln)
            body = json.dumps({"type": "error", "error": {"type": "invalid_request_error", "message": "document block unsupported"}}).encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(FakeAnthropicNoPdf)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-p", model="claude-sonnet-4-5", protocol="anthropic")
        client = RelayClient(cfg)
        client.protocol = "anthropic"
        try:
            ev = probe_native_pdf(client, cfg)
            assert ev is not None and ev.status == "FAIL"
            assert "PDF" in ev.summary
        finally:
            client.close()
    finally:
        srv.close()


def test_v5_output_cap_clamping_detector():
    class ClampedOutputRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            # Secretly cap output at 30 lines / 256 tokens with finish_reason='length'!
            lines = "\n".join(f"ITEM-{i:03d}: alpha beta gamma delta." for i in range(1, 31))
            body = json.dumps({
                "id": "chatcmpl-clamp", "model": req["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": lines}, "finish_reason": "length"}],
                "usage": {"prompt_tokens": 40, "completion_tokens": 256},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(ClampedOutputRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-o", model="gpt-5", protocol="openai_chat")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev = probe_output_cap(client, cfg)
            assert ev.status == "FAIL"
            assert "max_tokens" in ev.summary
        finally:
            client.close()
    finally:
        srv.close()


def test_v5_cost_estimator_and_ui_js_syntax():
    est = estimate_audit_cost("claude-opus-4-6", {"input_tokens": 20000, "output_tokens": 4000, "cache_read_tokens": 5000})
    assert est["matched_model_price"] is True
    assert est["estimated_usd"] > 0.4
    assert est["estimated_cny"] > 3.0

    # Verify embedded JS inside web/index.html parses with zero syntax errors using node if available
    import re as _re
    import shutil as _shutil
    import subprocess as _sp
    import tempfile as _tf

    html_text = (Path(__file__).resolve().parent.parent / "web" / "index.html").read_text(encoding="utf-8")
    m = _re.search(r"<script>(.*)</script>", html_text, flags=_re.S)
    assert m is not None
    node_exe = _shutil.which("node")
    if node_exe:
        with _tf.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as fp:
            fp.write(m.group(1))
            js_path = Path(fp.name)
        try:
            chk = _sp.run([node_exe, "--check", str(js_path)], capture_output=True, text=True)
            assert chk.returncode == 0, f"JS syntax error in web/index.html:\n{chk.stderr}"
        finally:
            js_path.unlink(missing_ok=True)


# ======================================================================
# 7. v6.0 Tests: Client UA Cloaking Trap & Physical Usage Speed Sanity
# ======================================================================


def test_v6_ua_cloaking_discriminatory_routing():
    class DiscriminatoryRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(ln)
            ua = (self.headers.get("User-Agent") or "").lower()
            # Serves real Claude to claude-cli UA, serves cheap deepseek to python-requests UA!
            if "claude-cli" in ua:
                resp = {
                    "id": "msg_01realcli", "model": "claude-sonnet-4-5",
                    "content": [{"type": "text", "text": '{"rand": 42, "prod": 247}'}],
                    "usage": {"input_tokens": 18, "output_tokens": 12},
                }
            else:
                resp = {
                    "id": "vllm_cheap99", "model": "deepseek-chat",
                    "content": [{"type": "text", "text": '<think>hmm</think>{"rand": 73, "prod": 247}'}],
                    "usage": {"input_tokens": 18, "output_tokens": 18},
                }
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(DiscriminatoryRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-u", model="claude-sonnet-4-5", protocol="anthropic")
        client = RelayClient(cfg)
        client.protocol = "anthropic"
        try:
            ev = probe_client_cloaking(client, cfg)
            assert ev.status == "FAIL"
            assert "UA" in ev.summary
        finally:
            client.close()
    finally:
        srv.close()


def test_v6_usage_physics_sanity():
    # Impossible physics: 2,000 output tokens/req in 150ms average -> 13,333 tok/s!
    ev = audit_usage_physics_sanity(
        {"output_tokens": 20000, "reasoning_tokens": 15000, "avg_latency_ms": 150.0, "ok_requests": 10},
        {"effective_tps": 45.0},
    )
    assert ev is not None and ev.status == "WARN"
    assert "违背物理生成速率常识" in ev.summary

    # Normal speed -> returns None (no false alarm)
    ev_ok = audit_usage_physics_sanity(
        {"output_tokens": 1200, "reasoning_tokens": 0, "avg_latency_ms": 1800.0, "ok_requests": 10},
        {"effective_tps": 65.0},
    )
    assert ev_ok is None


# ======================================================================
# 8. v7.0 Tests: Anti-OCR Bar Chart Vision, Custom-Op Expression Parser IQ, Latency Histogram
# ======================================================================


def test_v7_anti_ocr_chart_png_and_probe():
    chart = generate_chart_vision_image(random.Random(2026))
    raw = base64.b64decode(chart["png_b64"])
    assert raw.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(chart["bars"]) == 4
    assert chart["tallest_value"] == 95
    assert chart["shortest_value"] == 20

    # Simulate an OCR-middleware relay that guesses blindly because no numeric bar heights are printed!
    class BlindOcrRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(ln)
            body = json.dumps({
                "id": "chatcmpl-ocr", "model": "gpt-4o",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": '{"tallest": "Z", "shortest": "Z", "tallest_color": "pink", "tallest_value": 10}'}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 80, "completion_tokens": 20},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(BlindOcrRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-ocr", model="gpt-4o", protocol="openai_chat")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev = probe_chart_vision_anti_ocr(client, cfg)
            assert ev.status == "FAIL"
            assert "OCR" in ev.summary
        finally:
            client.close()
    finally:
        srv.close()


def test_v7_code_parser_sandbox_challenge_20_seeds():
    """Verify dynamic custom-operator recursive-descent parser IQ challenge across 20 seeds."""
    import re as _re

    for seed in range(500, 520):
        rng = random.Random(seed)
        q = _build_code_parser_challenge(rng)
        m = _re.search(r"x @ y = (\d+) \* x - (\d+) \* y", q["prompt"])
        assert m is not None
        k1, k2 = int(m.group(1)), int(m.group(2))
        good_solution = f"""```python
def eval_custom(expr):
    toks = []
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if c == ' ':
            i += 1
        elif '0' <= c <= '9':
            j = i
            while j < n and '0' <= expr[j] <= '9':
                j += 1
            toks.append(expr[i:j])
            i = j
        else:
            toks.append(c)
            i += 1
    pos = 0
    def p_add():
        nonlocal pos
        v = p_mul()
        while pos < len(toks) and toks[pos] == '+':
            pos += 1
            v += p_mul()
        return v
    def p_mul():
        nonlocal pos
        v = p_at()
        while pos < len(toks) and toks[pos] == '*':
            pos += 1
            v *= p_at()
        return v
    def p_at():
        nonlocal pos
        v = p_atom()
        while pos < len(toks) and toks[pos] == '@':
            pos += 1
            r = p_atom()
            v = {k1} * v - {k2} * r
        return v
    def p_atom():
        nonlocal pos
        if toks[pos] == '(':
            pos += 1
            v = p_add()
            pos += 1
            return v
        v = int(toks[pos])
        pos += 1
        return v
    return p_add()
```"""
        score, note = q["grader"](good_solution)
        assert score == 1.0, f"Seed {seed} failed: {note}"
        # eval() attempt must fail inside restricted builtins
        bad_eval, _ = q["grader"]("```python\ndef eval_custom(expr): return eval(expr)\n```")
        assert bad_eval == 0.0


def test_v7_latency_histogram_populated_in_audit(tmp_path: Path):
    srv = _MockServer(_make_openai_distribution_handler("42", "blue", "K"))
    store = BaselineStore(tmp_path)
    try:
        cfg = AuditConfig(
            base_url=srv.url, api_key="sk-lat", model="gpt-4o", protocol="openai_chat", mode="quick",
            run_protocol=False, run_tokenizer=False, run_fingerprint=True, run_smart_routing=False, run_cutoff=False, run_iq=False,
        )
        rep = run_full_audit(cfg, baseline_store=store)
        hist = rep.telemetry.get("latency_histogram")
        assert hist is not None
        assert len(hist["bins"]) == 8
        assert sum(hist["bins"]) >= 20
        assert "latency_jitter_cv" in rep.telemetry
        assert "p99_latency_ms" in rep.telemetry
    finally:
        srv.close()


# ======================================================================
# 9. v8.0 Tests: Bilingual Financial-Numeral + Double-Negation IQ (20 Seeds)
# ======================================================================


def test_v8_bilingual_nuance_iq_20_seeds():
    for seed in range(800, 820):
        rng = random.Random(seed)
        q = _build_bilingual_nuance(rng)
        assert len(q["expected"]["qualified"]) == 2
        good_json = json.dumps(q["expected"])
        score, note = q["grader"](good_json)
        assert score == 1.0, f"Seed {seed} failed: {note}"
        # Wrong subset must fail
        bad_score, _ = q["grader"](json.dumps({"qualified": [], "threshold_num": 0}))
        assert bad_score == 0.0


# ======================================================================
# 10. v9.0 Tests: CF-Ray IATA Edge PoP Decoder & Assistant Prefill Probe
# ======================================================================


def test_v9_net_forensics_cf_ray_and_prefill_probe():
    nf = analyze_network_headers({
        "cf-ray": "9a12bc34def56789-HKG",
        "server": "cloudflare",
        "x-oneapi-request-id": "req-1234",
    })
    assert "香港" in nf["edge_pop"]
    assert "OneAPI" in nf["gateway_guess"]
    assert any("HKG" in c for c in nf["clues"])

    class PrefillSeamlessRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            msgs = req.get("messages") or []
            assert msgs[-1]["role"] == "assistant"
            body = json.dumps({
                "id": "msg_01prefill",
                "model": req["model"],
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "42}"}],
                "usage": {"input_tokens": 18, "output_tokens": 2},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(PrefillSeamlessRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-pf", model="claude-sonnet-4-5", protocol="anthropic")
        client = RelayClient(cfg)
        client.protocol = "anthropic"
        try:
            ev = probe_assistant_prefill(client, cfg)
            assert ev is not None and ev.status == "PASS"
            assert ev.details["seamless"] is True
        finally:
            client.close()
    finally:
        srv.close()


# ======================================================================
# 11. v10.0 Tests: Zero-Cost Demo Sandbox & Strict Auto-Protocol Schema Guard
# ======================================================================


def test_v10_demo_sandbox_catches_all_traps(tmp_path: Path):
    store = BaselineStore(tmp_path)
    rep = run_demo_sandbox_audit(baseline_store=store)
    assert rep.verdict.authenticity_code == "LIKELY_FAKE_OR_WATERED"
    assert rep.verdict.trust_score <= 30
    by_id = {e.id: e for e in rep.evidences}
    assert by_id["crypto_thinking_signature"].status == "FAIL"
    assert by_id["adv_regex_brand_masking"].status == "FAIL"
    assert by_id["tok_fake_billing_split"].status == "FAIL"
    assert by_id["proto_hidden_sysprompt"].status == "FAIL"
    assert rep.telemetry["network_forensics"]["edge_pop"] == "中国香港 (HKG)"


def test_v10_auto_protocol_rejects_mismatched_200_schema():
    """Ensure auto-protocol falls back from anthropic to openai_chat even if relay returns 200 with OpenAI JSON on /v1/messages."""
    srv = _MockServer(_make_openai_distribution_handler("42", "blue", "K"))
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-auto", model="claude-opus-4-6", protocol="auto")
        client = RelayClient(cfg)
        try:
            proto, res = client.detect_protocol()
            assert proto == "openai_chat"
            assert res.ok is True
        finally:
            client.close()
    finally:
        srv.close()


# ======================================================================
# 12. v11.0 Tests: Anti-Reverse-Pool, 10-Dim Engineering IQ, Stealth, Budget Cap,
#     Passive Transparent Proxy, Webhook & Domain Anonymization
# ======================================================================


def test_v11_logit_bias_and_too_fast_flagship():
    from audit_engine.probes_v11 import (
        audit_too_fast_flagship_physics,
        probe_logit_bias_vocab_snipe,
    )

    class LogitBiasHonestRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            lb = req.get("logit_bias") or {}
            out = "seven" if lb.get("22") == -100 else "7"
            body = json.dumps({
                "id": "chatcmpl-lb",
                "model": req["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": out}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 1},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(LogitBiasHonestRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-lb", model="gpt-4o", protocol="openai_chat")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev = probe_logit_bias_vocab_snipe(client, cfg)
            assert ev is not None and ev.status == "PASS"
        finally:
            client.close()
    finally:
        srv.close()

    # Too-Fast-To-Be-Flagship physics trap
    from audit_engine.models import IQSummary

    cfg_opus = AuditConfig(base_url="https://x.com", api_key="sk", model="claude-opus-4-6")
    low_iq = IQSummary(total_score=58.0, iq_index=111, tier="B", tier_label="B", seed=1)
    ev_fast = audit_too_fast_flagship_physics(
        cfg_opus, {"effective_tps": 198.5, "chunk_count": 32, "fake_stream_suspected": False}, low_iq
    )
    assert ev_fast is not None and ev_fast.status == "FAIL"


def test_v11_hires_vision_multiturn_cache_and_parallel_tools():
    from audit_engine.png_gen import generate_hires_micro_image
    from audit_engine.probes_v11 import (
        probe_hires_vision_downscale,
        probe_multiturn_system_persistence,
        probe_parallel_tool_and_recovery,
        probe_prompt_cache_physics,
    )

    img = generate_hires_micro_image(random.Random(123))
    assert img["width"] == 1024 and img["height"] == 1024
    assert len(img["tl_code"]) == 3 and len(img["br_code"]) == 3
    assert base64.b64decode(img["png_b64"]).startswith(b"\x89PNG\r\n\x1a\n")

    class FullV11MockRelay(BaseHTTPRequestHandler):
        calls = 0

        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            FullV11MockRelay.calls += 1
            msgs = req.get("messages") or []
            sys_txt = ""
            for m in msgs:
                if m.get("role") == "system":
                    sys_txt = str(m.get("content", ""))

            if req.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                is_second = "OK-2" in str(msgs[-1].get("content", ""))
                chunk = {
                    "id": "chatcmpl-cache",
                    "model": req["model"],
                    "choices": [{"index": 0, "delta": {"content": "OK"}, "finish_reason": "stop"}],
                    "usage": {
                        "prompt_tokens": 1350,
                        "completion_tokens": 2,
                        "prompt_tokens_details": {"cached_tokens": 1200 if is_second else 0},
                    },
                }
                self.wfile.write(f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n".encode("utf-8"))
                return

            if req.get("tools"):
                has_tool_err = any(m.get("role") == "tool" and "EUR_ZONE" in str(m.get("content", "")) for m in msgs)
                if has_tool_err:
                    tcs = [{"id": "call_retry", "type": "function", "function": {"name": "get_fx_rate", "arguments": '{"base":"USD","quote":"EUR_ZONE"}'}}]
                else:
                    tcs = [
                        {"id": "c1", "type": "function", "function": {"name": "get_fx_rate", "arguments": '{"base":"USD","quote":"EUR"}'}},
                        {"id": "c2", "type": "function", "function": {"name": "get_tax_rule", "arguments": '{"country":"DE"}'}},
                        {"id": "c3", "type": "function", "function": {"name": "get_shipping_fee", "arguments": '{"city":"Berlin","tier":"express"}'}},
                    ]
                body = json.dumps({
                    "id": "chatcmpl-tools",
                    "model": req["model"],
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": tcs}, "finish_reason": "tool_calls"}],
                    "usage": {"prompt_tokens": 60, "completion_tokens": 30},
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            # Multi-turn persistence handler
            m_tag = re.search(r"\[SIG-\d{4}\]", sys_txt)
            tag = m_tag.group(0) if m_tag else ""
            first_u = next((str(m.get("content", "")) for m in msgs if m.get("role") == "user"), "")
            m_proj = re.search(r"Project=([A-Z]+), Port=(\d+)", first_u)
            if m_proj and "first turn" in str(msgs[-1].get("content", "")):
                ans = f"Project={m_proj.group(1)}, Port={m_proj.group(2)} {tag}"
            elif tag:
                ans = f"ACK {tag}"
            else:
                ans = '{"top_left": "AAA", "bottom_right": "BBB"}'

            body = json.dumps({
                "id": "chatcmpl-v11",
                "model": req["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": ans}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 40, "completion_tokens": 12},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(FullV11MockRelay)
    try:
        cfg = AuditConfig(base_url=srv.url, api_key="sk-v11", model="gpt-4o", protocol="openai_chat")
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            ev_cache = probe_prompt_cache_physics(client, cfg)
            assert ev_cache is not None and ev_cache.status == "PASS"

            ev_mt = probe_multiturn_system_persistence(client, cfg)
            assert ev_mt.status == "PASS"

            ev_pt = probe_parallel_tool_and_recovery(client, cfg)
            assert ev_pt.status == "PASS"

            ev_hr = probe_hires_vision_downscale(client, cfg)
            assert ev_hr.status == "WARN"  # wrong decoy codes AAA/BBB flagged cleanly
        finally:
            client.close()
    finally:
        srv.close()


def test_v11_practical_engineering_iq_sql_patch_rag():
    from audit_engine.probes_iq import (
        _build_rag_faithfulness_challenge,
        _build_sqlite_sql_challenge,
        _build_unified_diff_challenge,
    )

    rng = random.Random(202611)
    # 1. SQLite SQL Challenge + Read-Only Authorizer Security
    q_sql = _build_sqlite_sql_challenge(rng)
    good_sql = (
        "SELECT c.name, COALESCE(SUM(CASE WHEN o.status='paid' "
        "THEN o.amount - COALESCE(r.refund_amt, 0) ELSE 0 END), 0) AS net_spend "
        "FROM customers c LEFT JOIN orders o ON c.id = o.customer_id "
        "LEFT JOIN refunds r ON o.id = r.order_id GROUP BY c.id, c.name "
        "ORDER BY net_spend DESC, c.name ASC"
    )
    sc_ok, _ = q_sql["grader"](json.dumps({"sql": good_sql}))
    assert sc_ok == 1.0
    sc_evil, note_evil = q_sql["grader"]('{"sql": "DELETE FROM customers"}')
    assert sc_evil == 0.0

    # 2. Surgical Line-Patch Diff Challenge
    q_patch = _build_unified_diff_challenge(rng)
    good_patch = {
        "edits": [
            {"start_line": 11, "end_line": 11, "replacement": ["    if k <= 0 or k > len(nums):"]},
            {"start_line": 14, "end_line": 14, "replacement": ["    for i in range(len(nums) - k + 1):"]},
            {"start_line": 17, "end_line": 17, "replacement": ["        if any(x < 0 for x in win):"]},
        ]
    }
    sc_p, _ = q_patch["grader"](json.dumps(good_patch))
    assert sc_p == 1.0
    # Reject modifying protected clamp_window lines 1-6
    bad_patch = {"edits": [{"start_line": 1, "end_line": 2, "replacement": ["def clamp_window(a,b,c):", "    return a"]}]}
    sc_bad, _ = q_patch["grader"](json.dumps(bad_patch))
    assert sc_bad == 0.0

    # 3. Private Spec RAG Faithfulness + Honest Abstention
    q_rag = _build_rag_faithfulness_challenge(rng)
    sc_r, _ = q_rag["grader"](json.dumps(q_rag["expected"]))
    assert sc_r == 1.0


def test_v11_stealth_budget_cap_and_domain_anonymize(tmp_path: Path):
    from audit_engine.verdict import anonymize_report_dict, render_html_report

    seen_uas: list[str] = []

    class ExpensiveRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            seen_uas.append(self.headers.get("User-Agent", ""))
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            body = json.dumps({
                "id": "chatcmpl-bud",
                "model": req["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 2500, "completion_tokens": 500},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(ExpensiveRelay)
    try:
        cfg = AuditConfig(
            base_url=srv.url,
            api_key="sk-secret-key",
            model="claude-opus-4-6",
            protocol="openai_chat",
            mode="quick",
            stealth_mode=True,
            budget_cap_cny=0.30,  # ~1 request of Opus 2500in/500out is ~¥0.54 -> triggers cap fast!
        )
        rep = run_full_audit(cfg, baseline_store=BaselineStore(tmp_path))
        assert any("OpenAI/Python" in ua for ua in seen_uas)
        assert rep.telemetry["stealth_mode"] is True
        assert rep.telemetry["budget_cap_hit"] is True
        assert any(e.id == "budget_cap_guard" for e in rep.evidences)

        # Domain anonymization check
        rep_d = rep.to_dict()
        rep_d["config"]["base_url"] = "https://secret-private-relay.org/v1"
        anon = anonymize_report_dict(rep_d)
        assert "secret-private-relay.org" not in anon["config"]["base_url"]
        html_out = render_html_report(rep_d, anonymize_domain=True)
        assert "secret-private-relay.org" not in html_out
        assert "relay-masked.example" in html_out
    finally:
        srv.close()


def test_v11_passive_proxy_and_webhook_delivery():
    from audit_engine.monitor import send_webhook_alert
    from audit_engine.proxy_server import PassiveAuditProxy

    upstream_calls = [0]

    class UpstreamSwapRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            upstream_calls[0] += 1
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            ret_m = "gpt-4o-2024-11-20" if upstream_calls[0] == 1 else "deepseek-v3-sneaky"
            if req.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("cf-ray", "12345678-HKG")
                self.end_headers()
                c = {
                    "id": "chatcmpl-s1" if upstream_calls[0] == 1 else "ds_swap_02",
                    "model": ret_m,
                    "choices": [{"index": 0, "delta": {"content": "hello"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 50, "completion_tokens": 10},
                }
                self.wfile.write(f"data: {json.dumps(c)}\n\ndata: [DONE]\n\n".encode("utf-8"))
                return
            body = json.dumps({
                "id": "chatcmpl-s1" if upstream_calls[0] == 1 else "ds_swap_02",
                "model": ret_m,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 40, "completion_tokens": 8},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("cf-ray", "12345678-HKG")
            self.end_headers()
            self.wfile.write(body)

    webhook_got: list[dict] = []

    class WebhookReceiver(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            webhook_got.append(json.loads(self.rfile.read(ln).decode("utf-8")))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

    up_srv = _MockServer(UpstreamSwapRelay)
    wh_srv = _MockServer(WebhookReceiver)
    proxy = PassiveAuditProxy()
    try:
        st = proxy.start(up_srv.url, port=0)
        assert st["running"] is True
        px_url = st["listen_url"]

        # 1. Normal request through transparent proxy
        r1 = httpx.post(
            f"{px_url}/v1/chat/completions",
            headers={"Authorization": "Bearer sk-pass"},
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
            timeout=10.0,
        )
        assert r1.status_code == 200 and r1.json()["choices"][0]["message"]["content"] == "hi"

        # 2. Streaming SSE request where upstream silently swaps model + id prefix!
        with httpx.stream(
            "POST",
            f"{px_url}/v1/chat/completions",
            headers={"Authorization": "Bearer sk-pass"},
            json={"model": "gpt-4o", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
            timeout=10.0,
        ) as r2:
            assert r2.status_code == 200
            raw_sse = r2.read().decode("utf-8")
            assert "hello" in raw_sse

        st2 = proxy.status()
        assert st2["totals"]["requests"] == 2
        assert len(st2["alerts"]) >= 1  # caught silent model/id swap!

        # 3. Webhook alert delivery
        ok, detail = send_webhook_alert(f"{wh_srv.url}/feishu/hook", "Test Alert", ["Drift detected"])
        assert ok is True and len(webhook_got) == 1
        assert "msg_type" in webhook_got[0]
    finally:
        proxy.stop()
        up_srv.close()
        wh_srv.close()


def test_v11_plain_language_ai_summary_and_fallback(tmp_path: Path):
    from audit_engine.verdict import render_html_report

    # 1. Demo sandbox exercises LLM-generated plain_summary path
    rep = run_demo_sandbox_audit(baseline_store=BaselineStore(tmp_path))
    assert rep.plain_summary is not None
    assert rep.plain_summary["source"] == "llm"
    assert "【一句话结论】" in rep.plain_summary["content"]
    html_str = render_html_report(rep)
    assert "大白话体检结论（10 秒看懂）" in html_str

    # 2. When run_plain_summary=False, local zero-token fallback still provides clean plain Chinese
    srv = _MockServer(_make_openai_distribution_handler("42", "blue", "K"))
    try:
        cfg = AuditConfig(
            base_url=srv.url,
            api_key="sk-plain",
            model="gpt-6.2-sol",
            protocol="openai_chat",
            mode="quick",
            run_iq=False,
            run_protocol=False,
            run_tokenizer=False,
            run_plain_summary=False,
        )
        rep2 = run_full_audit(cfg, baseline_store=BaselineStore(tmp_path))
        assert rep2.plain_summary is not None
        assert rep2.plain_summary["source"] == "local_fallback"
        assert "【一句话结论】" in rep2.plain_summary["content"]
        assert "【最可能真实模型】" in rep2.plain_summary["content"]
        assert rep2.attribution["most_likely_model"]["model_name"]
    finally:
        srv.close()

    # 3. Verify calibrated 2026 attribution: 3-digit + high CJK compression + S-tier IQ on gpt-6.2-sol -> OpenAI gpt-6.2-sol!
    from audit_engine.attribution import infer_underlying_attribution
    from audit_engine.models import FingerprintSummary, IQSummary

    attr_sol = infer_underlying_attribution(
        claimed_model="gpt-6.2-sol",
        detected_protocol="openai_chat",
        evidences=[],
        fingerprint=FingerprintSummary(tokenizer_vector={"deltas": {"digits_30": 10, "cjk_32": 22}, "digit_cut_len": 3}),
        iq=IQSummary(total_score=93.3, iq_index=140, tier="S", tier_label="S 级", seed=118081),
        telemetry={"response_id_prefixes": {"chatcmpl-": 10}, "server_headers": {}},
    )
    assert attr_sol["most_likely_model"]["model_name"] == "gpt-6.2-sol"
    assert attr_sol["family_conflict"] is False


def test_http11_keepalive_after_heartbeat_and_403(tmp_path: Path):
    """Regression test: POST /api/heartbeat with body must drain socket so next POST on same keep-alive connection never hits 501 HTML."""
    import app as app_mod

    tok = "keepalive_tok_123"
    state = app_mod.AppState(app_token=tok)
    state.baseline_store = BaselineStore(tmp_path / "bl")
    state.history_store = HistoryStore(tmp_path / "hist")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app_mod.make_handler(state))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        with httpx.Client(http2=False) as c:
            # 1. Heartbeat with 2-byte '{}' body
            r1 = c.post(f"{base}/api/heartbeat?token={tok}", headers={"X-App-Token": tok}, content=b"{}")
            assert r1.status_code == 200 and r1.json()["ok"] is True
            # 2. Next POST on the EXACT SAME HTTP/1.1 keep-alive TCP socket!
            r2 = c.post(f"{base}/api/audit/demo?token={tok}", headers={"X-App-Token": tok}, content=b"{}")
            assert r2.status_code == 200 and "job_id" in r2.json()
            # 3. Unauthorized POST with body must also drain cleanly without breaking the next request!
            r3 = c.post(f"{base}/api/audit/start", content=b'{"base_url":"x"}')
            assert r3.status_code == 403 and "error" in r3.json()
            r4 = c.get(f"{base}/api/health")
            assert r4.status_code == 200 and r4.json()["ok"] is True
    finally:
        state.monitor.stop()
        state.passive_proxy.stop()
        srv.shutdown()
        srv.server_close()


def test_v11_1_modern_relay_antiban_and_temp_not_false_alarm(tmp_path: Path):
    """Normal relays with 140-token anti-ban system prompt & stripped temperature/stop on gpt-6.2-sol must NOT false-alarm as WARN/FAIL."""
    from audit_engine.probes_protocol import run_protocol_probes

    class NormalModernRelay(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(ln).decode("utf-8"))
            if req.get("top_logprobs") == 99:
                body = json.dumps({"error": {"message": "invalid top_logprobs", "type": "invalid_request_error"}}).encode("utf-8")
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
                c = {
                    "id": "chatcmpl-mod",
                    "object": "chat.completion.chunk",
                    "model": req["model"],
                    "choices": [{"index": 0, "delta": {"content": "1 2 3 4 5"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 140, "completion_tokens": 5},
                }
                self.wfile.write(f"data: {json.dumps(c)}\n\ndata: [DONE]\n\n".encode("utf-8"))
                return
            # Silently accepts temperature=99 (standard for 2026 unified reasoning models) and adds 140-tok anti-ban prompt!
            body = json.dumps({
                "id": "chatcmpl-mod",
                "model": req["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 140, "completion_tokens": 2},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = _MockServer(NormalModernRelay)
    try:
        cfg = AuditConfig(
            base_url=srv.url, api_key="sk-mod", model="gpt-6.2-sol",
            protocol="openai_chat", mode="quick", run_vision=False,
        )
        client = RelayClient(cfg)
        client.protocol = "openai_chat"
        try:
            evs, _ = run_protocol_probes(client, cfg)
            by_id = {e.id: e for e in evs}
            assert by_id["proto_error_schema"].status == "INFO"
            assert by_id["proto_error_schema"].score_impact == 0
            assert by_id["proto_hidden_sysprompt"].status == "INFO"
            assert by_id["proto_hidden_sysprompt"].score_impact == 0
        finally:
            client.close()
    finally:
        srv.close()


def test_v11_2_doubled_iq_bank_all_31_generators():
    """Verify all 14 new extended dynamic IQ generators produce mathematically exact ground truth and doubled counts."""
    from audit_engine.probes_iq import run_iq_suite
    from audit_engine.probes_iq_extended import get_extended_iq_builders

    rng = random.Random(20261122)
    ext = get_extended_iq_builders()
    assert len(ext) == 14

    # Validate every single new generator generates cleanly and scores 1.0 on exact expected answers!
    q_simp = ext["simpson"](rng)
    s, _ = q_simp["grader"](json.dumps({
        "overall_winner": "B", "subgroup_winner": "A",
        "clinic_a_overall_pct": q_simp["expected"]["a_pct"],
        "clinic_b_overall_pct": q_simp["expected"]["b_pct"],
    }))
    assert s == 1.0

    q_harm = ext["harmonic"](rng)
    assert q_harm["grader"](json.dumps({"exact_fraction": q_harm["expected"], "decimal": 0}))[0] == 1.0

    q_sat = ext["sat5"](rng)
    assert q_sat["grader"](json.dumps(q_sat["expected"]))[0] == 1.0

    q_dag = ext["dag"](rng)
    assert q_dag["grader"](json.dumps({"min_hours": q_dag["expected"]}))[0] == 1.0

    q_tier = ext["tiered_cn"](rng)
    assert q_tier["grader"](json.dumps({"fee_yuan": q_tier["expected"]}))[0] == 1.0

    q_ie = ext["comb_ie"](rng)
    assert q_ie["grader"](json.dumps({"count": q_ie["expected"]}))[0] == 1.0

    q_mp = ext["modpow"](rng)
    assert q_mp["grader"](json.dumps({"remainder": q_mp["expected"]}))[0] == 1.0

    q_dj = ext["dijkstra"](rng)
    assert q_dj["grader"](json.dumps({"min_cost": q_dj["expected"]}))[0] == 1.0

    q_cl = ext["closure"](rng)
    assert q_cl["grader"](json.dumps({"result": q_cl["expected"]}))[0] == 1.0

    q_die = ext["die3d"](rng)
    assert q_die["grader"](json.dumps(q_die["expected"]))[0] == 1.0

    q_xf = ext["instr_xform"](rng)
    assert q_xf["grader"](json.dumps(q_xf["expected"]))[0] == 1.0

    q_rag = ext["rag_amend"](rng)
    assert q_rag["grader"](json.dumps(q_rag["expected"]))[0] == 1.0

    q_sql = ext["sql_having"](rng)
    good_sql = "SELECT dept, MAX(salary) AS top_sal, SUM(salary) AS total_sal FROM staff GROUP BY dept HAVING COUNT(*) >= 2 ORDER BY top_sal DESC, total_sal DESC, dept ASC"
    assert q_sql["grader"](json.dumps({"sql": good_sql}))[0] == 1.0

    q_dp = ext["dp_sandbox"](rng)
    max_s = 3 if "1..3" in q_dp["prompt"] else 2
    dp_code = f"""```python
def min_journey_cost(costs, pen):
    n = len(costs)
    if n == 0: return 0
    if n == 1: return costs[0]
    dp = [10**18] * n
    dp[0] = costs[0]
    for i in range(1, n):
        best = dp[i - 1]
        for s in range(2, {max_s} + 1):
            if i - s >= 0:
                best = min(best, dp[i - s] + pen * (s - 1))
        dp[i] = best + costs[i]
    return dp[-1]
```"""
    assert q_dp["grader"](dp_code)[0] == 1.0

    # Verify doubled counts in quick (16), standard (31), deep (34+)
    srv = _MockServer(_make_openai_distribution_handler("42", "blue", "K"))
    try:
        for mode_name, min_q in [("quick", 16), ("standard", 30), ("deep", 34)]:
            cfg = AuditConfig(
                base_url=srv.url, api_key="sk-iq", model="gpt-6.2-sol",
                protocol="openai_chat", mode=mode_name, run_long_context=False, iq_seed=998877,
            )
            client = RelayClient(cfg)
            client.protocol = "openai_chat"
            try:
                _, summary = run_iq_suite(client, cfg)
                assert len(summary.questions) >= min_q, f"{mode_name} had only {len(summary.questions)} questions"
                assert len(summary.dimension_scores) == 9  # all 9 non-long-ctx dims covered even in quick!
            finally:
                client.close()
    finally:
        srv.close()

