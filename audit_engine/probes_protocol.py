"""L1 Cryptographic & Protocol Forensics Probes.

Follows zero-trust auditing: ignores self-reported model strings unless
corroborated by non-spoofable protocol, cryptographic, error-schema, and
capability artifacts.
"""

from __future__ import annotations

import base64
import json
import random
import re
from typing import Any, Callable

from .client import RelayClient
from .models import AuditConfig, EvidenceItem
from .png_gen import generate_vision_probe_image

ProgressCb = Callable[[str, str], None]


def _is_valid_base64_blob(val: str) -> bool:
    if not val or len(val) < 40:
        return False
    # Support standard & url-safe base64
    cleaned = val.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", cleaned):
        return False
    try:
        pad = "=" * ((4 - len(cleaned) % 4) % 4)
        raw = base64.urlsafe_b64decode(cleaned + pad)
        return len(raw) >= 24
    except Exception:
        return False


def _tamper_signature(sig: str) -> str:
    """Flip one character in the middle of a base64 signature without breaking length."""
    if len(sig) < 12:
        return sig + "X"
    mid = len(sig) // 2
    orig = sig[mid]
    replacement = "A" if orig != "A" else "B"
    return sig[:mid] + replacement + sig[mid + 1 :]


def _classify_error_schema(status: int, raw_json: dict[str, Any] | None, raw_text: str) -> list[str]:
    clues: list[str] = []
    txt = (raw_text or "").lower()

    if isinstance(raw_json, dict):
        if raw_json.get("type") == "error" and isinstance(raw_json.get("error"), dict):
            et = raw_json["error"].get("type", "")
            if et in (
                "invalid_request_error",
                "authentication_error",
                "rate_limit_error",
                "overloaded_error",
            ):
                clues.append("Anthropic 原生错误 Schema (type='error' + error.type)")
        elif isinstance(raw_json.get("error"), dict):
            err = raw_json["error"]
            keys = set(err.keys())
            if {"message", "type", "param", "code"}.issubset(keys):
                clues.append("OpenAI 原生错误 Schema (message/type/param/code 四字段完整)")
            elif "code" in keys and "status" in keys:
                clues.append("Google Gemini 原生错误 Schema (error.code + error.status)")
            elif "message" in keys and "type" in keys:
                if "one_api" in txt or "new_api" in txt or "rix_api" in txt:
                    clues.append("OneAPI / NewAPI 中转网关错误包装")
                else:
                    clues.append("类 OpenAI 兼容网关错误 Schema")
        elif "detail" in raw_json and isinstance(raw_json.get("detail"), (list, str)):
            clues.append("FastAPI / vLLM / SGLang / 自建开源推理框架错误 Schema (detail)")
        elif "object" in raw_json and raw_json.get("object") == "error":
            clues.append("vLLM / 开源 OpenAI 兼容服务端错误 Schema (object='error')")

    if "oneapi" in txt or "one-api" in txt or "new-api" in txt or "newapi" in txt:
        clues.append("响应文本暴露 OneAPI / NewAPI 网关关键字")
    if "litellm" in txt:
        clues.append("响应文本暴露 LiteLLM 代理关键字")
    if "openrouter" in txt:
        clues.append("响应文本暴露 OpenRouter 路由关键字")
    if "pydantic" in txt or "validation error" in txt:
        clues.append("暴露 Python FastAPI/Pydantic 校验报错（常见于自建 vLLM/SGLang 开源部署）")
    if "deepseek" in txt:
        clues.append("报错信息泄露 DeepSeek 后端特征")
    if "dashscope" in txt or "qwen" in txt:
        clues.append("报错信息泄露阿里云 DashScope / Qwen 后端特征")
    if "zhipu" in txt or "bigmodel" in txt:
        clues.append("报错信息泄露智谱 GLM 后端特征")
    if "bedrock" in txt or "vertex" in txt:
        clues.append("报错信息暴露云托管代理 (AWS Bedrock / GCP Vertex)")

    if not clues and status >= 400:
        clues.append(f"非标准错误格式 (HTTP {status})")
    return clues


def run_protocol_probes(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> tuple[list[EvidenceItem], list[str]]:
    """Run all L1 cryptographic, protocol, caching, error-schema, tool, and vision probes."""
    evidences: list[EvidenceItem] = []
    engine_clues: list[str] = []
    proto = client.protocol
    model_low = config.model.lower()

    def notify(step: str, msg: str) -> None:
        if emit:
            emit(step, msg)

    # ------------------------------------------------------------------
    # Probe 1: Streaming SSE Framing, Headers, ID Prefix & Model Echo
    # ------------------------------------------------------------------
    notify("protocol_sse", "探测流式 SSE 协议结构、响应头、ID 前缀与首字延迟 (TTFT)...")
    sse_res = client.chat(
        messages=[{"role": "user", "content": "Count from 1 to 5 separated by spaces."}],
        max_tokens=48,
        temperature=0.0,
        stream=True,
    )
    if sse_res.ok:
        rid = sse_res.response_id
        ret_model = sse_res.returned_model
        hdrs = sse_res.headers
        sse_anomalies: list[str] = []
        sse_proofs: list[str] = []

        # Analyze ID prefix vs claimed model / protocol
        if proto == "anthropic":
            if rid.startswith("msg_"):
                sse_proofs.append(f"响应 ID 符合 Anthropic 格式 (`{rid[:14]}...`)")
            elif rid:
                sse_anomalies.append(f"Anthropic 协议返回异常 ID 前缀: `{rid[:20]}`（官方应为 `msg_`）")
            if "message_start" in sse_res.sse_events and "content_block_delta" in sse_res.sse_events:
                sse_proofs.append("SSE 事件流符合 Anthropic 原生序列 (message_start → content_block_delta)")
            else:
                sse_anomalies.append(f"SSE 事件序列不完整: {sse_res.sse_events[:8]}")
        elif proto == "openai_chat":
            if rid.startswith("chatcmpl-"):
                sse_proofs.append(f"响应 ID 符合 OpenAI 格式 (`{rid[:18]}...`)")
            elif rid.startswith("gen-"):
                engine_clues.append("ID 前缀 `gen-`（典型 OpenRouter 路由特征）")
            elif rid.startswith("cmpl-") or rid.startswith("chat-"):
                engine_clues.append(f"ID 前缀 `{rid[:12]}`（常见于 vLLM / 开源兼容网关）")
            elif rid:
                engine_clues.append(f"非标准 OpenAI ID 前缀: `{rid[:18]}`")

            if sse_res.system_fingerprint:
                sse_proofs.append(f"存在 system_fingerprint: `{sse_res.system_fingerprint}`")
            elif any(k in model_low for k in ("gpt-4", "gpt-5", "o1", "o3", "o4")):
                sse_anomalies.append("未返回 OpenAI `system_fingerprint` 字段（部分代理会剥离或非官方端点）")

        # Check for leaked <think> tags inside text (huge tell for DeepSeek-R1 / Qwen3 masquerading!)
        if "<think>" in sse_res.text or "</think>" in sse_res.text:
            if any(k in model_low for k in ("claude", "gpt", "o1", "o3", "o4", "gemini")):
                sse_anomalies.append(
                    "正文泄露 `<think>...</think>` 开源思考标签！Claude/GPT/Gemini 官方不会在正文输出此标签（高度疑似开源推理模型套壳）"
                )
                engine_clues.append("正文泄露 `<think>` 标签（常见于 DeepSeek-R1 / QwQ / Qwen3 开源部署）")

        # Inspect relay/proxy headers
        for hk, hv in hdrs.items():
            if any(x in hk for x in ("oneapi", "newapi", "rixapi", "veloera", "litellm")):
                engine_clues.append(f"响应头暴露中转网关 `{hk}: {hv}`")
            if hk == "anthropic-organization-id":
                sse_proofs.append("存在 `anthropic-organization-id` 响应头")
            if hk == "openai-processing-ms":
                sse_proofs.append(f"存在 `openai-processing-ms: {hv}` 官方处理耗时头")

        # Model mismatch check
        if ret_model and ret_model.lower() != model_low:
            # Allow versioned snapshots like claude-sonnet-4-20250514 for claude-sonnet-4
            if not (ret_model.lower().startswith(model_low) or model_low.startswith(ret_model.lower())):
                sse_anomalies.append(
                    f"返回模型名 `{ret_model}` 与请求模型 `{config.model}` 明显不匹配！"
                )
            else:
                sse_proofs.append(f"解析到具体快照版本: `{ret_model}`")

        status = "FAIL" if any("<think>" in a or "明显不匹配" in a for a in sse_anomalies) else (
            "WARN" if sse_anomalies else "PASS"
        )
        evidences.append(
            EvidenceItem(
                id="proto_sse_metadata",
                layer="L1_PROTOCOL",
                title="流式 SSE 结构与响应头元数据取证",
                status=status,
                severity="HIGH" if status == "FAIL" else ("MEDIUM" if status == "WARN" else "INFO"),
                summary=(
                    "；".join(sse_anomalies)
                    if sse_anomalies
                    else ("；".join(sse_proofs) if sse_proofs else f"流式连通正常 (TTFT {round(sse_res.ttft_ms or 0)}ms)")
                ),
                details={
                    "protocol": proto,
                    "response_id": rid,
                    "returned_model": ret_model,
                    "system_fingerprint": sse_res.system_fingerprint,
                    "ttft_ms": round(sse_res.ttft_ms, 1) if sse_res.ttft_ms is not None else None,
                    "total_latency_ms": round(sse_res.latency_ms, 1),
                    "sse_events_sample": sse_res.sse_events[:15],
                    "interesting_headers": {
                        k: v
                        for k, v in hdrs.items()
                        if any(
                            w in k
                            for w in (
                                "server",
                                "via",
                                "cf-",
                                "openai",
                                "anthropic",
                                "oneapi",
                                "newapi",
                                "request-id",
                                "ratelimit",
                                "x-powered",
                            )
                        )
                    },
                },
                score_impact=-25 if status == "FAIL" else (-6 if status == "WARN" else 5),
            )
        )
    else:
        evidences.append(
            EvidenceItem(
                id="proto_sse_metadata",
                layer="L1_PROTOCOL",
                title="流式 SSE 结构与响应头元数据取证",
                status="WARN",
                severity="MEDIUM",
                summary=f"流式 SSE 请求失败或被中转站禁用: {sse_res.error[:140]}",
                details={"status_code": sse_res.status_code, "error": sse_res.error},
                score_impact=-8,
            )
        )

    # ------------------------------------------------------------------
    # Probe 2: Cryptographic Thinking Signature & 1-Byte Tamper Replay
    # (Gold-Standard L1 Proof for Anthropic Claude + Thinking Check for others)
    # ------------------------------------------------------------------
    if proto == "anthropic" or "claude" in model_low:
        notify("protocol_crypto", "执行 Claude Extended Thinking 加密签名获取与 1 字节篡改验签测试...")
        if proto == "anthropic":
            think_res = client.raw_post(
                {
                    "model": config.model,
                    "max_tokens": 1500,
                    "thinking": {"type": "enabled", "budget_tokens": 1024},
                    "messages": [
                        {
                            "role": "user",
                            "content": "What is 17 * 23 + 19? Show brief answer only.",
                        }
                    ],
                },
                protocol="anthropic",
            )
            if think_res.ok and think_res.thinking_signature:
                sig = think_res.thinking_signature
                sig_valid_b64 = _is_valid_base64_blob(sig)
                sig_len = len(sig)

                # Turn 2A: Replay unmodified signature (real Anthropic must accept 200)
                assistant_blocks = []
                if think_res.raw_json and isinstance(think_res.raw_json.get("content"), list):
                    assistant_blocks = think_res.raw_json["content"]
                else:
                    assistant_blocks = [
                        {"type": "thinking", "thinking": think_res.thinking, "signature": sig},
                        {"type": "text", "text": think_res.text or "410"},
                    ]

                replay_ok_res = client.raw_post(
                    {
                        "model": config.model,
                        "max_tokens": 1500,
                        "thinking": {"type": "enabled", "budget_tokens": 1024},
                        "messages": [
                            {
                                "role": "user",
                                "content": "What is 17 * 23 + 19? Show brief answer only.",
                            },
                            {"role": "assistant", "content": assistant_blocks},
                            {"role": "user", "content": "Multiply that result by 2. Reply only the number."},
                        ],
                    },
                    protocol="anthropic",
                )

                # Turn 2B: Replay with 1-byte tampered signature (real Anthropic MUST reject with HTTP 400!)
                tampered_blocks = json.loads(json.dumps(assistant_blocks))
                for blk in tampered_blocks:
                    if isinstance(blk, dict) and blk.get("type") == "thinking" and blk.get("signature"):
                        blk["signature"] = _tamper_signature(str(blk["signature"]))
                        break

                tamper_res = client.raw_post(
                    {
                        "model": config.model,
                        "max_tokens": 1500,
                        "thinking": {"type": "enabled", "budget_tokens": 1024},
                        "messages": [
                            {
                                "role": "user",
                                "content": "What is 17 * 23 + 19? Show brief answer only.",
                            },
                            {"role": "assistant", "content": tampered_blocks},
                            {"role": "user", "content": "Multiply that result by 2. Reply only the number."},
                        ],
                    },
                    protocol="anthropic",
                )

                tamper_rejected = (not tamper_res.ok) and tamper_res.status_code == 400 and (
                    "signature" in (tamper_res.raw_text or "").lower()
                    or "invalid" in (tamper_res.raw_text or "").lower()
                )

                if sig_valid_b64 and sig_len >= 80 and replay_ok_res.ok and tamper_rejected:
                    engine_clues.append("通过 Anthropic Thinking 加密签名 + 篡改拒收验签（官方级密码学铁证）")
                    evidences.append(
                        EvidenceItem(
                            id="crypto_thinking_signature",
                            layer="L1_CRYPTO",
                            title="Claude Thinking 密码学签名与篡改验签",
                            status="PASS",
                            severity="CRITICAL",
                            summary=(
                                f"强密码学铁证通过！返回有效加密签名（长度 {sig_len} 字符），"
                                f"原样回传返回 200，篡改 1 字节签名被服务端严格拒收 (HTTP 400)。"
                            ),
                            details={
                                "signature_length": sig_len,
                                "signature_preview": f"{sig[:28]}...{sig[-16:]}",
                                "valid_base64": sig_valid_b64,
                                "unmodified_replay_status": replay_ok_res.status_code,
                                "tampered_replay_status": tamper_res.status_code,
                                "tampered_error": tamper_res.error[:240],
                            },
                            score_impact=32,
                        )
                    )
                elif tamper_res.ok:
                    evidences.append(
                        EvidenceItem(
                            id="crypto_thinking_signature",
                            layer="L1_CRYPTO",
                            title="Claude Thinking 密码学签名与篡改验签",
                            status="FAIL",
                            severity="CRITICAL",
                            summary=(
                                "严重伪造证据！篡改 1 字节 Thinking 签名后服务端竟然返回 HTTP 200 放行，"
                                "说明后端并未经过 Anthropic 官方私钥验签（高度疑似套壳或伪造签名）！"
                            ),
                            details={
                                "signature_length": sig_len,
                                "tampered_replay_status": tamper_res.status_code,
                                "tampered_response_text": tamper_res.text[:200],
                            },
                            score_impact=-40,
                        )
                    )
                else:
                    evidences.append(
                        EvidenceItem(
                            id="crypto_thinking_signature",
                            layer="L1_CRYPTO",
                            title="Claude Thinking 密码学签名与篡改验签",
                            status="WARN",
                            severity="HIGH",
                            summary=(
                                f"返回了签名 (len={sig_len})，但回传校验表现异常 "
                                f"(原样={replay_ok_res.status_code}, 篡改={tamper_res.status_code})。"
                            ),
                            details={
                                "signature_length": sig_len,
                                "valid_base64": sig_valid_b64,
                                "unmodified_replay_status": replay_ok_res.status_code,
                                "tampered_replay_status": tamper_res.status_code,
                                "tampered_error": tamper_res.error[:240],
                            },
                            score_impact=-10,
                        )
                    )
            elif think_res.ok and not think_res.thinking_signature:
                has_xml_think = "<think>" in (think_res.text or "")
                evidences.append(
                    EvidenceItem(
                        id="crypto_thinking_signature",
                        layer="L1_CRYPTO",
                        title="Claude Thinking 密码学签名与篡改验签",
                        status="FAIL",
                        severity="CRITICAL",
                        summary=(
                            "开启 Extended Thinking 后返回 HTTP 200，但完全缺失官方加密 `signature` 字段"
                            + ("，且正文中出现 `<think>` 开源标签（明显套壳）！" if has_xml_think else "（签名被剥离或非官方 Claude 后端）！")
                        ),
                        details={
                            "returned_thinking_len": len(think_res.thinking),
                            "has_xml_think_tag": has_xml_think,
                            "raw_snippet": think_res.raw_text[:350],
                        },
                        score_impact=-35,
                    )
                )
            else:
                # Could be an older Claude model without extended thinking (e.g. Haiku 3 / Sonnet 3.5)
                expects_thinking = any(
                    k in model_low for k in ("3-7", "3.7", "sonnet-4", "opus-4", "haiku-4", "4-5", "4.5", "4-6", "4.6")
                )
                evidences.append(
                    EvidenceItem(
                        id="crypto_thinking_signature",
                        layer="L1_CRYPTO",
                        title="Claude Thinking 密码学签名与篡改验签",
                        status="FAIL" if expects_thinking else "INFO",
                        severity="HIGH" if expects_thinking else "INFO",
                        summary=(
                            f"该 Claude 版本应支持 Extended Thinking，但端点报错拒绝: {think_res.error[:180]}"
                            if expects_thinking
                            else f"端点不支持 Extended Thinking（旧版模型属正常，无法取得签名铁证）: {think_res.error[:150]}"
                        ),
                        details={"status_code": think_res.status_code, "error": think_res.error[:300]},
                        score_impact=-20 if expects_thinking else 0,
                    )
                )
        else:
            evidences.append(
                EvidenceItem(
                    id="crypto_thinking_signature",
                    layer="L1_CRYPTO",
                    title="Claude Thinking 密码学签名探针",
                    status="INFO",
                    severity="INFO",
                    summary="当前通过 OpenAI 兼容协议调用 Claude，该协议层剥离了 Anthropic 原生 Thinking Signature，无法进行私钥验签（建议切换到 Anthropic `/v1/messages` 协议复测）。",
                    details={"active_protocol": proto},
                    score_impact=0,
                )
            )

    # ------------------------------------------------------------------
    # Probe 3: Parameter Boundary & Error Schema Fingerprinting
    # ------------------------------------------------------------------
    notify("protocol_error_fp", "发送参数边界异常探针，识别真实底层推理引擎错误 Schema...")
    err_clues: list[str] = []
    err_records: list[dict[str, Any]] = []

    if proto == "anthropic":
        bad_payloads = [
            ("max_tokens_zero", {"model": config.model, "max_tokens": 0, "messages": [{"role": "user", "content": "hi"}]}),
            (
                "unknown_field",
                {
                    "model": config.model,
                    "max_tokens": 16,
                    "__audit_invalid_field__": True,
                    "messages": [{"role": "user", "content": "hi"}],
                },
            ),
        ]
    elif proto == "gemini":
        bad_payloads = [
            (
                "invalid_temp",
                {
                    "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
                    "generationConfig": {"temperature": 99.0, "maxOutputTokens": 16},
                },
            ),
        ]
    else:
        bad_payloads = [
            (
                "invalid_temp_high",
                {
                    "model": config.model,
                    "messages": [{"role": "user", "content": "hi"}],
                    "temperature": 99.0,
                    "max_tokens": 16,
                },
            ),
            (
                "invalid_top_logprobs",
                {
                    "model": config.model,
                    "messages": [{"role": "user", "content": "hi"}],
                    "logprobs": True,
                    "top_logprobs": 99,
                    "max_tokens": 8,
                },
            ),
        ]

    accepted_temp_only = False
    accepted_non_temp_illegal = False
    for name, payload in bad_payloads:
        r = client.raw_post(payload, protocol=proto)
        clues = _classify_error_schema(r.status_code, r.raw_json, r.raw_text)
        err_clues.extend(clues)
        if r.ok:
            if "temp" in name:
                accepted_temp_only = True
            else:
                accepted_non_temp_illegal = True
        err_records.append(
            {
                "probe": name,
                "status_code": r.status_code,
                "accepted_unexpectedly": r.ok,
                "clues": clues,
                "snippet": (r.raw_text or "")[:280],
            }
        )

    unique_err_clues = list(dict.fromkeys(err_clues))
    engine_clues.extend(unique_err_clues)

    # Check for cross-vendor leak in error messages!
    cross_vendor_leak = False
    leak_keywords = []
    if any(k in model_low for k in ("claude", "fable")):
        leak_keywords = ["deepseek", "qwen", "dashscope", "zhipu", "bigmodel", "vllm", "pydantic"]
    elif any(k in model_low for k in ("gpt-", "o1", "o3", "o4", "astra", "sol")):
        leak_keywords = ["deepseek", "qwen", "dashscope", "zhipu", "bigmodel", "vllm", "pydantic"]
    elif any(k in model_low for k in ("gemini", "neon", "argon")):
        leak_keywords = ["deepseek", "qwen", "zhipu", "vllm", "pydantic"]

    all_err_text = " ".join(x["snippet"].lower() for x in err_records)
    leaked_hits = [kw for kw in leak_keywords if kw in all_err_text]
    if leaked_hits:
        cross_vendor_leak = True

    if cross_vendor_leak:
        err_status, err_sev, err_imp = "FAIL", "HIGH", -30
        err_summary = f"异常报错里直接暴露了别家厂商或开源框架名称（{', '.join(leaked_hits)}），高度疑似套壳冒充！"
    elif accepted_non_temp_illegal:
        err_status, err_sev, err_imp = "WARN", "LOW", -4
        err_summary = "中转站把部分明显越界的参数（如 top_logprobs=99 或 max_tokens=0）静默过滤掉了，说明网关做了参数兼容清洗（不一定代表假模型）。"
    elif accepted_temp_only:
        err_status, err_sev, err_imp = "INFO", "INFO", 0
        err_summary = "中转站自动忽略了温度参数（现在的新代大模型官方大多也不支持调温度，属于中转站防报错的正常兼容处理，不代表假货）。"
    else:
        err_status, err_sev, err_imp = "PASS", "INFO", 6
        err_summary = (
            "参数边界校验正常；识别到底层接口特征：" + "；".join(unique_err_clues[:3])
            if unique_err_clues
            else "参数边界校验正常，接口按规范拦截了非法请求。"
        )

    evidences.append(
        EvidenceItem(
            id="proto_error_schema",
            layer="L1_PROTOCOL",
            title="接口报错特征与参数校验",
            status=err_status,
            severity=err_sev,
            summary=err_summary,
            details={"probes": err_records, "schema_clues": unique_err_clues, "leaked_hits": leaked_hits},
            score_impact=err_imp,
        )
    )

    # ------------------------------------------------------------------
    # Probe 4: Hidden System Prompt Injection & Prompt Caching Threshold
    # ------------------------------------------------------------------
    notify("protocol_hidden_prompt", "检测中转站是否额外注入防封/隐藏提示词与缓存特征...")
    hi_res = client.chat(
        messages=[{"role": "user", "content": "Hi"}],
        max_tokens=8,
        temperature=0.0,
    )
    if hi_res.ok:
        in_tok = hi_res.input_tokens
        # Note: Most legitimate third-party relays inject a small 50-260 token anti-ban system prompt.
        # Only warn on heavy overhead (>=280) and FAIL on extreme injection/inflation (>=500)!
        if in_tok >= 500:
            evidences.append(
                EvidenceItem(
                    id="proto_hidden_sysprompt",
                    layer="L1_PROTOCOL",
                    title="防封提示词与空载扣费检测",
                    status="FAIL",
                    severity="HIGH",
                    summary=(
                        f"只发了一个 'Hi' 就扣了 {in_tok} 个输入字头（远超常见防封提示词长度），"
                        "说明中转站暗中塞了超长隐藏提示词（可能强行洗脑伪装身份，或每次对话白白多扣不少钱）。"
                    ),
                    details={"prompt": "Hi", "reported_input_tokens": in_tok, "normal_antiban_max": 280},
                    score_impact=-18,
                )
            )
        elif in_tok >= 280:
            evidences.append(
                EvidenceItem(
                    id="proto_hidden_sysprompt",
                    layer="L1_PROTOCOL",
                    title="防封提示词与空载扣费检测",
                    status="WARN",
                    severity="LOW",
                    summary=(
                        f"只发 'Hi' 扣了 {in_tok} 个输入字头，中转站自带的防封/固定系统提示词偏长，"
                        "一般不影响智商，但每轮对话会多扣一点输入费用。"
                    ),
                    details={"prompt": "Hi", "reported_input_tokens": in_tok, "normal_antiban_max": 280},
                    score_impact=-4,
                )
            )
        elif in_tok >= 45:
            evidences.append(
                EvidenceItem(
                    id="proto_hidden_sysprompt",
                    layer="L1_PROTOCOL",
                    title="防封提示词与空载扣费检测",
                    status="INFO",
                    severity="INFO",
                    summary=(
                        f"检测到约 {in_tok} 个字头的固定前缀（绝大多数中转站都会加一段防封提示词，属正常现象，不影响正常使用）。"
                    ),
                    details={"prompt": "Hi", "reported_input_tokens": in_tok},
                    score_impact=0,
                )
            )
        elif in_tok > 0:
            evidences.append(
                EvidenceItem(
                    id="proto_hidden_sysprompt",
                    layer="L1_PROTOCOL",
                    title="防封提示词与空载扣费检测",
                    status="PASS",
                    severity="INFO",
                    summary=f"空载输入非常干净（仅 {in_tok} 字头），没有偷偷多塞隐藏提示词。",
                    details={"prompt": "Hi", "reported_input_tokens": in_tok},
                    score_impact=5,
                )
            )
        else:
            evidences.append(
                EvidenceItem(
                    id="proto_hidden_sysprompt",
                    layer="L1_PROTOCOL",
                    title="防封提示词与空载扣费检测",
                    status="INFO",
                    severity="INFO",
                    summary="服务端未返回本次输入字数统计，跳过空载检查。",
                    details={"reported_input_tokens": in_tok},
                    score_impact=0,
                )
            )

    # Prompt Caching Probe (Standard & Deep modes)
    if config.mode in ("standard", "deep") and proto in ("anthropic", "openai_chat"):
        # Deterministic ~1,350-token cacheable block (exceeds 1,024-token cache minimum)
        cache_block = "\n".join(
            f"Record #{i:03d}: Telemetry calibration entry alpha-{i*7 % 97:02d} beta-{i*13 % 89:02d} gamma-verified."
            for i in range(1, 76)
        )
        if proto == "anthropic":
            c_payload = {
                "model": config.model,
                "max_tokens": 16,
                "temperature": 0.0,
                "system": [
                    {
                        "type": "text",
                        "text": cache_block,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                "messages": [{"role": "user", "content": "Reply with the number of Record #075 only."}],
            }
            c1 = client.raw_post(c_payload, protocol="anthropic")
            c2 = client.raw_post(c_payload, protocol="anthropic")
            if c1.ok and c2.ok:
                hit_create = c1.cache_creation_tokens > 0 or c1.cache_read_tokens > 0
                hit_read = c2.cache_read_tokens > 0
                if hit_read:
                    evidences.append(
                        EvidenceItem(
                            id="proto_prompt_cache",
                            layer="L1_PROTOCOL",
                            title="官方 Prompt Cache 缓存命中验证",
                            status="PASS",
                            severity="MEDIUM",
                            summary=(
                                f"二次相同长前缀成功命中官方 Prompt Cache "
                                f"(首呼 write={c1.cache_creation_tokens}/read={c1.cache_read_tokens}, "
                                f"二呼 read={c2.cache_read_tokens})。"
                            ),
                            details={
                                "call1_cache_create": c1.cache_creation_tokens,
                                "call1_cache_read": c1.cache_read_tokens,
                                "call2_cache_read": c2.cache_read_tokens,
                                "call1_input": c1.input_tokens,
                            },
                            score_impact=10,
                        )
                    )
                else:
                    # Step 2: Escalate to ~2,400 tokens to distinguish 2048-min models (Haiku/certain Opus) vs broken caching!
                    cache_block_2k = "\n".join(
                        f"Record #{i:03d}: Telemetry calibration entry alpha-{i*7 % 97:02d} beta-{i*13 % 89:02d} gamma-verified."
                        for i in range(1, 145)
                    )
                    c_payload_2k = {
                        "model": config.model,
                        "max_tokens": 16,
                        "temperature": 0.0,
                        "system": [
                            {
                                "type": "text",
                                "text": cache_block_2k,
                                "cache_control": {"type": "ephemeral"},
                            }
                        ],
                        "messages": [{"role": "user", "content": "Reply with the number of Record #144 only."}],
                    }
                    c3 = client.raw_post(c_payload_2k, protocol="anthropic")
                    c4 = client.raw_post(c_payload_2k, protocol="anthropic")
                    if c3.ok and c4.ok and c4.cache_read_tokens > 0:
                        expects_1k = "sonnet" in model_low and "haiku" not in model_low
                        evidences.append(
                            EvidenceItem(
                                id="proto_prompt_cache",
                                layer="L1_PROTOCOL",
                                title="官方 Prompt Cache 阈值阶梯指纹 (1024 vs 2048)",
                                status="WARN" if expects_1k else "PASS",
                                severity="MEDIUM",
                                summary=(
                                    f"触发 2048+ token 缓存门槛（1.3K 未命中，2.4K 命中 read={c4.cache_read_tokens}）！"
                                    + (
                                        "注意：Sonnet 官方门槛通常为 1024 tokens，而 Haiku 为 2048 tokens，建议警惕同系降级！"
                                        if expects_1k
                                        else "符合 2048 门槛模型特征（如 Haiku / 部分 Opus 版本）。"
                                    )
                                ),
                                details={
                                    "tier_1k_create": c1.cache_creation_tokens,
                                    "tier_1k_read2": c2.cache_read_tokens,
                                    "tier_2k_create": c3.cache_creation_tokens,
                                    "tier_2k_read2": c4.cache_read_tokens,
                                },
                                score_impact=-6 if expects_1k else 8,
                            )
                        )
                    else:
                        evidences.append(
                            EvidenceItem(
                                id="proto_prompt_cache",
                                layer="L1_PROTOCOL",
                                title="官方 Prompt Cache 阈值阶梯指纹 (1024 vs 2048)",
                                status="WARN",
                                severity="MEDIUM",
                                summary=(
                                    "连续发送 1.3K 与 2.4K token 的 `cache_control: ephemeral` 前缀均未触发缓存读命中 "
                                    f"(1K read={c2.cache_read_tokens}, 2K read={c4.cache_read_tokens if c4.ok else 0})。"
                                    "可能是中转站剥离了缓存字段、轮询切换不同账号/上游，或模型门槛为 4096 / 非官方后端。"
                                ),
                                details={
                                    "tier_1k_create": c1.cache_creation_tokens,
                                    "tier_1k_read2": c2.cache_read_tokens,
                                    "tier_2k_create": c3.cache_creation_tokens if c3.ok else 0,
                                    "tier_2k_read2": c4.cache_read_tokens if c4.ok else 0,
                                },
                                score_impact=-6,
                            )
                        )
        elif proto == "openai_chat":
            c1 = client.chat(
                messages=[{"role": "user", "content": cache_block + "\nWhat is the last record number? Answer digits only."}],
                max_tokens=16,
                temperature=0.0,
            )
            c2 = client.chat(
                messages=[{"role": "user", "content": cache_block + "\nWhat is the last record number? Answer digits only."}],
                max_tokens=16,
                temperature=0.0,
            )
            if c1.ok and c2.ok:
                cached2 = c2.cache_read_tokens
                evidences.append(
                    EvidenceItem(
                        id="proto_prompt_cache",
                        layer="L1_PROTOCOL",
                        title="Prompt Cache 自动缓存命中观测",
                        status="PASS" if cached2 > 0 else "INFO",
                        severity="INFO",
                        summary=(
                            f"二次长前缀请求观测到 `cached_tokens={cached2}` 缓存命中。"
                            if cached2 > 0
                            else "二次 >1,200 token 前缀未返回 `cached_tokens`（部分兼容端点/路由池不透传缓存统计）。"
                        ),
                        details={
                            "call1_input": c1.input_tokens,
                            "call1_cached": c1.cache_read_tokens,
                            "call2_cached": cached2,
                        },
                        score_impact=6 if cached2 > 0 else 0,
                    )
                )

    # ------------------------------------------------------------------
    # Probe 5: Strict Native Tool Use / Function Calling Structure
    # ------------------------------------------------------------------
    notify("protocol_tool_use", "检测原生结构化 Tool Use / Function Calling 协议完整性...")
    if proto == "anthropic":
        tools_spec = [
            {
                "name": "verify_vault_code",
                "description": "Verify a vault access code and priority level.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "vault_id": {"type": "integer"},
                        "priority": {"type": "string", "enum": ["LOW", "HIGH", "CRITICAL"]},
                        "tag": {"type": "string"},
                    },
                    "required": ["vault_id", "priority", "tag"],
                },
            }
        ]
    elif proto == "gemini":
        tools_spec = [
            {
                "functionDeclarations": [
                    {
                        "name": "verify_vault_code",
                        "description": "Verify a vault access code and priority level.",
                        "parameters": {
                            "type": "OBJECT",
                            "properties": {
                                "vault_id": {"type": "INTEGER"},
                                "priority": {"type": "STRING", "enum": ["LOW", "HIGH", "CRITICAL"]},
                                "tag": {"type": "STRING"},
                            },
                            "required": ["vault_id", "priority", "tag"],
                        },
                    }
                ]
            }
        ]
    else:
        tools_spec = [
            {
                "type": "function",
                "function": {
                    "name": "verify_vault_code",
                    "description": "Verify a vault access code and priority level.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "vault_id": {"type": "integer"},
                            "priority": {"type": "string", "enum": ["LOW", "HIGH", "CRITICAL"]},
                            "tag": {"type": "string"},
                        },
                        "required": ["vault_id", "priority", "tag"],
                    },
                },
            }
        ]

    tool_res = client.chat(
        messages=[
            {
                "role": "user",
                "content": "Call verify_vault_code immediately with vault_id=742, priority='CRITICAL', tag='audit-k9'. Do not reply with prose.",
            }
        ],
        max_tokens=160,
        temperature=0.0,
        tools=tools_spec,
    )
    if tool_res.ok and tool_res.tool_calls:
        tc = tool_res.tool_calls[0]
        tc_id = str(tc.get("id") or "")
        args_obj: dict[str, Any] = {}
        if proto == "anthropic":
            tc_name = str(tc.get("name") or "")
            args_obj = tc.get("input") if isinstance(tc.get("input"), dict) else {}
        elif proto == "gemini":
            tc_name = str(tc.get("name") or "")
            args_obj = tc.get("args") if isinstance(tc.get("args"), dict) else {}
        else:
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else tc
            tc_name = str(fn.get("name") or "")
            raw_args = fn.get("arguments")
            if isinstance(raw_args, dict):
                args_obj = raw_args
            elif isinstance(raw_args, str):
                try:
                    args_obj = json.loads(raw_args)
                except Exception:
                    args_obj = {}

        exact_args = (
            tc_name == "verify_vault_code"
            and args_obj.get("vault_id") == 742
            and args_obj.get("priority") == "CRITICAL"
            and args_obj.get("tag") == "audit-k9"
        )
        id_note = ""
        if proto == "anthropic" and tc_id and not tc_id.startswith("toolu_"):
            id_note = f"（注意：tool_use id `{tc_id}` 非 Anthropic 官方 `toolu_` 前缀）"
        elif proto == "openai_chat" and tc_id and not tc_id.startswith(("call_", "toolu_")):
            id_note = f"（tool_call id 前缀: `{tc_id[:14]}`）"

        evidences.append(
            EvidenceItem(
                id="cap_tool_use",
                layer="L3_CAPABILITY",
                title="原生 Tool Use / Function Calling 协议探测",
                status="PASS" if exact_args and not ("非 Anthropic" in id_note) else "WARN",
                severity="MEDIUM",
                summary=(
                    f"原生结构化工具调用成功，参数完全匹配 (id=`{tc_id or 'n/a'}`){id_note}"
                    if exact_args
                    else f"触发了工具调用但参数解析不完全精确: {args_obj}{id_note}"
                ),
                details={"tool_call": tc, "parsed_args": args_obj, "exact_match": exact_args},
                score_impact=8 if exact_args else -4,
            )
        )
    else:
        evidences.append(
            EvidenceItem(
                id="cap_tool_use",
                layer="L3_CAPABILITY",
                title="原生 Tool Use / Function Calling 协议探测",
                status="FAIL",
                severity="HIGH",
                summary=(
                    f"未返回原生结构化 tool_call（状态={tool_res.status_code}），"
                    "中转站可能剥离了 tools 参数或底层模型不支持原生 Function Calling。"
                ),
                details={"text_fallback": (tool_res.text or "")[:200], "error": tool_res.error[:200]},
                score_impact=-16,
            )
        )

    # ------------------------------------------------------------------
    # Probe 6: Dynamic In-Memory Multimodal Vision Probe (Uncacheable!)
    # ------------------------------------------------------------------
    if config.run_vision:
        notify("protocol_vision", "动态生成防缓存测试图（随机验证码+彩色几何图形），验证多模态视觉能力...")
        img = generate_vision_probe_image(random.Random())
        vision_prompt = (
            "Inspect the attached image carefully. It shows a colored geometric shape on the left "
            "and a 4-character uppercase alphanumeric code on the right. "
            'Reply ONLY with strict JSON: {"shape": "circle|square|triangle", "color": "red|blue|green", "code": "XXXX"}'
        )

        if proto == "anthropic":
            v_msg = [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": img["png_b64"],
                            },
                        },
                        {"type": "text", "text": vision_prompt},
                    ],
                }
            ]
        elif proto == "gemini":
            v_msg = [
                {
                    "role": "user",
                    "content": [
                        {"inlineData": {"mimeType": "image/png", "data": img["png_b64"]}},
                        {"text": vision_prompt},
                    ],
                }
            ]
        else:
            v_msg = [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": vision_prompt},
                        {"type": "image_url", "image_url": {"url": img["data_url"]}},
                    ],
                }
            ]

        v_res = client.chat(messages=v_msg, max_tokens=120, temperature=0.0)
        if v_res.ok:
            txt_up = (v_res.text or "").upper()
            txt_low = (v_res.text or "").lower()
            code_ok = img["code"] in txt_up
            shape_ok = img["shape_name"] in txt_low
            color_ok = img["color_name"] in txt_low
            if code_ok and shape_ok and color_ok:
                evidences.append(
                    EvidenceItem(
                        id="cap_vision_dynamic",
                        layer="L3_CAPABILITY",
                        title="动态多模态视觉验真（随机图码+色彩图形）",
                        status="PASS",
                        severity="MEDIUM",
                        summary=f"视觉能力验证通过！精准识别动态生成图形 ({img['color_name']} {img['shape_name']}) 与 4 位随机码 `{img['code']}`。",
                        details={
                            "expected": {"code": img["code"], "color": img["color_name"], "shape": img["shape_name"]},
                            "actual": v_res.text[:200],
                        },
                        score_impact=10,
                    )
                )
            elif code_ok or (shape_ok and color_ok):
                evidences.append(
                    EvidenceItem(
                        id="cap_vision_dynamic",
                        layer="L3_CAPABILITY",
                        title="动态多模态视觉验真（随机图码+色彩图形）",
                        status="WARN",
                        severity="LOW",
                        summary=f"具备视觉输入但识别部分偏差（期望 {img['color_name']} {img['shape_name']} / `{img['code']}`，实际 `{v_res.text.strip()[:90]}`）。",
                        details={
                            "expected": {"code": img["code"], "color": img["color_name"], "shape": img["shape_name"]},
                            "actual": v_res.text[:200],
                        },
                        score_impact=-2,
                    )
                )
            else:
                evidences.append(
                    EvidenceItem(
                        id="cap_vision_dynamic",
                        layer="L3_CAPABILITY",
                        title="动态多模态视觉验真（随机图码+色彩图形）",
                        status="FAIL",
                        severity="HIGH",
                        summary=(
                            f"视觉识别完全失败（胡乱猜测或无视图片）！期望 `{img['color_name']} {img['shape_name']} {img['code']}`，"
                            f"实际返回 `{v_res.text.strip()[:100]}`。极可能是中转站剥离了图片或底层被替换成了纯文本模型！"
                        ),
                        details={
                            "expected": {"code": img["code"], "color": img["color_name"], "shape": img["shape_name"]},
                            "actual": v_res.text[:240],
                        },
                        score_impact=-22,
                    )
                )
        else:
            # Non-vision text-only models (like deepseek-chat / deepseek-reasoner) legitimately reject image inputs
            expects_vision = any(
                k in model_low for k in ("claude-3", "claude-4", "claude-sonnet", "claude-opus", "claude-haiku", "gpt-4o", "gpt-4.1", "gpt-5", "gemini", "o3", "o4")
            )
            evidences.append(
                EvidenceItem(
                    id="cap_vision_dynamic",
                    layer="L3_CAPABILITY",
                    title="动态多模态视觉验真（随机图码+色彩图形）",
                    status="FAIL" if expects_vision else "INFO",
                    severity="HIGH" if expects_vision else "INFO",
                    summary=(
                        f"声称的多模态旗舰模型竟然拒绝图片输入 ({v_res.error[:140]})！高度疑似被替换为纯文本模型（如 DeepSeek 文本版）！"
                        if expects_vision
                        else f"端点不支持图像输入（若该模型本身为纯文本模型属正常）: {v_res.error[:120]}"
                    ),
                    details={"status_code": v_res.status_code, "error": v_res.error[:240]},
                    score_impact=-25 if expects_vision else 0,
                )
            )

    return evidences, list(dict.fromkeys(engine_clues))
