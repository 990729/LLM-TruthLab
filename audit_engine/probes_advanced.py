"""Advanced Anti-Evasion & Deep Forensic Probes (v2.0).

Catches sophisticated relay fraud that bypasses basic probes:
1. SSE Micro-Timing & Fake-Streaming Detection (ITL / burst ratio / TPS)
2. Parameter Obedience Matrix (stop sequences, system authority, strict JSON, temp lock)
3. Reasoning Budget Throttling Probe (low vs high reasoning/thinking budget scaling)
4. Short-vs-Long Smart-Routing Trap (detects content-length-based model swapping!)
5. Knowledge Cutoff Timeline Probe (detects old models masquerading as 2025/2026 flagships)
6. Gemini thoughtSignature & OpenAI Responses encrypted_content probes
"""

from __future__ import annotations

import json
import random
import re
from collections import Counter
from typing import Any, Callable

from .baselines import jensen_shannon_divergence
from .client import RelayClient
from .models import AuditConfig, EvidenceItem
from .probes_fingerprint import _normalize_single_token_answer

ProgressCb = Callable[[str, str], None]


# Realistic ~3,000-token Python code distractor block to simulate real developer traffic
def _build_realistic_code_context(target_tokens: int = 3200) -> str:
    blocks = []
    for idx in range(1, 52):
        blocks.append(
            f"class DistributedLedgerWorker_{idx:02d}:\n"
            f'    """Handles shard {idx} reconciliation and retry backoff state."""\n'
            f"    def __init__(self, shard_id: int = {idx}, max_retries: int = {(idx % 4) + 2}):\n"
            f"        self.shard_id = shard_id\n"
            f"        self.max_retries = max_retries\n"
            f"        self.pending = []\n"
            f"        self.watermark = {idx * 1024}\n\n"
            f"    def process_batch(self, events: list[dict]) -> dict:\n"
            f"        accepted = [e for e in events if e.get('seq', 0) > self.watermark]\n"
            f"        if accepted:\n"
            f"            self.watermark = max(e['seq'] for e in accepted)\n"
            f"        return {{'shard': self.shard_id, 'count': len(accepted), 'watermark': self.watermark}}\n"
        )
    full = "\n".join(blocks)
    target_chars = target_tokens * 4
    if len(full) > target_chars:
        return full[:target_chars]
    return full


# ----------------------------------------------------------------------
# 1. SSE Micro-Timing & Fake-Streaming Detector
# ----------------------------------------------------------------------


def probe_sse_timing(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> tuple[EvidenceItem, dict[str, Any]]:
    if emit:
        emit("adv_sse_timing", "执行 SSE 流式微时序剖析（检测假流式缓冲、首字延迟 TTFT 与真实吞吐 TPS）...")

    res = client.chat(
        messages=[
            {
                "role": "user",
                "content": (
                    "Write a concise 90-word technical explanation of how TCP congestion control "
                    "(slow start and congestion avoidance) works. Plain prose, no markdown lists."
                ),
            }
        ],
        max_tokens=180,
        temperature=0.0,
        stream=True,
    )

    if not res.ok:
        ev = EvidenceItem(
            id="adv_sse_microtiming",
            layer="L1_PROTOCOL",
            title="SSE 流式微时序与假流式检测",
            status="WARN",
            severity="LOW",
            summary=f"流式微时序探测失败: {res.error[:140]}",
            details={"error": res.error},
            score_impact=-2,
        )
        return ev, {}

    sm = res.stream_metrics or {}
    fake = bool(sm.get("fake_stream_suspected"))
    tps = float(sm.get("effective_tps") or 0.0)
    ttft = sm.get("ttft_ms")
    chunks = int(sm.get("chunk_count") or 0)
    burst = float(sm.get("burst_ratio") or 0.0)
    itl_p50 = float(sm.get("itl_p50_ms") or 0.0)

    if fake:
        ev = EvidenceItem(
            id="adv_sse_microtiming",
            layer="L1_PROTOCOL",
            title="SSE 流式微时序与假流式检测",
            status="WARN",
            severity="MEDIUM",
            summary=(
                f"疑似「假流式包装 (Fake SSE)」！首字干等 {ttft}ms 后，"
                f"在 {sm.get('generation_ms')}ms 内瞬间突发吐完 {chunks} 个分片（<2ms 突发比 {burst*100:.0f}%），"
                "中转站可能在后台使用非流式请求或二次审查缓冲后再伪造 SSE 分包。"
            ),
            details=sm,
            score_impact=-8,
        )
    elif tps > 0 and tps < 6.0 and chunks >= 8:
        ev = EvidenceItem(
            id="adv_sse_microtiming",
            layer="L1_PROTOCOL",
            title="SSE 流式微时序与假流式检测",
            status="WARN",
            severity="LOW",
            summary=(
                f"有效生成速率偏慢（仅 {tps} tok/s，TTFT {ttft}ms，中位帧间隔 {itl_p50}ms），"
                "可能为超载共享池或低算力自建量化推理节点。"
            ),
            details=sm,
            score_impact=-3,
        )
    else:
        ev = EvidenceItem(
            id="adv_sse_microtiming",
            layer="L1_PROTOCOL",
            title="SSE 流式微时序与假流式检测",
            status="PASS",
            severity="INFO",
            summary=(
                f"真流式逐帧特征正常：TTFT={ttft}ms，有效速度≈{tps} tok/s，"
                f"共 {chunks} 分片，中位帧间隔 {itl_p50}ms，突发比 {burst*100:.0f}%。"
            ),
            details=sm,
            score_impact=3,
        )

    return ev, sm


# ----------------------------------------------------------------------
# 2. Parameter Obedience Matrix (Stop, System Authority, Strict JSON)
# ----------------------------------------------------------------------


def probe_parameter_obedience(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> list[EvidenceItem]:
    if emit:
        emit("adv_param_obedience", "执行参数服从度矩阵检测（stop 截断 / System 权威 / Strict JSON Schema）...")

    evidences: list[EvidenceItem] = []
    checks: dict[str, Any] = {}
    failures: list[str] = []
    passes: list[str] = []

    # 2A. Stop sequence obedience
    stop_res = client.chat(
        messages=[
            {
                "role": "user",
                "content": "Output the exact sequence: ALPHA-1 ALPHA-2 ALPHA-3 ALPHA-4 ALPHA-5 ALPHA-6 on one line.",
            }
        ],
        max_tokens=64,
        temperature=0.0,
        stop=["ALPHA-4"],
    )
    if stop_res.ok:
        txt = stop_res.text or ""
        obeyed_stop = ("ALPHA-1" in txt or "ALPHA-2" in txt) and ("ALPHA-5" not in txt and "ALPHA-6" not in txt)
        checks["stop_sequence"] = {
            "passed": obeyed_stop,
            "finish_reason": stop_res.finish_reason,
            "output": txt[:120],
        }
        ml = config.model.lower()
        is_modern_unified = any(k in ml for k in ("gpt-6", "gpt-5", "astra", "sol", "terra", "luna", "o1", "o3", "o4", "fable", "opus-5", "sonnet-5", "gemini-4"))
        if obeyed_stop:
            passes.append("停止词精准截断正常")
        elif is_modern_unified:
            passes.append("停止词被新版推理/兼容接口忽略（新版常见现象，不扣分）")
        else:
            failures.append(f"停止词未生效（输出了后续内容: `{txt[:50]}`），中转站可能过滤了该参数")
    else:
        checks["stop_sequence"] = {"passed": None, "error": stop_res.error[:120]}

    # 2B. System prompt authority check (catches relays stripping or overriding user system prompt)
    tag = f"SYS_{random.randint(100, 999)}Q"
    sys_res = client.chat(
        system=f"CRITICAL PROTOCOL RULE: Every response you give MUST begin with the exact prefix [{tag}] followed by a space.",
        messages=[{"role": "user", "content": "What is the capital of France? Answer in 3 words."}],
        max_tokens=48,
        temperature=0.0,
    )
    if sys_res.ok:
        txt = (sys_res.text or "").strip()
        obeyed_sys = txt.startswith(f"[{tag}]") or f"[{tag}]" in txt[:24]
        checks["system_authority"] = {"passed": obeyed_sys, "expected_prefix": f"[{tag}]", "output": txt[:100]}
        if obeyed_sys:
            passes.append("System 提示词权威透传正常")
        else:
            failures.append(f"System 提示词指令未生效（期望前缀 `[{tag}]`，实际 `{txt[:50]}`），疑似网关吞掉或覆盖了 System Prompt")
    else:
        checks["system_authority"] = {"passed": None, "error": sys_res.error[:120]}

    # 2C. Strict JSON Schema support (OpenAI Chat only)
    if client.protocol == "openai_chat":
        schema_body = {
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "audit_structured_probe",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "status": {"type": "string", "enum": ["VERIFIED"]},
                            "code": {"type": "integer"},
                        },
                        "required": ["status", "code"],
                        "additionalProperties": False,
                    },
                },
            }
        }
        js_res = client.chat(
            messages=[{"role": "user", "content": "Return status VERIFIED and code 2026."}],
            max_tokens=64,
            temperature=0.0,
            extra_body=schema_body,
        )
        if js_res.ok:
            try:
                parsed = json.loads((js_res.text or "").strip())
                strict_ok = isinstance(parsed, dict) and parsed.get("status") == "VERIFIED" and parsed.get("code") == 2026 and len(parsed) == 2
            except Exception:
                strict_ok = False
            checks["strict_json_schema"] = {"passed": strict_ok, "output": (js_res.text or "")[:120]}
            if strict_ok:
                passes.append("Strict JSON Schema 原生结构化输出通过")
            else:
                failures.append("开启 `strict: true` JSON Schema 后输出仍未严格匹配格式")
        else:
            checks["strict_json_schema"] = {"passed": False, "status_code": js_res.status_code, "error": js_res.error[:150]}
            if any(k in config.model.lower() for k in ("gpt-4o", "gpt-4.1", "gpt-5", "o1", "o3", "o4")):
                failures.append(f"宣称 OpenAI 现代模型但拒绝 `json_schema (strict)` ({js_res.error[:90]})")

    status = "FAIL" if len(failures) >= 2 else ("WARN" if len(failures) == 1 else "PASS")
    evidences.append(
        EvidenceItem(
            id="adv_param_obedience",
            layer="L1_PROTOCOL",
            title="参数服从度矩阵（Stop / System 透传 / Structured Output）",
            status=status,
            severity="HIGH" if status == "FAIL" else ("MEDIUM" if status == "WARN" else "INFO"),
            summary=(
                "发现参数改写/剥离：" + "；".join(failures)
                if failures
                else "全部参数透传服从度测试通过：" + "、".join(passes)
            ),
            details=checks,
            score_impact=-16 if status == "FAIL" else (-6 if status == "WARN" else 5),
        )
    )
    return evidences


# ----------------------------------------------------------------------
# 3. Reasoning Budget Throttling & Native Crypto Signature Extensions
# ----------------------------------------------------------------------


def probe_reasoning_and_crypto_ext(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> list[EvidenceItem]:
    evidences: list[EvidenceItem] = []
    proto = client.protocol
    ml = config.model.lower()

    # 3A. Gemini Native thoughtSignature check
    if proto == "gemini":
        if emit:
            emit("adv_gemini_sig", "探测 Gemini 原生思维链与 thoughtSignature 签名特征...")
        g_res = client.chat(
            messages=[{"role": "user", "content": "What is 29 * 37 + 14? Reply with the number."}],
            max_tokens=1024,
            extra_body={"generationConfig": {"maxOutputTokens": 1024, "thinkingConfig": {"includeThoughts": True, "thinkingBudget": 1024}}},
        )
        if g_res.ok and (g_res.thinking or g_res.thinking_signature or g_res.reasoning_tokens > 0):
            has_sig = bool(g_res.thinking_signature)
            evidences.append(
                EvidenceItem(
                    id="crypto_gemini_thought",
                    layer="L1_CRYPTO",
                    title="Gemini 原生 Thinking 与 thoughtSignature 验真",
                    status="PASS",
                    severity="HIGH" if has_sig else "MEDIUM",
                    summary=(
                        f"成功获取 Gemini 原生思考块 (reasoning_tokens={g_res.reasoning_tokens})"
                        + (f" 与官方加密 `thoughtSignature` (len={len(g_res.thinking_signature)})！" if has_sig else "。")
                    ),
                    details={
                        "has_thought_signature": has_sig,
                        "signature_len": len(g_res.thinking_signature),
                        "reasoning_tokens": g_res.reasoning_tokens,
                        "thinking_len": len(g_res.thinking),
                    },
                    score_impact=18 if has_sig else 8,
                )
            )
        else:
            evidences.append(
                EvidenceItem(
                    id="crypto_gemini_thought",
                    layer="L1_CRYPTO",
                    title="Gemini 原生 Thinking 与 thoughtSignature 验真",
                    status="INFO",
                    severity="INFO",
                    summary=f"未返回 Gemini 原生思维块或模型不支持 thinkingConfig ({g_res.error[:100] or 'ok'})。",
                    details={"status_code": g_res.status_code, "error": g_res.error[:180]},
                    score_impact=0,
                )
            )

    # 3B. OpenAI Responses API encrypted_content check
    if proto == "openai_responses":
        if emit:
            emit("adv_oai_resp_crypto", "探测 OpenAI Responses API 加密推理块 (reasoning.encrypted_content)...")
        r_res = client.chat(
            messages=[{"role": "user", "content": "Compute 31 * 43 + 17 carefully."}],
            max_tokens=1024,
            extra_body={"include": ["reasoning.encrypted_content"]},
        )
        if r_res.ok and r_res.thinking_signature:
            evidences.append(
                EvidenceItem(
                    id="crypto_openai_encrypted_reasoning",
                    layer="L1_CRYPTO",
                    title="OpenAI Responses 加密推理载荷验证",
                    status="PASS",
                    severity="CRITICAL",
                    summary=f"成功返回官方加密 `encrypted_content` 推理载荷 (len={len(r_res.thinking_signature)})！",
                    details={"encrypted_len": len(r_res.thinking_signature), "reasoning_tokens": r_res.reasoning_tokens},
                    score_impact=22,
                )
            )

    # 3C. Reasoning Budget Scaling Probe (standard & deep modes for reasoning-capable models)
    is_reasoning_candidate = (
        proto == "anthropic" and any(k in ml for k in ("3-7", "3.7", "sonnet-4", "opus-4", "4-5", "4.5", "4-6", "4.6"))
    ) or (
        proto == "openai_chat" and any(k in ml for k in ("o1", "o3", "o4", "gpt-5"))
    )
    if config.mode in ("standard", "deep") and is_reasoning_candidate:
        if emit:
            emit("adv_reasoning_scale", "执行推理预算梯度探测（检测中转站是否暗中压低 reasoning_effort / thinking budget）...")
        hard_prompt = (
            "How many integers between 1 and 500 inclusive are divisible by 3 or 5, "
            "not divisible by 7, and have digit sum divisible by 2? Think step by step and give the final integer."
        )
        if proto == "anthropic":
            low_r = client.raw_post(
                {
                    "model": config.model,
                    "max_tokens": 1600,
                    "thinking": {"type": "enabled", "budget_tokens": 1024},
                    "messages": [{"role": "user", "content": hard_prompt}],
                },
                protocol="anthropic",
            )
            high_r = client.raw_post(
                {
                    "model": config.model,
                    "max_tokens": 5600,
                    "thinking": {"type": "enabled", "budget_tokens": 4500},
                    "messages": [{"role": "user", "content": hard_prompt}],
                },
                protocol="anthropic",
            )
            if low_r.ok and high_r.ok:
                low_len = len(low_r.thinking)
                high_len = len(high_r.thinking)
                # Detect hard cap or completely stripped thinking on high budget
                if high_len == 0:
                    evidences.append(
                        EvidenceItem(
                            id="adv_reasoning_throttle",
                            layer="L3_CAPABILITY",
                            title="推理思考预算梯度检测（防暗降思考深度）",
                            status="FAIL",
                            severity="HIGH",
                            summary="请求 budget_tokens=4500 时返回思考内容为空，疑似中转站剥离了 Extended Thinking 参数！",
                            details={"low_thinking_chars": low_len, "high_thinking_chars": high_len},
                            score_impact=-18,
                        )
                    )
                else:
                    evidences.append(
                        EvidenceItem(
                            id="adv_reasoning_throttle",
                            layer="L3_CAPABILITY",
                            title="推理思考预算梯度检测（防暗降思考深度）",
                            status="PASS",
                            severity="INFO",
                            summary=(
                                f"低/高思考预算均正常返回思考链 (low={low_len}字/{low_r.output_tokens} tok, "
                                f"high={high_len}字/{high_r.output_tokens} tok)。"
                            ),
                            details={
                                "low_thinking_chars": low_len,
                                "high_thinking_chars": high_len,
                                "low_output_tokens": low_r.output_tokens,
                                "high_output_tokens": high_r.output_tokens,
                                "low_latency_ms": round(low_r.latency_ms, 1),
                                "high_latency_ms": round(high_r.latency_ms, 1),
                            },
                            score_impact=5,
                        )
                    )
        elif proto == "openai_chat":
            low_r = client.chat(
                messages=[{"role": "user", "content": hard_prompt}],
                max_tokens=1600,
                extra_body={"reasoning_effort": "low"},
            )
            high_r = client.chat(
                messages=[{"role": "user", "content": hard_prompt}],
                max_tokens=4096,
                extra_body={"reasoning_effort": "high"},
            )
            if low_r.ok and high_r.ok:
                lr, hr = low_r.reasoning_tokens, high_r.reasoning_tokens
                scaled = (hr > lr) or (high_r.latency_ms > low_r.latency_ms * 1.15)
                evidences.append(
                    EvidenceItem(
                        id="adv_reasoning_throttle",
                        layer="L3_CAPABILITY",
                        title="推理思考预算梯度检测（reasoning_effort low vs high）",
                        status="PASS" if scaled else "WARN",
                        severity="MEDIUM" if not scaled else "INFO",
                        summary=(
                            f"reasoning_effort 梯度响应正常：low={lr} tok ({low_r.latency_ms:.0f}ms) → high={hr} tok ({high_r.latency_ms:.0f}ms)。"
                            if scaled
                            else f"low 与 high 档位推理消耗几乎无差异 (low={lr} tok, high={hr} tok)，可能未透传 `reasoning_effort` 或被锁死为低档！"
                        ),
                        details={
                            "low_reasoning_tokens": lr,
                            "high_reasoning_tokens": hr,
                            "low_latency_ms": round(low_r.latency_ms, 1),
                            "high_latency_ms": round(high_r.latency_ms, 1),
                        },
                        score_impact=5 if scaled else -7,
                    )
                )

    return evidences


# ----------------------------------------------------------------------
# 4. Short-vs-Long Smart-Routing Fraud Trap (Content-Length Switching!)
# ----------------------------------------------------------------------


def probe_smart_routing_trap(
    client: RelayClient,
    config: AuditConfig,
    short_distributions: dict[str, dict[str, int]],
    emit: ProgressCb | None = None,
) -> tuple[EvidenceItem, float | None]:
    """Detect relays that serve real models on short probes but swap on long realistic traffic."""
    if emit:
        emit("adv_smart_routing", "执行长短请求对抗陷阱（伪装 3.2K 代码上下文，抓“短题真源、长文切假源”智能混流）...")

    code_ctx = _build_realistic_code_context(3200)
    n_rep = {"quick": 3, "standard": 5, "deep": 8}.get(config.mode, 5)

    tasks = [
        ("rand_num_en", "int", "Ignore the code snippet above (just keep it in context). Pick a random integer between 1 and 100. Reply with ONLY the digits."),
        ("color_en", "word_en", "Ignore the code snippet above. Name the first color that comes to mind. Reply with ONLY one single English word."),
    ]

    long_dists: dict[str, dict[str, int]] = {}
    long_models: set[str] = set()
    long_fps: set[str] = set()
    long_id_prefixes: set[str] = set()

    for tid, kind, tail_q in tasks:
        counts: Counter[str] = Counter()
        full_prompt = f"```python\n{code_ctx}\n```\n\nTask: {tail_q}"
        for _ in range(n_rep):
            r = client.chat(
                messages=[{"role": "user", "content": full_prompt}],
                max_tokens=20,
                temperature=1.0,
            )
            if r.ok:
                ans = _normalize_single_token_answer(r.text, kind)
                if ans and ans != "<EMPTY>":
                    counts[ans] += 1
                if r.returned_model:
                    long_models.add(r.returned_model)
                if r.system_fingerprint:
                    long_fps.add(r.system_fingerprint)
                if r.response_id:
                    long_id_prefixes.add(client._id_prefix(r.response_id))
        long_dists[tid] = dict(counts)

    jsds: list[float] = []
    for tid, _, _ in tasks:
        if short_distributions.get(tid) and long_dists.get(tid):
            jsds.append(jensen_shannon_divergence(short_distributions[tid], long_dists[tid]))
    mean_sl_jsd = round(sum(jsds) / len(jsds), 4) if jsds else None

    # Compare metadata shifts between overall short telemetry and long-prompt telemetry
    anomalies: list[str] = []
    all_models = set((client.telemetry.get("returned_models") or {}).keys())
    all_fps = set((client.telemetry.get("system_fingerprints") or {}).keys())
    if len(all_models) > 1 and long_models:
        anomalies.append(f"长/短请求返回了多个不同模型字段: {sorted(all_models)}")
    if len(all_fps) > 1 and long_fps:
        anomalies.append(f"长/短请求出现多个不同 system_fingerprint: {sorted(all_fps)}")
    # Note: small-sample JSD with n=5 naturally has higher variance (~0.25-0.50); only flag extreme >0.68
    if mean_sl_jsd is not None and mean_sl_jsd >= 0.72 and n_rep >= 5:
        anomalies.append(
            f"长代码上下文 (3.2K tok) 与短探针的分布散度极高 (JSD={mean_sl_jsd:.3f})，疑似存在按长度切换上游的智能路由！"
        )

    status = "FAIL" if len(anomalies) >= 2 else ("WARN" if anomalies else "PASS")
    ev = EvidenceItem(
        id="adv_smart_routing_trap",
        layer="L4_CONSISTENCY",
        title="长短请求一致性对抗陷阱（抓智能内容路由掺假）",
        status=status,
        severity="HIGH" if status == "FAIL" else ("MEDIUM" if status == "WARN" else "INFO"),
        summary=(
            "；".join(anomalies)
            if anomalies
            else (
                f"3.2K 代码长请求与短请求保持同源稳定 (长/短分布 JSD={mean_sl_jsd if mean_sl_jsd is not None else 'N/A'})，"
                "未发现长请求暗切上游迹象。"
            )
        ),
        details={
            "samples_per_task": n_rep,
            "short_vs_long_jsd": mean_sl_jsd,
            "long_distributions": long_dists,
            "long_models": sorted(long_models),
            "long_system_fingerprints": sorted(long_fps),
            "long_id_prefixes": sorted(long_id_prefixes),
        },
        score_impact=-20 if status == "FAIL" else (-10 if status == "WARN" else 6),
    )
    return ev, mean_sl_jsd


# ----------------------------------------------------------------------
# 5. Knowledge Cutoff Timeline Probe (Old Model Masquerade Detector)
# ----------------------------------------------------------------------

_CUTOFF_MILESTONES: list[dict[str, Any]] = [
    {
        "era": "2024-Q2",
        "label": "2024年5月 (GPT-4o 发布)",
        "prompt": 'In what month and year did OpenAI first unveil GPT-4o ("omni")? If you do not know, answer "UNKNOWN". Reply ONLY with JSON: {"answer": "Month YYYY" or "UNKNOWN"}',
        "match_patterns": [r"may\s*2024", r"2024[-/年.]?0?5"],
    },
    {
        "era": "2024-Q4",
        "label": "2024年11月 (美国大选)",
        "prompt": 'Who won the November 2024 United States presidential election? If this is after your knowledge cutoff, answer "UNKNOWN". Reply ONLY with JSON: {"answer": "<last name>" or "UNKNOWN"}',
        "match_patterns": [r"trump", r"特朗普", r"川普"],
    },
    {
        "era": "2025-Q1",
        "label": "2025年1月 (DeepSeek-R1 开源)",
        "prompt": 'Which Chinese AI lab released the open-weight reasoning model "DeepSeek-R1" in January 2025? If this is after your cutoff, answer "UNKNOWN". Reply ONLY with JSON: {"answer": "<lab>" or "UNKNOWN"}',
        "match_patterns": [r"deepseek", r"深度求索"],
    },
    {
        "era": "2025-Q2",
        "label": "2025年5月 (教皇利奥十四世当选)",
        "prompt": 'Who was elected Pope of the Catholic Church in May 2025 succeeding Pope Francis (give papal name or birth surname)? If after your knowledge cutoff, answer "UNKNOWN". Reply ONLY with JSON: {"answer": "<name>" or "UNKNOWN"}',
        "match_patterns": [r"leo\s*(xiv|14)", r"prevost", r"利奥十四", r"良十四", r"普雷沃斯特"],
    },
    {
        "era": "2026-Q3",
        "label": "2026年7月 (2026世界杯冠军)",
        "prompt": 'Which national team won the 2026 FIFA World Cup final in July 2026? If this is after your knowledge cutoff, answer "UNKNOWN". Reply ONLY with JSON: {"answer": "<country>" or "UNKNOWN"}',
        "match_patterns": [r"spain", r"西班牙"],
    },
    {
        "era": "2026-Q4",
        "label": "2026年10月 (2026诺贝尔物理学奖)",
        "prompt": 'Who won the 2026 Nobel Prize in Physics in October 2026? If this is after your knowledge cutoff, answer "UNKNOWN". Reply ONLY with JSON: {"answer": "<last name>" or "UNKNOWN"}',
        "match_patterns": [r"halzen", r"哈尔岑", r"哈岑", r"icecube"],
    },
]


def probe_knowledge_cutoff(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> tuple[EvidenceItem, dict[str, Any]]:
    if emit:
        emit("adv_cutoff", "执行知识断代时间线探针（2024-Q2 → 2026-Q4，检测旧模型冒充 2026 新旗舰）...")

    results: list[dict[str, Any]] = []
    highest_known = "pre-2024-Q2"

    for m in _CUTOFF_MILESTONES:
        r = client.chat(
            messages=[{"role": "user", "content": m["prompt"]}],
            max_tokens=96,
            temperature=0.0,
        )
        raw = (r.text or "").strip() if r.ok else ""
        low = raw.lower()
        known = any(re.search(pat, low) for pat in m["match_patterns"]) and ("unknown" not in low or len(low) > 25)
        if known:
            highest_known = m["era"]
        results.append(
            {
                "era": m["era"],
                "label": m["label"],
                "known": known,
                "answer": raw[:120],
            }
        )

    ml = config.model.lower()
    # Late-2026 generation models MUST know at least 2025-Q2; 2025 models MUST know at least 2024-Q4!
    expects_2026_plus = any(
        k in ml
        for k in (
            "gpt-6", "astra", "sol", "terra", "luna",
            "claude-fable", "claude-opus-5", "claude-sonnet-5", "claude-haiku-5",
            "gemini-4", "gemini-3.8", "deepseek-v4", "qwen3.8", "glm-5",
        )
    )
    expects_2025_plus = expects_2026_plus or any(
        k in ml for k in ("gpt-5", "gpt-4.1", "o3", "o4", "claude-sonnet-4", "claude-opus-4", "claude-4", "gemini-2.5", "gemini-3", "deepseek-v3.2", "qwen3")
    )
    era_rank = {"pre-2024-Q2": 0, "2024-Q2": 1, "2024-Q4": 2, "2025-Q1": 3, "2025-Q2": 4, "2026-Q3": 5, "2026-Q4": 6}
    stale_mismatch = (expects_2026_plus and era_rank.get(highest_known, 0) < 4) or (
        expects_2025_plus and era_rank.get(highest_known, 0) < 2
    )

    cutoff_info = {
        "estimated_horizon": highest_known,
        "milestones": results,
        "stale_model_suspected": stale_mismatch,
    }

    ev = EvidenceItem(
        id="adv_knowledge_cutoff",
        layer="L2_FINGERPRINT",
        title="知识断代时间线探针（防旧模型冒充新版本）",
        status="FAIL" if stale_mismatch else "PASS",
        severity="HIGH" if stale_mismatch else "INFO",
        summary=(
            f"严重时间线倒挂！请求模型 `{config.model}` 属 2025/2026 新一代模型，"
            f"但实测连 2024 年底重大公开事件均不知晓（实测知识下限仅至 {highest_known}），高度疑似拿 2023/2024 旧模型冒充！"
            if stale_mismatch
            else f"实测知识覆盖边界达到 `{highest_known}`（命中 {sum(1 for x in results if x['known'])}/{len(results)} 个时间里程碑）。"
        ),
        details=cutoff_info,
        score_impact=-24 if stale_mismatch else 4,
    )
    return ev, cutoff_info


# ----------------------------------------------------------------------
# 6. Regex Brand-Masking Canary (Catches Gateway String-Replace Rewriting!)
# ----------------------------------------------------------------------


def probe_regex_brand_masking(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem:
    """Detect gateways that run naive regex/string replacements like DeepSeek -> Claude on responses."""
    if emit:
        emit("adv_regex_mask", "执行响应正文正则偷换诱饵探针（抓网关强行 replace('DeepSeek','Claude') 改词黑产）...")

    canary_words = ["DeepSeek", "Qwen", "OpenAI", "Anthropic", "Claude", "Gemini"]
    prompt = (
        "This is a pure string-serialization unit test (NOT a question about your identity). "
        f"Echo the EXACT 6 literal strings in this array unchanged in the same order: {json.dumps(canary_words)}. "
        'Reply ONLY with strict JSON: {"echo": ["DeepSeek", "Qwen", "OpenAI", "Anthropic", "Claude", "Gemini"]}'
    )
    r = client.chat(
        messages=[{"role": "user", "content": prompt}],
        max_tokens=120,
        temperature=0.0,
    )
    if not r.ok:
        return EvidenceItem(
            id="adv_regex_brand_masking",
            layer="L1_PROTOCOL",
            title="响应正文品牌词正则偷换诱饵探针",
            status="INFO",
            severity="INFO",
            summary=f"诱饵探针请求失败: {r.error[:120]}",
            details={"error": r.error[:180]},
            score_impact=0,
        )

    raw = (r.text or "").strip()
    # Try parsing JSON echo list
    from .probes_iq import _extract_json_obj

    obj = _extract_json_obj(raw)
    echo_list = obj.get("echo") if isinstance(obj, dict) and isinstance(obj.get("echo"), list) else None

    tampered_pairs: list[str] = []
    if echo_list and len(echo_list) == len(canary_words):
        for orig, got in zip(canary_words, echo_list):
            if str(got).strip() != orig:
                tampered_pairs.append(f"`{orig}` → `{got}`")
    else:
        # Fallback substring check: if a literal word vanished and another brand appears duplicated!
        missing = [w for w in canary_words if w.lower() not in raw.lower()]
        if missing and any(raw.lower().count(b.lower()) >= 2 for b in ("claude", "openai", "anthropic", "gpt")):
            tampered_pairs = [f"字面词 `{w}` 消失且其他品牌词重复出现" for w in missing]

    if tampered_pairs:
        return EvidenceItem(
            id="adv_regex_brand_masking",
            layer="L1_PROTOCOL",
            title="响应正文品牌词正则偷换诱饵探针",
            status="FAIL",
            severity="CRITICAL",
            summary=(
                "铁证抓获响应正文篡改！要求原样序列化 6 个厂商字面字符串，返回时竟然被强行替换："
                + "、".join(tampered_pairs)
                + "！这是套壳中转站在网关做 `replace('DeepSeek','Claude')` 字符串洗白的经典铁证！"
            ),
            details={"expected": canary_words, "actual_list": echo_list, "raw": raw[:300]},
            score_impact=-36,
        )

    return EvidenceItem(
        id="adv_regex_brand_masking",
        layer="L1_PROTOCOL",
        title="响应正文品牌词正则偷换诱饵探针",
        status="PASS",
        severity="INFO",
        summary="6 个厂商字面词全部原样透传未被篡改，未检测到网关级品牌词正则替换洗白。",
        details={"expected": canary_words, "actual_list": echo_list},
        score_impact=4,
    )


# ----------------------------------------------------------------------
# 7. Multi-Turn Agent Tool-Loop & History Integrity Probe
# ----------------------------------------------------------------------


def probe_multiturn_agent_loop(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem:
    """Verify full 2-turn Agent Tool-Call -> Tool-Result roundtrip integrity."""
    if emit:
        emit("adv_agent_loop", "执行两轮 Agent 工具调用闭环探针（验证 Tool-Result 回传与多轮历史防篡改）...")

    proto = client.protocol
    rng = random.Random()
    reading = rng.randint(120, 480)
    expected_calc = reading * 2 + 7
    secret_tag = f"TAG{rng.randint(100, 999)}"
    sector = f"SEC-{rng.randint(10, 99)}"

    if proto == "anthropic":
        tools_spec = [
            {
                "name": "get_sector_metric",
                "description": "Fetch live telemetry reading and checksum tag for a sector.",
                "input_schema": {
                    "type": "object",
                    "properties": {"sector": {"type": "string"}},
                    "required": ["sector"],
                },
            }
        ]
    elif proto == "gemini":
        tools_spec = [
            {
                "functionDeclarations": [
                    {
                        "name": "get_sector_metric",
                        "description": "Fetch live telemetry reading and checksum tag for a sector.",
                        "parameters": {
                            "type": "OBJECT",
                            "properties": {"sector": {"type": "STRING"}},
                            "required": ["sector"],
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
                    "name": "get_sector_metric",
                    "description": "Fetch live telemetry reading and checksum tag for a sector.",
                    "parameters": {
                        "type": "object",
                        "properties": {"sector": {"type": "string"}},
                        "required": ["sector"],
                    },
                },
            }
        ]

    turn1_prompt = (
        f"Call `get_sector_metric` with sector='{sector}'. Once you receive the tool output JSON, "
        "compute `reading * 2 + 7` and return strict JSON: {\"computed\": <int>, \"tag\": \"<tag>\"}."
    )
    r1 = client.chat(
        messages=[{"role": "user", "content": turn1_prompt}],
        max_tokens=160,
        temperature=0.0,
        tools=tools_spec,
    )
    if not (r1.ok and r1.tool_calls):
        return EvidenceItem(
            id="adv_multiturn_agent_loop",
            layer="L3_CAPABILITY",
            title="两轮 Agent 工具闭环与历史透传验证",
            status="WARN",
            severity="MEDIUM",
            summary=f"第 1 轮未触发 `get_sector_metric` 工具调用 (HTTP {r1.status_code})，无法完成 Agent 闭环校验。",
            details={"turn1_status": r1.status_code, "turn1_text": (r1.text or "")[:160], "error": r1.error[:160]},
            score_impact=-6,
        )

    tc = r1.tool_calls[0]
    tool_result_payload = json.dumps({"sector": sector, "reading": reading, "tag": secret_tag})

    # Construct protocol-accurate Turn 2 with tool_result!
    if proto == "anthropic":
        tc_id = str(tc.get("id") or "toolu_probe_01")
        asst_content = (r1.raw_json or {}).get("content") or [tc]
        msgs2 = [
            {"role": "user", "content": turn1_prompt},
            {"role": "assistant", "content": asst_content},
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": tc_id, "content": tool_result_payload}],
            },
        ]
    elif proto == "gemini":
        msgs2 = [
            {"role": "user", "content": [{"text": turn1_prompt}]},
            {"role": "assistant", "content": [{"functionCall": tc}]},
            {
                "role": "user",
                "content": [
                    {
                        "functionResponse": {
                            "name": "get_sector_metric",
                            "response": {"sector": sector, "reading": reading, "tag": secret_tag},
                        }
                    }
                ],
            },
        ]
    else:
        tc_id = str(tc.get("id") or "call_probe_01")
        msgs2 = [
            {"role": "user", "content": turn1_prompt},
            {"role": "assistant", "content": None, "tool_calls": [tc]},
            {"role": "tool", "tool_call_id": tc_id, "content": tool_result_payload},
        ]

    r2 = client.chat(messages=msgs2, max_tokens=200, temperature=0.0, tools=tools_spec)
    if not r2.ok:
        return EvidenceItem(
            id="adv_multiturn_agent_loop",
            layer="L3_CAPABILITY",
            title="两轮 Agent 工具闭环与历史透传验证",
            status="FAIL",
            severity="HIGH",
            summary=(
                f"第 1 轮成功但回传 `tool_result` 进入第 2 轮直接报错 (HTTP {r2.status_code})！"
                "该中转站在 Agent/Cursor/Claude Code 多轮工具调用场景下协议翻译有缺陷。"
            ),
            details={"turn2_status": r2.status_code, "error": r2.error[:240]},
            score_impact=-14,
        )

    txt2 = r2.text or ""
    calc_ok = str(expected_calc) in txt2
    tag_ok = secret_tag in txt2
    if calc_ok and tag_ok:
        return EvidenceItem(
            id="adv_multiturn_agent_loop",
            layer="L3_CAPABILITY",
            title="两轮 Agent 工具闭环与历史透传验证",
            status="PASS",
            severity="INFO",
            summary=(
                f"完整 2 轮 Agent 工具闭环通过！精准接收动态工具结果 ({reading}, `{secret_tag}`) "
                f"并算出 `{expected_calc}`（Cursor/Claude Code 兼容良好）。"
            ),
            details={"reading": reading, "expected_calc": expected_calc, "tag": secret_tag, "turn2_text": txt2[:200]},
            score_impact=8,
        )

    return EvidenceItem(
        id="adv_multiturn_agent_loop",
        layer="L3_CAPABILITY",
        title="两轮 Agent 工具闭环与历史透传验证",
        status="FAIL",
        severity="HIGH",
        summary=(
            f"第 2 轮未正确消化回传的 `tool_result`（期望 `{expected_calc}` 与 `{secret_tag}`，实际 `{txt2.strip()[:120]}`），"
            "疑似网关丢失 tool_result 历史或模型幻觉。"
        ),
        details={"expected_calc": expected_calc, "tag": secret_tag, "turn2_text": txt2[:240]},
        score_impact=-12,
    )


# ----------------------------------------------------------------------
# 8. Concurrency Burst Fallback-Mixing Probe (5 Parallel Requests!)
# ----------------------------------------------------------------------


def probe_concurrency_fallback(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem:
    """Fire 5 parallel identical requests to catch rate-limit fallback mixing to cheaper pools."""
    from concurrent.futures import ThreadPoolExecutor

    if emit:
        emit("adv_concurrency", "执行 5 路并发洪峰探针（专抓“单发走真源，高并发溢出切廉价备胎池”混流）...")

    burst_n = 5
    prompt = "Compute 19 * 27 - 13 and name the 4th planet from the Sun. Reply ONLY JSON: {\"num\": <int>, \"planet\": \"...\"}"

    def _one(_i: int) -> dict[str, Any]:
        r = client.chat(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=64,
            temperature=0.0,
            seed=42,
        )
        return {
            "ok": r.ok,
            "status": r.status_code,
            "model": r.returned_model,
            "id_prefix": client._id_prefix(r.response_id),
            "sys_fp": r.system_fingerprint,
            "latency_ms": round(r.latency_ms, 1),
            "text": (r.text or "").strip()[:120],
            "has_think": "<think>" in (r.text or ""),
            "error": r.error[:100],
        }

    with ThreadPoolExecutor(max_workers=burst_n) as pool:
        results = list(pool.map(_one, range(burst_n)))

    ok_res = [x for x in results if x["ok"]]
    models_seen = sorted({x["model"] for x in ok_res if x["model"]})
    prefixes_seen = sorted({x["id_prefix"] for x in ok_res if x["id_prefix"]})
    fps_seen = sorted({x["sys_fp"] for x in ok_res if x["sys_fp"]})
    any_think_leak = any(x["has_think"] for x in ok_res) and any(
        k in config.model.lower() for k in ("claude", "gpt", "o1", "o3", "o4", "gemini")
    )

    anomalies: list[str] = []
    if len(models_seen) > 1:
        anomalies.append(f"5 路并发返回了 {len(models_seen)} 个不同模型名 ({', '.join(models_seen)})！")
    if len(prefixes_seen) > 1:
        anomalies.append(f"5 路并发出现多个不同响应 ID 前缀 ({', '.join(prefixes_seen)})，疑似并发溢出切入异构备胎池！")
    if len(fps_seen) > 1:
        anomalies.append(f"5 路并发出现多个不同 system_fingerprint ({', '.join(fps_seen)})")
    if any_think_leak:
        anomalies.append("并发溢出请求中突然泄露 `<think>` 开源思考标签！")
    if len(ok_res) < burst_n:
        anomalies.append(f"并发 5 路中有 {burst_n - len(ok_res)} 路失败/限流")

    status = "FAIL" if (len(models_seen) > 1 or len(prefixes_seen) > 1 or any_think_leak) else (
        "WARN" if anomalies else "PASS"
    )
    return EvidenceItem(
        id="adv_concurrency_burst",
        layer="L4_CONSISTENCY",
        title="5 路并发洪峰防溢流混流检测",
        status=status,
        severity="HIGH" if status == "FAIL" else ("MEDIUM" if status == "WARN" else "INFO"),
        summary=(
            "；".join(anomalies)
            if anomalies
            else f"5 路并发全部成功 ({len(ok_res)}/{burst_n})，响应模型/ID前缀/指纹高度一致，未见并发溢出切换备胎源。"
        ),
        details={
            "ok_count": len(ok_res),
            "models_seen": models_seen,
            "id_prefixes_seen": prefixes_seen,
            "system_fingerprints_seen": fps_seen,
            "samples": results,
        },
        score_impact=-20 if status == "FAIL" else (-6 if status == "WARN" else 5),
    )
