"""Underlying Model Family Attribution Engine.

Synthesizes all forensic dimensions (cryptographic proofs, tokenizer boundary
vectors, error schemas, response IDs/headers, leaked tags, knowledge cutoff,
baseline JSD matches, and IQ band) into a transparent, evidence-backed suspect
ranking answering: "What model family is REALLY behind this relay?"
"""

from __future__ import annotations

from typing import Any

from .models import EvidenceItem, FingerprintSummary, IQSummary


_FAMILIES = [
    ("anthropic_claude", "Anthropic Claude (Fable / Opus / Sonnet) 系列"),
    ("openai_gpt", "OpenAI GPT-6 / GPT-5 / o 系列"),
    ("google_gemini", "Google Gemini 4 / 3 系列"),
    ("deepseek", "DeepSeek (V4 / V3 / R1) 系列"),
    ("qwen_glm_cn", "国产开源大词表 (Qwen3 / GLM-5 等)"),
    ("open_vllm_other", "自建开源推理 (vLLM / Llama / Mistral)"),
]


def infer_underlying_attribution(
    *,
    claimed_model: str,
    detected_protocol: str,
    evidences: list[EvidenceItem],
    fingerprint: FingerprintSummary,
    iq: IQSummary | None,
    telemetry: dict[str, Any],
) -> dict[str, Any]:
    """Produce a ranked suspect probability map with explicit evidence reasons."""
    scores: dict[str, float] = {k: 10.0 for k, _ in _FAMILIES}
    reasons: dict[str, list[str]] = {k: [] for k, _ in _FAMILIES}

    ev_by_id = {e.id: e for e in evidences}
    tok_vec = fingerprint.tokenizer_vector or {}
    deltas = tok_vec.get("deltas") or {}
    d_digits = int(deltas.get("digits_30") or 0)
    d_cjk = int(deltas.get("cjk_32") or 0)
    digit_cut = tok_vec.get("digit_cut_len")

    # 1. Cryptographic Proofs (Heaviest weight!)
    c_ev = ev_by_id.get("crypto_thinking_signature")
    if c_ev:
        if c_ev.status == "PASS":
            scores["anthropic_claude"] += 75
            reasons["anthropic_claude"].append("通过 Anthropic Thinking 私钥加密签名 + 1字节篡改拒收验签")
        elif c_ev.status == "FAIL" and "放行" in c_ev.summary:
            scores["anthropic_claude"] -= 40
            scores["deepseek"] += 15
            scores["qwen_glm_cn"] += 15
            scores["open_vllm_other"] += 15
            reasons["anthropic_claude"].append("篡改签名竟返回 200（排除官方 Anthropic 后端）")

    g_ev = ev_by_id.get("crypto_gemini_thought")
    if g_ev and g_ev.status == "PASS" and (g_ev.details or {}).get("has_thought_signature"):
        scores["google_gemini"] += 65
        reasons["google_gemini"].append("返回 Gemini 原生 thoughtSignature 加密字段")

    o_ev = ev_by_id.get("crypto_openai_encrypted_reasoning")
    if o_ev and o_ev.status == "PASS":
        scores["openai_gpt"] += 65
        reasons["openai_gpt"].append("返回 OpenAI Responses 原生 encrypted_content 载荷")

    # 2. Tokenizer Vector & max_tokens=1 Cut (Very strong family separator!)
    if d_digits >= 24 or digit_cut == 1:
        scores["openai_gpt"] -= 25
        scores["anthropic_claude"] -= 18
        if 0 < d_cjk <= 26:
            scores["deepseek"] += 32
            scores["qwen_glm_cn"] += 32
            scores["google_gemini"] += 10
            reasons["deepseek"].append(f"单数字词表 (digits={d_digits}, cut={digit_cut}) + 高中文压缩 (cjk={d_cjk})")
            reasons["qwen_glm_cn"].append(f"单数字词表 (digits={d_digits}, cut={digit_cut}) + 高中文压缩 (cjk={d_cjk})")
        else:
            scores["google_gemini"] += 28
            scores["deepseek"] += 16
            reasons["google_gemini"].append(f"单数字 SentencePiece 特征 (digits={d_digits}, cjk={d_cjk})")
    elif 8 <= d_digits <= 13 or digit_cut == 3:
        scores["deepseek"] -= 18
        scores["qwen_glm_cn"] -= 18
        scores["google_gemini"] -= 16
        if 0 < d_cjk <= 39:
            scores["openai_gpt"] += 34
            reasons["openai_gpt"].append(f"3位数字合并 (digits={d_digits}) + 高效中文压缩 (cjk={d_cjk}，符合 OpenAI o200k/GPT-6 词表)")
        elif d_cjk >= 40:
            scores["anthropic_claude"] += 28
            scores["openai_gpt"] += 12
            reasons["anthropic_claude"].append(f"3位数字合并 + Claude 风格较高中文开销 (cjk={d_cjk})")
        else:
            scores["openai_gpt"] += 18
            scores["anthropic_claude"] += 14

    # Fake tiktoken billing split caught -> almost certainly DeepSeek/Qwen behind OpenAI/Claude proxy
    if "tok_fake_billing_split" in ev_by_id:
        scores["openai_gpt"] -= 35
        scores["anthropic_claude"] -= 35
        scores["deepseek"] += 30
        scores["qwen_glm_cn"] += 28
        reasons["deepseek"].append("账单假算3位合并但真实单 Token 仅吐 1 位数字（典型套壳特征）")

    # 3. Error Schema & Leaked Tags / Headers / ID Prefixes
    id_prefixes = list((telemetry.get("response_id_prefixes") or {}).keys())
    hdrs = telemetry.get("server_headers") or {}
    if any(p.startswith("msg_") for p in id_prefixes):
        scores["anthropic_claude"] += 18
        reasons["anthropic_claude"].append("原生 `msg_` 响应 ID 前缀")
    if any(p.startswith(("chatcmpl-", "resp_")) for p in id_prefixes):
        scores["openai_gpt"] += 15
        reasons["openai_gpt"].append("OpenAI 风格响应 ID 前缀 (`chatcmpl-` / `resp_`)")
    if "anthropic-organization-id" in hdrs:
        scores["anthropic_claude"] += 16
        reasons["anthropic_claude"].append("存在 `anthropic-organization-id` 响应头")
    if "openai-processing-ms" in hdrs or "openai-organization" in hdrs:
        scores["openai_gpt"] += 18
        reasons["openai_gpt"].append("存在 OpenAI 官方响应头 (`openai-processing-ms`)")

    sse_ev = ev_by_id.get("proto_sse_metadata")
    if sse_ev and "<think>" in sse_ev.summary:
        scores["anthropic_claude"] -= 35
        scores["openai_gpt"] -= 35
        scores["deepseek"] += 35
        scores["qwen_glm_cn"] += 26
        reasons["deepseek"].append("正文泄露 `<think>` 开源推理标签")
        reasons["qwen_glm_cn"].append("正文泄露 `<think>` 开源推理标签")

    err_ev = ev_by_id.get("proto_error_schema")
    if err_ev:
        err_blob = str(err_ev.details or "").lower()
        if "anthropic 原生错误" in err_blob:
            scores["anthropic_claude"] += 16
            reasons["anthropic_claude"].append("Anthropic 原生错误 Schema")
        if "openai 原生错误" in err_blob:
            scores["openai_gpt"] += 16
            reasons["openai_gpt"].append("OpenAI 原生错误 Schema")
        if "google gemini 原生错误" in err_blob:
            scores["google_gemini"] += 18
            reasons["google_gemini"].append("Google Gemini 原生错误 Schema")
        if "deepseek" in err_blob:
            scores["deepseek"] += 45
            reasons["deepseek"].append("报错报文直接泄露 DeepSeek 字样")
        if "qwen" in err_blob or "dashscope" in err_blob or "zhipu" in err_blob:
            scores["qwen_glm_cn"] += 45
            reasons["qwen_glm_cn"].append("报错报文直接泄露 Qwen/DashScope/Zhipu 字样")
        if "vllm" in err_blob or "pydantic" in err_blob or "fastapi" in err_blob:
            scores["open_vllm_other"] += 38
            reasons["open_vllm_other"].append("报错泄露 FastAPI/Pydantic/vLLM 开源推理栈")

    # 4. Baseline JSD Strong Match
    if fingerprint.baseline_matches:
        best = fingerprint.baseline_matches[0]
        bm = (best.get("baseline_model") or "").lower()
        if best.get("verdict") == "MATCH_STRONG":
            if "claude" in bm:
                scores["anthropic_claude"] += 55
                reasons["anthropic_claude"].append(f"强匹配官方基线 `{best['baseline_name']}` (JSD={best['mean_jsd']})")
            elif any(k in bm for k in ("gpt", "o1", "o3", "o4")):
                scores["openai_gpt"] += 55
                reasons["openai_gpt"].append(f"强匹配官方基线 `{best['baseline_name']}` (JSD={best['mean_jsd']})")
            elif "gemini" in bm:
                scores["google_gemini"] += 55
                reasons["google_gemini"].append(f"强匹配官方基线 `{best['baseline_name']}` (JSD={best['mean_jsd']})")
            elif "deepseek" in bm:
                scores["deepseek"] += 55
                reasons["deepseek"].append(f"强匹配基线 `{best['baseline_name']}` (JSD={best['mean_jsd']})")
            elif any(k in bm for k in ("qwen", "glm")):
                scores["qwen_glm_cn"] += 55
                reasons["qwen_glm_cn"].append(f"强匹配基线 `{best['baseline_name']}` (JSD={best['mean_jsd']})")

    # 5. Vision dropped on multimodal flagship -> nudges toward text-only open models (e.g., DeepSeek text)
    vis_ev = ev_by_id.get("cap_vision_dynamic")
    if vis_ev and vis_ev.status == "FAIL":
        scores["deepseek"] += 15
        scores["open_vllm_other"] += 12
        reasons["deepseek"].append("视觉能力完全缺失/拒收图片（常见于纯文本模型套壳）")

    # Normalize positive scores to relative confidence percentages
    clamped = {k: max(1.0, v) for k, v in scores.items()}
    total = sum(clamped.values()) or 1.0

    ranked = []
    label_map = dict(_FAMILIES)
    for key, val in sorted(clamped.items(), key=lambda kv: kv[1], reverse=True):
        pct = round((val / total) * 100.0, 1)
        ranked.append(
            {
                "family_id": key,
                "family_label": label_map[key],
                "score": round(val, 1),
                "confidence_pct": pct,
                "reasons": reasons[key] or ["无强特异性证据，仅基础先验分"],
            }
        )

    top = ranked[0]
    claimed_low = claimed_model.lower()
    claimed_family = "unknown"
    if any(k in claimed_low for k in ("claude", "fable", "opus", "sonnet", "haiku")):
        claimed_family = "anthropic_claude"
    elif any(k in claimed_low for k in ("gpt", "astra", "sol", "terra", "luna", "o1", "o3", "o4")):
        claimed_family = "openai_gpt"
    elif any(k in claimed_low for k in ("gemini", "neon", "argon", "hydrogen")):
        claimed_family = "google_gemini"
    elif "deepseek" in claimed_low:
        claimed_family = "deepseek"
    elif any(k in claimed_low for k in ("qwen", "glm")):
        claimed_family = "qwen_glm_cn"

    claimed_raw_score = clamped.get(claimed_family, 0.0)
    family_conflict = (
        claimed_family != "unknown"
        and top["family_id"] != claimed_family
        and top["confidence_pct"] >= 36.0
        and (top["score"] - claimed_raw_score) >= 8.0
    )

    # Pinpoint the single highest-confidence latest (2026) specific model!
    iq_sc = iq.total_score if iq is not None else None
    tps_ev = ev_by_id.get("v11_too_fast_flagship")
    is_too_fast = tps_ev is not None and tps_ev.status in ("WARN", "FAIL")
    best_bl = fingerprint.baseline_matches[0] if fingerprint.baseline_matches else None

    if best_bl and best_bl.get("verdict") == "MATCH_STRONG" and best_bl.get("baseline_model"):
        ml_name = str(best_bl["baseline_model"])
        ml_conf = min(98.0, round(max(86.0, 98.0 - float(best_bl.get("mean_jsd") or 0.0) * 60.0), 1))
        ml_basis = f"单 Token 行为分布强匹配本地官方基线 `{best_bl.get('baseline_name')}` (JSD={best_bl.get('mean_jsd')})"
    else:
        fid = top["family_id"]
        same_fam = (fid == claimed_family) and not family_conflict
        if fid == "openai_gpt":
            if is_too_fast or (iq_sc is not None and iq_sc < 68.0):
                ml_name = "gpt-6-luna"
                ml_basis = "词表/协议属 OpenAI 系，但智商或超高吞吐更接近轻量版 gpt-6-luna"
            elif same_fam and any(k in claimed_low for k in ("astra", "sol", "terra", "luna", "gpt-6", "gpt-5", "o3")):
                ml_name = claimed_model
                ml_basis = f"词表与协议特征指向 OpenAI 最新系，且实测能力与 `{claimed_model}` 相符"
            elif iq_sc is not None and iq_sc >= 88.0:
                ml_name = "gpt-6.2-astra / gpt-6.2-sol"
                ml_basis = f"OpenAI 词表特征 + S 级顶尖工程智商 ({iq_sc}/100)"
            elif iq_sc is not None and iq_sc >= 72.0:
                ml_name = "gpt-6.2-sol / gpt-6.1-terra"
                ml_basis = f"OpenAI 词表特征 + 中高阶工程智商 ({iq_sc}/100)"
            else:
                ml_name = "gpt-6.2-sol"
                ml_basis = "综合词表与协议特征最倾向 OpenAI GPT-6 主力系列"
        elif fid == "anthropic_claude":
            if is_too_fast or (iq_sc is not None and iq_sc < 68.0):
                ml_name = "claude-haiku-5-5"
                ml_basis = "特征属 Claude 系，但能力或超高吞吐更接近轻量版 claude-haiku-5-5"
            elif same_fam and any(k in claimed_low for k in ("fable", "opus", "sonnet", "haiku")):
                ml_name = claimed_model
                ml_basis = f"验签/协议与能力档位均指向 `{claimed_model}`"
            elif iq_sc is not None and iq_sc >= 90.0:
                ml_name = "claude-fable-5-2 / claude-opus-5-5"
                ml_basis = f"Claude 特征 + S 级顶尖智商 ({iq_sc}/100)"
            elif iq_sc is not None and iq_sc >= 74.0:
                ml_name = "claude-sonnet-5-5"
                ml_basis = f"Claude 特征 + A 级主力智商 ({iq_sc}/100)"
            else:
                ml_name = "claude-sonnet-5-5"
                ml_basis = "综合协议与词表特征最倾向 Anthropic Claude 5.x 主力系列"
        elif fid == "google_gemini":
            if iq_sc is not None and iq_sc >= 85.0:
                ml_name = "gemini-4-neon / gemini-4-argon"
                ml_basis = f"Gemini 特征 + 顶尖智商 ({iq_sc}/100)"
            elif iq_sc is not None and iq_sc < 68.0:
                ml_name = "gemini-3.5-flash-lite"
                ml_basis = f"Gemini 特征 + 轻量档智商 ({iq_sc}/100)"
            else:
                ml_name = "gemini-4-hydrogen / gemini-3.8-flash"
                ml_basis = "综合词表与协议特征最倾向 Google Gemini 最新系列"
        elif fid == "deepseek":
            if iq_sc is not None and iq_sc < 70.0:
                ml_name = "deepseek-v4.1-flash"
                ml_basis = "单数字高密中文词表/标签特征 + 轻量档表现"
            else:
                ml_name = "deepseek-v4"
                ml_basis = "单数字高密中文词表或思考标签/报错特征强烈指向 DeepSeek 最新系列"
        elif fid == "qwen_glm_cn":
            if iq_sc is not None and iq_sc < 70.0:
                ml_name = "qwen3.8-flash"
                ml_basis = "单数字高密中文词表 + 轻量档表现"
            else:
                ml_name = "qwen3.8 / glm-5.3"
                ml_basis = "单数字高密中文词表与协议特征指向国产最新大词表系列"
        else:
            ml_name = "自建开源模型 (vLLM / 量化权重)"
            ml_basis = "报错或推理栈特征指向自建 vLLM / 开源模型部署"

        ml_conf = top["confidence_pct"]

    most_likely_model = {
        "model_name": ml_name,
        "family_id": top["family_id"],
        "family_label": top["family_label"],
        "confidence_pct": ml_conf,
        "basis": ml_basis,
    }

    return {
        "claimed_model": claimed_model,
        "claimed_family": claimed_family,
        "top_suspect": top,
        "most_likely_model": most_likely_model,
        "family_conflict": family_conflict,
        "candidates": ranked,
        "note": (
            "以上归因与「最可能真实模型」综合了密码学签名、词表差分、错误 Schema、响应元数据、10维智商与基线 JSD 证据；"
            "如需 100% 锁定同家族具体型号（如 Opus 5.5 vs Sonnet 5.5 / Astra vs Sol），建议结合官方基线或 A/B 对决。"
        ),
    }
