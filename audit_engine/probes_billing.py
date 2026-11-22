"""Billing Multiplier Fraud, Quantization Precision & Stylometric Micro-Fingerprint Probes (v4.0).

1. Billing Linearity & Multiplier Fraud Detector:
   Measures net `input_tokens` delta across +300 common English words (which EVERY
   real BPE/SentencePiece tokenizer encodes into ~300..410 tokens). Catches relays
   that secretly multiply `prompt_tokens` by 1.3x-2.0x to overcharge users!
2. Quantization / Precision Degradation Probe (Deep JSON Patch + Character Indexing):
   Catches heavily quantized INT4/Q2-Q4 models that pass simple chat but collapse
   on fine-grained character indexing and 4-level lossless JSON patching.
3. Stylometric Micro-Fingerprint:
   Extracts non-spoofable formatting/punctuation habits (em-dash rate, markdown
   structure, code comment style) to enrich baseline profiles.
"""

from __future__ import annotations

import json
import random
import re
from typing import Any, Callable

from .client import RelayClient
from .models import AuditConfig, EvidenceItem
from .probes_iq import _extract_json_obj

ProgressCb = Callable[[str, str], None]

# 50 ultra-common single-token English words (every modern tokenizer encodes these ~1.0-1.25 tok/word)
_COMMON_WORDS = [
    "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "near", "river",
    "water", "flows", "under", "stone", "bridge", "every", "morning", "light", "shines", "bright",
    "people", "walk", "along", "green", "garden", "path", "while", "birds", "sing", "above",
    "tall", "trees", "wind", "moves", "soft", "clouds", "across", "clear", "blue", "sky",
    "quiet", "village", "keeps", "warm", "fire", "inside", "small", "wooden", "house", "today",
]


def probe_billing_multiplier(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem:
    """Catch relays silently multiplying prompt_tokens (e.g., 1.5x billing inflation)."""
    if emit:
        emit("adv_billing_mult", "执行输入 Token 倍率注水审计（300 常用英文词净增量物理边界校验）...")

    base_words = " ".join(_COMMON_WORDS * 2)  # 100 common English words
    long_words = " ".join(_COMMON_WORDS * 8)  # 400 common English words (+300 net words)

    p1 = f"Reply ONLY with OK.\nText: {base_words}"
    p2 = f"Reply ONLY with OK.\nText: {long_words}"

    r1 = client.chat(messages=[{"role": "user", "content": p1}], max_tokens=8, temperature=0.0)
    r2 = client.chat(messages=[{"role": "user", "content": p2}], max_tokens=8, temperature=0.0)

    if not (r1.ok and r2.ok and r1.input_tokens > 0 and r2.input_tokens > 0):
        return EvidenceItem(
            id="adv_billing_multiplier",
            layer="L1_TOKENIZER",
            title="输入 Token 倍率注水审计（300 词线性差分）",
            status="INFO",
            severity="INFO",
            summary="端点未返回完整的 `input_tokens`，跳过输入倍率注水审计。",
            details={"in1": r1.input_tokens, "in2": r2.input_tokens},
            score_impact=0,
        )

    delta = r2.input_tokens - r1.input_tokens
    tok_per_word = round(delta / 300.0, 3)

    # Physical tokenizer bounds for 300 ultra-common space-separated English words:
    # Real tokenizers: ~300..365 tokens (1.00..1.22 tok/word).
    # Allow generous slack up to 440 (1.46 tok/word) before flagging billing inflation!
    if delta > 445:
        est_mult = round(delta / 315.0, 2)
        return EvidenceItem(
            id="adv_billing_multiplier",
            layer="L1_TOKENIZER",
            title="输入 Token 倍率注水审计（300 词线性差分）",
            status="FAIL",
            severity="HIGH",
            summary=(
                f"抓获输入计费注水！净增 300 个最常用英文单词竟多计费 {delta} tokens ({tok_per_word} tok/词，"
                f"物理词表正常应为 300~360 tokens)，疑似中转站暗中按约 {est_mult}x 倍率虚报输入 Token 偷吃余额！"
            ),
            details={
                "in_100w": r1.input_tokens,
                "in_400w": r2.input_tokens,
                "delta_300w": delta,
                "tok_per_word": tok_per_word,
                "estimated_multiplier": est_mult,
            },
            score_impact=-20,
        )
    if delta < 220:
        return EvidenceItem(
            id="adv_billing_multiplier",
            layer="L1_TOKENIZER",
            title="输入 Token 倍率注水审计（300 词线性差分）",
            status="WARN",
            severity="MEDIUM",
            summary=(
                f"净增 300 个英文单词仅增加 {delta} tokens ({tok_per_word} tok/词，低于物理词表下限)，"
                "提示网关可能在上报假 `usage` 数值或存在输入截断。"
            ),
            details={"in_100w": r1.input_tokens, "in_400w": r2.input_tokens, "delta_300w": delta, "tok_per_word": tok_per_word},
            score_impact=-8,
        )

    return EvidenceItem(
        id="adv_billing_multiplier",
        layer="L1_TOKENIZER",
        title="输入 Token 倍率注水审计（300 词线性差分）",
        status="PASS",
        severity="INFO",
        summary=f"净增 300 个常用英文词消耗 {delta} tokens ({tok_per_word} tok/词)，完全落入真实词表线性区间，未见输入倍率注水。",
        details={"in_100w": r1.input_tokens, "in_400w": r2.input_tokens, "delta_300w": delta, "tok_per_word": tok_per_word},
        score_impact=5,
    )


def probe_quantization_precision(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem:
    """Detect heavy quantization (INT4/Q2-Q4) via fine-grained string indexing + deep JSON patch."""
    if emit:
        emit("adv_quant_precision", "执行细粒度精度抗量化探针（精确字符索引 + 4 层无损 JSON 局部改写）...")

    rng = random.Random()
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    token_str = "".join(rng.choice(alphabet) for _ in range(32))
    idx1 = rng.randint(6, 14)   # 1-based
    idx2 = rng.randint(19, 28)  # 1-based
    target_ch = token_str[rng.randint(0, 31)]
    expected_c1 = token_str[idx1 - 1]
    expected_c2 = token_str[idx2 - 1]
    expected_cnt = token_str.count(target_ch)

    # Also build a 4-level nested JSON patch test
    new_port = rng.randint(7000, 9999)
    new_tag = f"v{rng.randint(2,9)}.{rng.randint(10,99)}"
    orig_doc = {
        "cluster": {
            "id": "cl-904",
            "region": "ap-east-1",
            "nodes": {
                "primary": {"host": "10.0.4.11", "port": 5432, "tls": True},
                "replica": {"host": "10.0.4.12", "port": 5433, "tls": True},
            },
            "meta": {"release": "v1.00", "checksum": 88421},
        }
    }
    expected_doc = json.loads(json.dumps(orig_doc))
    expected_doc["cluster"]["nodes"]["replica"]["port"] = new_port
    expected_doc["cluster"]["meta"]["release"] = new_tag

    prompt = (
        "Complete BOTH precision sub-tasks in a single strict JSON object:\n"
        f'Task A (1-based string indexing on "{token_str}"):\n'
        f"  - `char_{idx1}`: the character at 1-based position {idx1}\n"
        f"  - `char_{idx2}`: the character at 1-based position {idx2}\n"
        f'  - `count_target`: exact number of times "{target_ch}" appears in that string\n\n'
        "Task B (Lossless Deep JSON Patch):\n"
        f"  Given this JSON: {json.dumps(orig_doc)}\n"
        f'  Change ONLY `cluster.nodes.replica.port` to {new_port} and `cluster.meta.release` to "{new_tag}". '
        "Keep every other key, type, and value 100% identical.\n\n"
        'Reply ONLY with strict JSON: {"task_a": {"c1": "<char>", "c2": "<char>", "cnt": <int>}, "task_b": <patched_json>}'
    )

    r = client.chat(messages=[{"role": "user", "content": prompt}], max_tokens=700, temperature=0.0)
    if not r.ok or not r.text:
        return EvidenceItem(
            id="adv_quantization_precision",
            layer="L3_CAPABILITY",
            title="细粒度精度与抗重度量化探测",
            status="WARN",
            severity="LOW",
            summary=f"精度探测请求失败: {r.error[:120]}",
            details={"error": r.error[:180]},
            score_impact=-2,
        )

    obj = _extract_json_obj(r.text)
    if not isinstance(obj, dict):
        return EvidenceItem(
            id="adv_quantization_precision",
            layer="L3_CAPABILITY",
            title="细粒度精度与抗重度量化探测",
            status="WARN",
            severity="MEDIUM",
            summary="未返回合法嵌套 JSON 结构，细粒度结构化精度偏弱（疑似低配模型或重度量化）。",
            details={"raw": r.text[:240]},
            score_impact=-6,
        )

    ta = obj.get("task_a") if isinstance(obj.get("task_a"), dict) else {}
    tb = obj.get("task_b")
    c1_ok = str(ta.get("c1", "")).strip() == expected_c1
    c2_ok = str(ta.get("c2", "")).strip() == expected_c2
    try:
        cnt_ok = int(ta.get("cnt", -1)) == expected_cnt
    except Exception:
        cnt_ok = False
    patch_ok = tb == expected_doc

    hits = sum([c1_ok, c2_ok, cnt_ok, patch_ok])
    if hits == 4:
        return EvidenceItem(
            id="adv_quantization_precision",
            layer="L3_CAPABILITY",
            title="细粒度精度与抗重度量化探测",
            status="PASS",
            severity="INFO",
            summary="4/4 细粒度精度项全过（32位随机串双位置索引 + 字符计数 + 4层无损 JSON 改写全精确），无明显重度量化退化。",
            details={"hits": hits, "c1_ok": c1_ok, "c2_ok": c2_ok, "cnt_ok": cnt_ok, "patch_ok": patch_ok},
            score_impact=6,
        )
    if hits >= 2:
        return EvidenceItem(
            id="adv_quantization_precision",
            layer="L3_CAPABILITY",
            title="细粒度精度与抗重度量化探测",
            status="INFO",
            severity="INFO",
            summary=f"细粒度精度命中 {hits}/4 项 (索引1={c1_ok}, 索引2={c2_ok}, 计数={cnt_ok}, 无损JSON={patch_ok})。",
            details={"hits": hits, "c1_ok": c1_ok, "c2_ok": c2_ok, "cnt_ok": cnt_ok, "patch_ok": patch_ok},
            score_impact=0,
        )
    return EvidenceItem(
        id="adv_quantization_precision",
        layer="L3_CAPABILITY",
        title="细粒度精度与抗重度量化探测",
        status="WARN",
        severity="MEDIUM",
        summary=f"细粒度精度严重退化（仅命中 {hits}/4 项，无损 JSON={patch_ok}），常见于重度量化 (INT4/Q4) 或小参数降级模型。",
        details={
            "hits": hits,
            "c1_ok": c1_ok,
            "c2_ok": c2_ok,
            "cnt_ok": cnt_ok,
            "patch_ok": patch_ok,
            "expected_a": {"c1": expected_c1, "c2": expected_c2, "cnt": expected_cnt},
            "got_a": ta,
        },
        score_impact=-8,
    )


def extract_stylometry_profile(text: str) -> dict[str, Any]:
    """Compute lightweight non-spoofable formatting/punctuation stylometry metrics."""
    s = text or ""
    n_chars = max(1, len(s))
    em_dashes = s.count("—") + s.count("--")
    bullets = len(re.findall(r"(?m)^\s*[-*•]\s+", s))
    bolds = len(re.findall(r"\*\*[^*]+\*\*", s))
    cjk_chars = len(re.findall(r"[\u4e00-\u9fff]", s))
    return {
        "char_len": len(s),
        "em_dash_count": em_dashes,
        "bullet_lines": bullets,
        "bold_spans": bolds,
        "cjk_ratio": round(cjk_chars / n_chars, 3),
    }


def probe_native_pdf(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem | None:
    """Test native PDF document attachment support (Anthropic type='document' / Gemini inlineData)."""
    proto = client.protocol
    if proto not in ("anthropic", "gemini"):
        return None

    if emit:
        emit("adv_native_pdf", "动态生成防缓存 PDF 文档，验证原生 PDF 附件解析能力（抓伪装 Anthropic 转发层）...")

    from .pdf_gen import generate_probe_pdf

    pdf = generate_probe_pdf(random.Random())
    prompt = (
        "Read the attached PDF document. Extract the exact Verification Code and compute the Audit Arithmetic sum. "
        'Reply ONLY with strict JSON: {"code": "<code_from_pdf>", "sum": <integer>}'
    )

    if proto == "anthropic":
        msgs = [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/pdf",
                            "data": pdf["pdf_b64"],
                        },
                    },
                    {"type": "text", "text": prompt},
                ],
            }
        ]
    else:
        msgs = [
            {
                "role": "user",
                "content": [
                    {"inlineData": {"mimeType": "application/pdf", "data": pdf["pdf_b64"]}},
                    {"text": prompt},
                ],
            }
        ]

    res = client.chat(messages=msgs, max_tokens=160, temperature=0.0)
    if not res.ok:
        return EvidenceItem(
            id="cap_native_pdf",
            layer="L3_CAPABILITY",
            title="原生 PDF 文档附件解析验真（防假协议转发）",
            status="FAIL",
            severity="HIGH",
            summary=(
                f"原生 PDF 附件请求被拒绝 (HTTP {res.status_code}: {res.error[:140]})！"
                "真实 Anthropic / Gemini 原生端点均支持 base64 PDF，拒收高度提示中转站底层转接了不支持 PDF 的兼容网关或套壳模型！"
            ),
            details={"status_code": res.status_code, "error": res.error[:240], "pdf_bytes": pdf["byte_size"]},
            score_impact=-18,
        )

    txt = (res.text or "").upper()
    code_ok = str(pdf["code"]).upper() in txt
    sum_ok = str(pdf["expected_sum"]) in txt
    if code_ok and sum_ok:
        return EvidenceItem(
            id="cap_native_pdf",
            layer="L3_CAPABILITY",
            title="原生 PDF 文档附件解析验真（防假协议转发）",
            status="PASS",
            severity="MEDIUM",
            summary=f"原生 PDF 解析通过！精准提取动态 PDF 验证码 `{pdf['code']}` 并算出 {pdf['num_a']}+{pdf['num_b']}={pdf['expected_sum']}。",
            details={"expected_code": pdf["code"], "expected_sum": pdf["expected_sum"], "actual": res.text[:200]},
            score_impact=10,
        )

    return EvidenceItem(
        id="cap_native_pdf",
        layer="L3_CAPABILITY",
        title="原生 PDF 文档附件解析验真（防假协议转发）",
        status="FAIL",
        severity="HIGH",
        summary=(
            f"虽返回 HTTP 200 但未能读取动态 PDF 内容（期望 `{pdf['code']}` / {pdf['expected_sum']}，实际 `{res.text.strip()[:100]}`），"
            "高度疑似中转网关静默丢弃了 PDF 附件块！"
        ),
        details={"expected_code": pdf["code"], "expected_sum": pdf["expected_sum"], "actual": res.text[:240]},
        score_impact=-20,
    )


def probe_output_cap(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem:
    """Detect relays that secretly clamp max_tokens down (e.g., hard-capping output at 256/512)."""
    if emit:
        emit("adv_output_cap", "执行长输出防偷砍 `max_tokens` 上限探针（检测 512/1024 隐形断尾）...")

    prompt = (
        "Output numbered lines from ITEM-001 to ITEM-110 inclusive (one per line), "
        "each formatted strictly as: ITEM-XXX: alpha beta gamma delta. "
        "Do NOT skip any number and do NOT add extra commentary."
    )
    res = client.chat(
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1600,
        temperature=0.0,
    )
    if not res.ok:
        return EvidenceItem(
            id="cap_output_max_tokens",
            layer="L3_CAPABILITY",
            title="长输出上限防偷砍探测 (max_tokens=1600)",
            status="WARN",
            severity="LOW",
            summary=f"长输出探测失败: {res.error[:140]}",
            details={"error": res.error[:180]},
            score_impact=-3,
        )

    txt = res.text or ""
    lines = [ln for ln in txt.splitlines() if "ITEM-" in ln]
    hit_end = "ITEM-110" in txt
    truncated = res.finish_reason in ("length", "max_tokens", "MAX_TOKENS")
    out_tok = res.output_tokens

    if truncated and not hit_end and (0 < out_tok <= 600 or len(lines) < 55):
        return EvidenceItem(
            id="cap_output_max_tokens",
            layer="L3_CAPABILITY",
            title="长输出上限防偷砍探测 (max_tokens=1600)",
            status="FAIL",
            severity="HIGH",
            summary=(
                f"请求 `max_tokens=1600` 却在仅输出 {len(lines)} 行 / {out_tok} tokens 时被强制截断 (`finish_reason={res.finish_reason}`)！"
                "高度疑似中转网关暗中调低了用户的 `max_tokens` 上限以压缩输出成本！"
            ),
            details={"lines_generated": len(lines), "output_tokens": out_tok, "finish_reason": res.finish_reason},
            score_impact=-16,
        )

    return EvidenceItem(
        id="cap_output_max_tokens",
        layer="L3_CAPABILITY",
        title="长输出上限防偷砍探测 (max_tokens=1600)",
        status="PASS",
        severity="INFO",
        summary=f"长输出正常完成（输出 {len(lines)} 行 / {out_tok} tokens，finish_reason=`{res.finish_reason}`），未发现隐形压低 `max_tokens` 截断。",
        details={"lines_generated": len(lines), "output_tokens": out_tok, "finish_reason": res.finish_reason, "hit_end": hit_end},
        score_impact=4,
    )


def probe_client_cloaking(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem:
    """Detect User-Agent / Client-Header discriminatory routing (e.g. different upstream for Claude Code / Cursor)."""
    if emit:
        emit("adv_ua_cloaking", "执行客户端 UA 伪装差异路由探针（对比普通脚本 vs 模拟 Claude Code / OpenAI SDK 请求头）...")

    prompt = (
        "Pick a single random integer between 1 and 100, and answer 13 * 19. "
        'Reply ONLY JSON: {"rand": <int>, "prod": <int>}'
    )
    proto = client.protocol
    # Call 1: Generic script headers
    r_generic = client.raw_post(
        (
            {"model": config.model, "max_tokens": 64, "temperature": 0.0, "messages": [{"role": "user", "content": prompt}]}
            if proto in ("anthropic", "openai_chat")
            else {"contents": [{"role": "user", "parts": [{"text": prompt}]}], "generationConfig": {"maxOutputTokens": 64, "temperature": 0.0}}
        ),
        protocol=proto,
        extra_headers={"User-Agent": "python-requests/2.32.0"},
    )
    # Call 2: Simulated IDE / CLI client headers
    cloaked_hdrs = (
        {"User-Agent": "claude-cli/1.0.50 (external, cli)", "x-app": "cli"}
        if ("claude" in config.model.lower() or proto == "anthropic")
        else {"User-Agent": "OpenAI/JS 4.85.0", "X-Title": "Cursor"}
    )
    r_ide = client.raw_post(
        (
            {"model": config.model, "max_tokens": 64, "temperature": 0.0, "messages": [{"role": "user", "content": prompt}]}
            if proto in ("anthropic", "openai_chat")
            else {"contents": [{"role": "user", "parts": [{"text": prompt}]}], "generationConfig": {"maxOutputTokens": 64, "temperature": 0.0}}
        ),
        protocol=proto,
        extra_headers=cloaked_hdrs,
    )

    if not (r_generic.ok and r_ide.ok):
        # Some relays explicitly reject non-CLI User-Agent (e.g., Claude Code exclusive pools!)
        if r_ide.ok and not r_generic.ok:
            return EvidenceItem(
                id="adv_ua_cloaking",
                layer="L4_CONSISTENCY",
                title="客户端 UA 差异路由与看人下菜碟探测",
                status="WARN",
                severity="MEDIUM",
                summary=(
                    f"普通脚本 UA 被拒 (HTTP {r_generic.status_code}) 但伪装 IDE/CLI UA 成功返回 200，"
                    "说明该中转站开启了客户端 User-Agent 校验/专属白名单路由。"
                ),
                details={"generic_status": r_generic.status_code, "ide_status": r_ide.status_code, "cloaked_headers": cloaked_hdrs},
                score_impact=-4,
            )
        return EvidenceItem(
            id="adv_ua_cloaking",
            layer="L4_CONSISTENCY",
            title="客户端 UA 差异路由与看人下菜碟探测",
            status="INFO",
            severity="INFO",
            summary=f"UA 对比探测未双通 (generic={r_generic.status_code}, ide={r_ide.status_code})。",
            details={"generic_status": r_generic.status_code, "ide_status": r_ide.status_code},
            score_impact=0,
        )

    diffs: list[str] = []
    if r_generic.returned_model and r_ide.returned_model and r_generic.returned_model != r_ide.returned_model:
        diffs.append(f"返回模型随 UA 切换：`{r_generic.returned_model}` vs `{r_ide.returned_model}`")
    p1 = client._id_prefix(r_generic.response_id)
    p2 = client._id_prefix(r_ide.response_id)
    if p1 and p2 and p1 != p2:
        diffs.append(f"响应 ID 前缀随 UA 切换：`{p1}` vs `{p2}`")
    if r_generic.system_fingerprint and r_ide.system_fingerprint and r_generic.system_fingerprint != r_ide.system_fingerprint:
        diffs.append(f"system_fingerprint 随 UA 切换：`{r_generic.system_fingerprint}` vs `{r_ide.system_fingerprint}`")
    if ("<think>" in r_generic.text) != ("<think>" in r_ide.text):
        diffs.append("仅在其中一种 UA 下泄露了 `<think>` 开源思考标签！")

    if diffs:
        return EvidenceItem(
            id="adv_ua_cloaking",
            layer="L4_CONSISTENCY",
            title="客户端 UA 差异路由与看人下菜碟探测",
            status="FAIL",
            severity="HIGH",
            summary="抓获「看客户端 UA 下菜碟」差异路由！" + "；".join(diffs),
            details={
                "generic": {"model": r_generic.returned_model, "id_prefix": p1, "fp": r_generic.system_fingerprint, "latency_ms": round(r_generic.latency_ms, 1)},
                "ide_cloaked": {"headers": cloaked_hdrs, "model": r_ide.returned_model, "id_prefix": p2, "fp": r_ide.system_fingerprint, "latency_ms": round(r_ide.latency_ms, 1)},
            },
            score_impact=-22,
        )

    return EvidenceItem(
        id="adv_ua_cloaking",
        layer="L4_CONSISTENCY",
        title="客户端 UA 差异路由与看人下菜碟探测",
        status="PASS",
        severity="INFO",
        summary=f"普通脚本 UA 与伪装 IDE/CLI UA 返回同源元数据 (model=`{r_ide.returned_model or config.model}`, id=`{p2 or 'n/a'}`)，未见差异路由。",
        details={
            "generic_latency_ms": round(r_generic.latency_ms, 1),
            "ide_latency_ms": round(r_ide.latency_ms, 1),
            "id_prefix": p2,
        },
        score_impact=4,
    )


def audit_usage_physics_sanity(telemetry: dict[str, Any], stream_metrics: dict[str, Any]) -> EvidenceItem | None:
    """Sanity-check reported output/reasoning tokens against physical generation speed limits."""
    out_tok = int(telemetry.get("output_tokens") or 0)
    reas_tok = int(telemetry.get("reasoning_tokens") or 0)
    avg_lat = float(telemetry.get("avg_latency_ms") or 0.0)
    ok_reqs = int(telemetry.get("ok_requests") or 0)
    eff_tps = float((stream_metrics or {}).get("effective_tps") or 0.0)

    if ok_reqs <= 0 or out_tok <= 0 or avg_lat <= 0:
        return None

    # Average output tokens per request vs average latency: if implied speed > 1800 tok/s
    # while streaming TPS wasn't ultra-fast ASIC (or fake-stream wasn't a cached instant hit), flag!
    avg_out_per_req = out_tok / ok_reqs
    implied_tps = avg_out_per_req / max(0.05, avg_lat / 1000.0)

    if avg_out_per_req >= 300 and implied_tps > 1800.0:
        return EvidenceItem(
            id="adv_usage_physics",
            layer="L1_TOKENIZER",
            title="输出/思考 Token 物理生成速率反假账核验",
            status="WARN",
            severity="HIGH",
            summary=(
                f"违背物理生成速率常识！单次平均上报 {avg_out_per_req:.0f} output tokens（含推理 {reas_tok}），"
                f"但平均端到端耗时仅 {avg_lat:.0f}ms（推算均值高达 {implied_tps:.0f} tok/s），"
                "高度疑似中转网关在 `usage` 中虚报/伪造 `output_tokens` 或 `reasoning_tokens`！"
            ),
            details={
                "avg_output_tokens_per_req": round(avg_out_per_req, 1),
                "avg_latency_ms": avg_lat,
                "implied_tps": round(implied_tps, 1),
                "stream_effective_tps": eff_tps,
            },
            score_impact=-12,
        )
    return None


def probe_chart_vision_anti_ocr(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem:
    """Send a dynamic pixel bar chart (NO printed bar values) to defeat OCR-to-text middleware relays."""
    if emit:
        emit("adv_chart_vision", "动态生成无数值标注像素柱状图，反 OCR 中间件套壳并验证真视觉读数...")

    from .png_gen import generate_chart_vision_image

    chart = generate_chart_vision_image(random.Random())
    prompt = (
        "Inspect this vertical bar chart with four bars labeled A, B, C, D and a Y-axis from 0 to 100. "
        "Note that the numeric heights are NOT printed as text; read them visually from the Y-axis gridlines.\n"
        'Reply ONLY with strict JSON: {"tallest": "A|B|C|D", "shortest": "A|B|C|D", '
        '"tallest_color": "red|blue|green|orange", "tallest_value": <integer 0..100>}'
    )

    proto = client.protocol
    if proto == "anthropic":
        v_msg = [
            {
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": chart["png_b64"]}},
                    {"type": "text", "text": prompt},
                ],
            }
        ]
    elif proto == "gemini":
        v_msg = [
            {
                "role": "user",
                "content": [
                    {"inlineData": {"mimeType": "image/png", "data": chart["png_b64"]}},
                    {"text": prompt},
                ],
            }
        ]
    else:
        v_msg = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": chart["data_url"]}},
                ],
            }
        ]

    res = client.chat(messages=v_msg, max_tokens=160, temperature=0.0)
    if not res.ok:
        return EvidenceItem(
            id="cap_vision_anti_ocr_chart",
            layer="L3_CAPABILITY",
            title="像素图表视觉读数验真（反 OCR 文本中间件套壳）",
            status="WARN",
            severity="MEDIUM",
            summary=f"像素图表视觉请求失败 (HTTP {res.status_code}): {res.error[:140]}",
            details={"status_code": res.status_code, "error": res.error[:200]},
            score_impact=-6,
        )

    obj = _extract_json_obj(res.text) or {}
    t_ok = str(obj.get("tallest", "")).strip().upper() == chart["tallest_label"]
    s_ok = str(obj.get("shortest", "")).strip().upper() == chart["shortest_label"]
    c_ok = str(obj.get("tallest_color", "")).strip().lower() == chart["tallest_color"]
    v_ok = False
    try:
        got_v = int(float(str(obj.get("tallest_value", -999))))
        v_ok = abs(got_v - int(chart["tallest_value"])) <= 12
    except Exception:
        got_v = None

    hits = sum([t_ok, s_ok, c_ok, v_ok])
    if hits >= 3 and t_ok and s_ok:
        return EvidenceItem(
            id="cap_vision_anti_ocr_chart",
            layer="L3_CAPABILITY",
            title="像素图表视觉读数验真（反 OCR 文本中间件套壳）",
            status="PASS",
            severity="MEDIUM",
            summary=(
                f"真多模态空间视觉验证通过 ({hits}/4)！精准识别最高柱 `{chart['tallest_label']}`"
                f"({chart['tallest_color']}, ≈{chart['tallest_value']}) 与最矮柱 `{chart['shortest_label']}`，排除纯 OCR 文本转译套壳。"
            ),
            details={"expected": chart["bars"], "actual": obj, "hits": hits},
            score_impact=10,
        )

    return EvidenceItem(
        id="cap_vision_anti_ocr_chart",
        layer="L3_CAPABILITY",
        title="像素图表视觉读数验真（反 OCR 文本中间件套壳）",
        status="FAIL" if hits <= 1 else "WARN",
        severity="HIGH" if hits <= 1 else "MEDIUM",
        summary=(
            f"无字柱状图视觉读数偏差严重（仅命中 {hits}/4 项，期望最高={chart['tallest_label']}/{chart['tallest_color']}，最矮={chart['shortest_label']}）！"
            "如果验证码测试通过而柱状图失败，高度疑似中转站在网关用低成本 OCR 把图片转文字再喂给纯文本模型（或换成了极弱小视觉模型）！"
        ),
        details={"expected": chart["bars"], "actual": obj, "raw": (res.text or "")[:240], "hits": hits},
        score_impact=-16 if hits <= 1 else -6,
    )


def probe_assistant_prefill(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> EvidenceItem | None:
    """Fingerprint how the endpoint handles a trailing assistant prefill message."""
    proto = client.protocol
    if proto not in ("anthropic", "openai_chat"):
        return None

    if emit:
        emit("adv_prefill", "执行 Assistant Prefill 尾消息续写指纹探针（区分原生 Prefill 与网关丢弃/改写）...")

    msgs = [
        {"role": "user", "content": "Output valid JSON with key answer equal to 42."},
        {"role": "assistant", "content": '{"answer": '},
    ]
    r = client.chat(messages=msgs, max_tokens=24, temperature=0.0)
    if not r.ok:
        return EvidenceItem(
            id="adv_assistant_prefill",
            layer="L2_FINGERPRINT",
            title="Assistant Prefill 尾消息续写行为指纹",
            status="INFO",
            severity="INFO",
            summary=f"端点拒绝以 assistant 结尾的 Prefill 消息 (HTTP {r.status_code}: {r.error[:110]})（部分推理模型/严格网关属正常特征）。",
            details={"supported": False, "status_code": r.status_code, "error": r.error[:180]},
            score_impact=0,
        )

    txt = (r.text or "").strip()
    seamless = txt.startswith("42") and '{"answer"' not in txt
    repeated_whole = '{"answer"' in txt
    if seamless:
        return EvidenceItem(
            id="adv_assistant_prefill",
            layer="L2_FINGERPRINT",
            title="Assistant Prefill 尾消息续写行为指纹",
            status="PASS",
            severity="INFO",
            summary=f"原生无缝 Prefill 续写支持（紧接 `{msgs[1]['content']}` 输出 `{txt[:32]}`，典型 Anthropic 原生或支持前缀续写的推理栈）。",
            details={"supported": True, "seamless": True, "continuation": txt[:100]},
            score_impact=3,
        )
    if repeated_whole:
        return EvidenceItem(
            id="adv_assistant_prefill",
            layer="L2_FINGERPRINT",
            title="Assistant Prefill 尾消息续写行为指纹",
            status="INFO",
            severity="INFO",
            summary=f"返回 200 但从头重新生成了完整 JSON（`{txt[:45]}`），表明后端不支持原生 Prefill 或网关忽略了尾条 assistant 消息。",
            details={"supported": False, "seamless": False, "output": txt[:120]},
            score_impact=0,
        )
    return EvidenceItem(
        id="adv_assistant_prefill",
        layer="L2_FINGERPRINT",
        title="Assistant Prefill 尾消息续写行为指纹",
        status="INFO",
        severity="INFO",
        summary=f"Prefill 返回非标准续写片段：`{txt[:60]}`。",
        details={"supported": True, "seamless": False, "output": txt[:120]},
        score_impact=0,
    )
