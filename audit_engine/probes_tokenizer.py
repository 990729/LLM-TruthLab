"""L1/L2 Tokenizer Boundary Probing & Billing Integrity Forensics.

Combines:
1. Input-token differential vector across calibrated digit/CJK/whitespace probes
2. `max_tokens=1` output boundary cut probing (cannot be spoofed by gateway billing)
3. Billing cross-check (catches relays that fake usage via tiktoken or inflate tokens)
"""

from __future__ import annotations

from typing import Any, Callable

from .client import RelayClient
from .models import AuditConfig, EvidenceItem

ProgressCb = Callable[[str, str], None]

_BASE_PROMPT = "Reply with only the letter X.\nData:"

_DIFF_PROBES: dict[str, tuple[str, str]] = {
    "digits_30": ("30位连续数字", "012345678901234567890123456789"),
    "cjk_32": ("32字中文文本", "中华人民共和国人工智能大模型底层架构分词器边界测试字符串示例样本"),
    "spaces_32": ("32个连续空格", "|" + (" " * 32) + "|"),
    "ascii_code": ("代码混合串", "__init__ asyncio.create_task(getElementById('xmlHttpRequest'))"),
}


def _infer_tokenizer_family(
    deltas: dict[str, int],
    digit_cut_len: int | None,
    cjk_cut_str: str,
) -> tuple[str, list[str]]:
    """Infer underlying tokenizer family from differential token vector + 1-token cuts."""
    clues: list[str] = []
    d_digits = deltas.get("digits_30", 0)
    d_cjk = deltas.get("cjk_32", 0)
    d_spaces = deltas.get("spaces_32", 0)

    # Strong separator #1: 30 digits tokenization
    single_digit_vocab = (d_digits >= 24) or (digit_cut_len == 1)
    three_digit_vocab = (7 <= d_digits <= 14) or (digit_cut_len == 3)

    if d_digits > 0:
        if d_digits >= 25:
            clues.append(f"30位数字耗 {d_digits} tokens（单数字独立切分：典型 DeepSeek / Qwen / Gemini / Gemma 词表）")
        elif 8 <= d_digits <= 13:
            clues.append(f"30位数字耗 {d_digits} tokens（3位数字合并切分：典型 OpenAI o200k/cl100k / Llama-3 / Claude BPE）")
        else:
            clues.append(f"30位数字耗 {d_digits} tokens（混合数字切分）")

    if d_cjk > 0:
        ratio = d_cjk / 32.0
        if ratio <= 0.82:
            clues.append(f"32字中文仅耗 {d_cjk} tokens ({ratio:.2f} tok/字：中文高压缩词表，典型 DeepSeek / Qwen / GLM)")
        elif ratio <= 1.25:
            clues.append(f"32字中文耗 {d_cjk} tokens ({ratio:.2f} tok/字：现代多语种大词表，典型 OpenAI o200k / Gemini 256k)")
        else:
            clues.append(f"32字中文耗 {d_cjk} tokens ({ratio:.2f} tok/字：偏英语词表，典型 Claude BPE / OpenAI cl100k)")

    if digit_cut_len is not None:
        clues.append(f"`max_tokens=1` 首 Token 截断数字长度为 {digit_cut_len} 位")
    if cjk_cut_str:
        clues.append(f"`max_tokens=1` 中文首 Token 切分结果: `{cjk_cut_str}`")

    # Synthesize family guess
    if single_digit_vocab:
        if d_cjk > 0 and d_cjk <= 26:
            family = "Single-Digit + CJK-Dense (DeepSeek / Qwen / GLM 系列特征)"
        elif d_cjk >= 27:
            family = "Single-Digit + Multilingual (Gemini SentencePiece / Gemma / Mistral 特征)"
        else:
            family = "Single-Digit Vocab (DeepSeek / Qwen / Gemini 家族)"
    elif three_digit_vocab:
        if d_cjk >= 42:
            if d_spaces <= 5:
                family = "OpenAI cl100k_base / Claude-BPE (高中文开销 + 3位数字合并)"
            else:
                family = "Claude-BPE 风格词表 (3位数字合并 + 较高中文开销)"
        elif 24 <= d_cjk <= 41:
            family = "OpenAI o200k_base 风格词表 (GPT-4o / GPT-5 / o系列特征)"
        elif 0 < d_cjk < 24:
            family = "3位数字合并 + 高中文压缩（定制/混合 BPE）"
        else:
            family = "3-Digit BPE Vocab (OpenAI / Claude / Llama-3 家族)"
    else:
        family = "未明确归类（可能受网关自定义计费或非标准词表影响）"

    return family, clues


def _check_tokenizer_mismatch(model_low: str, deltas: dict[str, int], digit_cut_len: int | None) -> str | None:
    """Detect blatant contradictions between claimed model family and observed tokenizer."""
    d_digits = deltas.get("digits_30", 0)
    d_cjk = deltas.get("cjk_32", 0)

    # Claimed OpenAI GPT-4o / GPT-4.1 / GPT-5 / o-series MUST use o200k_base (3-digit tokens, ~10 tok for 30 digits)
    if any(k in model_low for k in ("gpt-4o", "gpt-4.1", "gpt-5", "o1", "o3", "o4")):
        if d_digits >= 25 or digit_cut_len == 1:
            return (
                f"宣称 OpenAI 现代模型（应使用 o200k_base，30位数字约 10 tokens、首截断为 3 位数字），"
                f"但实测 30位数字耗 {d_digits} tokens / 首截断长度={digit_cut_len}，与 DeepSeek/Qwen/Gemini 单数字词表高度吻合！"
            )
        if d_cjk > 0 and d_cjk <= 20:
            return (
                f"宣称 OpenAI 模型，但 32 字中文仅耗 {d_cjk} tokens（远低于 o200k_base 正常压缩率），疑似国产中文大词表模型替换。"
            )

    # Claimed Claude 3.5 / 3.7 / 4 / Sonnet / Opus / Haiku
    if "claude" in model_low:
        if d_digits >= 25 and (0 < d_cjk <= 24):
            return (
                f"宣称 Claude 模型，但实测呈“单数字切分 ({d_digits} tok) + 超高中文压缩 ({d_cjk} tok)”特征，"
                "与 Claude 原生词表严重矛盾，高度疑似 DeepSeek / Qwen / GLM 套壳！"
            )
        if digit_cut_len == 1 and (0 < d_cjk <= 23):
            return (
                "宣称 Claude 模型，但 `max_tokens=1` 首数字截断为 1 位且中文压缩率极高，明显偏向 DeepSeek / Qwen 词表！"
            )

    # Claimed Gemini (SentencePiece 256k -> single digit tokenization)
    if "gemini" in model_low:
        if 8 <= d_digits <= 13 and digit_cut_len == 3:
            return (
                f"宣称 Gemini 模型（原生 SentencePiece 通常按单数字切分），"
                f"但实测呈现 3 位数字合并切分 ({d_digits} tok / cut=3)，疑似非 Gemini 底座或网关改写。"
            )

    return None


def run_tokenizer_probes(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
) -> tuple[list[EvidenceItem], dict[str, Any], str]:
    """Run tokenizer differential, max_tokens=1 boundary cut, and billing checks."""
    evidences: list[EvidenceItem] = []
    model_low = config.model.lower()

    def notify(step: str, msg: str) -> None:
        if emit:
            emit(step, msg)

    # 1. Input-token differential vector
    notify("tok_diff", "测量 Tokenizer 词表差分向量（数字合并 / 中文压缩率 / 空格合并）...")
    base_res = client.chat(
        messages=[{"role": "user", "content": _BASE_PROMPT}],
        max_tokens=8,
        temperature=0.0,
    )
    deltas: dict[str, int] = {}
    raw_counts: dict[str, int] = {}

    if base_res.ok and base_res.input_tokens > 0:
        base_in = base_res.input_tokens
        raw_counts["base"] = base_in
        for key, (_label, text) in _DIFF_PROBES.items():
            r = client.chat(
                messages=[{"role": "user", "content": _BASE_PROMPT + text}],
                max_tokens=8,
                temperature=0.0,
            )
            if r.ok and r.input_tokens > 0:
                raw_counts[key] = r.input_tokens
                deltas[key] = max(0, r.input_tokens - base_in)

    # 2. Uncounterfeitable `max_tokens=1` output boundary cut probe
    notify("tok_cut", "执行 `max_tokens=1` 真实词表切分探针（防止中转站用 tiktoken 伪造账单）...")
    digit_cut_text = ""
    digit_cut_len: int | None = None
    cjk_cut_text = ""

    # Note: reasoning models with high hidden thoughts may return empty text at max_tokens=1; handle cleanly
    cut_digit_res = client.chat(
        messages=[
            {
                "role": "user",
                "content": "Output ONLY the exact string 1234567890 with no prefix, no spaces, and no punctuation.",
            }
        ],
        max_tokens=1,
        temperature=0.0,
    )
    if cut_digit_res.ok and cut_digit_res.text:
        digit_cut_text = cut_digit_res.text.strip()
        if digit_cut_text and digit_cut_text.isdigit() and "1234567890".startswith(digit_cut_text):
            digit_cut_len = len(digit_cut_text)

    cut_cjk_res = client.chat(
        messages=[
            {
                "role": "user",
                "content": "只原样输出下面这几个汉字，不要加任何标点或空格：中华人民共和国",
            }
        ],
        max_tokens=1,
        temperature=0.0,
    )
    if cut_cjk_res.ok and cut_cjk_res.text:
        cjk_cut_text = cut_cjk_res.text.strip()

    family_guess, clues = _infer_tokenizer_family(deltas, digit_cut_len, cjk_cut_text)
    mismatch = _check_tokenizer_mismatch(model_low, deltas, digit_cut_len)

    # Cross-check: Did the relay fake `input_tokens` with tiktoken while real output tokenizer differs?
    fake_billing_detected = False
    if (
        deltas.get("digits_30", 0) in range(8, 14)
        and digit_cut_len == 1
    ):
        fake_billing_detected = True

    tok_vector = {
        "base_input_tokens": raw_counts.get("base", 0),
        "deltas": deltas,
        "digit_cut_1tok": digit_cut_text,
        "digit_cut_len": digit_cut_len,
        "cjk_cut_1tok": cjk_cut_text,
        "clues": clues,
        "family_guess": family_guess,
    }

    if fake_billing_detected:
        evidences.append(
            EvidenceItem(
                id="tok_fake_billing_split",
                layer="L1_TOKENIZER",
                title="账单 Tokenizer 与真实输出词表矛盾检测",
                status="FAIL",
                severity="CRITICAL",
                summary=(
                    f"抓到硬核破绽！网关上报的 30 位数字计费为 {deltas.get('digits_30')} tokens（像 OpenAI tiktoken 3位合并），"
                    f"但 `max_tokens=1` 实际输出首数字却只吐出 1 位 (`{digit_cut_text}`)！"
                    "说明中转站疑似在网关用 tiktoken 假算账单，而真实底层是单数字词表模型（如 DeepSeek/Qwen/Gemini）！"
                ),
                details=tok_vector,
                score_impact=-35,
            )
        )

    if deltas or digit_cut_len is not None:
        evidences.append(
            EvidenceItem(
                id="tok_family_fingerprint",
                layer="L1_TOKENIZER",
                title="Tokenizer 词表边界指纹识别",
                status="FAIL" if mismatch else "PASS",
                severity="HIGH" if mismatch else "INFO",
                summary=mismatch if mismatch else f"推断词表家族：{family_guess}。" + (" ".join(clues[:2]) if clues else ""),
                details=tok_vector,
                score_impact=-28 if mismatch else 8,
            )
        )
    else:
        evidences.append(
            EvidenceItem(
                id="tok_family_fingerprint",
                layer="L1_TOKENIZER",
                title="Tokenizer 词表边界指纹识别",
                status="WARN",
                severity="LOW",
                summary="端点未返回有效 `usage.input_tokens` 且 `max_tokens=1` 无文本输出（可能是强制思考模型消耗了全部 1 token 预算）。",
                details=tok_vector,
                score_impact=-2,
            )
        )

    # 3. Output Token Billing Inflation Audit
    notify("tok_billing", "核验输出 Token 计费真实性（检测虚报/翻倍计费）...")
    bill_res = client.chat(
        messages=[
            {
                "role": "user",
                "content": "Repeat this exact sentence 3 times separated by newlines and nothing else: The quick brown fox jumps over the lazy dog near the river bank.",
            }
        ],
        max_tokens=120,
        temperature=0.0,
    )
    if bill_res.ok and bill_res.output_tokens > 0 and bill_res.text:
        words = len(bill_res.text.split())
        non_reasoning_out = max(0, bill_res.output_tokens - bill_res.reasoning_tokens)
        ratio = non_reasoning_out / max(1, words)
        # Normal English prose is ~1.15 - 1.55 tokens/word. Allow generous slack (2.6x) for short replies or invisible thinking
        if words >= 15 and bill_res.reasoning_tokens == 0 and not bill_res.thinking and ratio > 2.8:
            evidences.append(
                EvidenceItem(
                    id="tok_billing_inflation",
                    layer="L1_TOKENIZER",
                    title="输出 Token 计费膨胀审计",
                    status="WARN",
                    severity="MEDIUM",
                    summary=(
                        f"输出文本仅 {words} 个英文词，但上报 `output_tokens={bill_res.output_tokens}`"
                        f"（倍率 {ratio:.2f} tok/词，正常约 1.2~1.6），疑似存在计费膨胀或隐藏思考 Token 未单独列项。"
                    ),
                    details={
                        "words": words,
                        "reported_output_tokens": bill_res.output_tokens,
                        "reasoning_tokens": bill_res.reasoning_tokens,
                        "tokens_per_word": round(ratio, 2),
                    },
                    score_impact=-10,
                )
            )
        else:
            evidences.append(
                EvidenceItem(
                    id="tok_billing_inflation",
                    layer="L1_TOKENIZER",
                    title="输出 Token 计费膨胀审计",
                    status="PASS",
                    severity="INFO",
                    summary=(
                        f"输出 {words} 词消耗 {bill_res.output_tokens} tokens"
                        + (f"（含推理 {bill_res.reasoning_tokens}）" if bill_res.reasoning_tokens else "")
                        + f"，单价换算倍率 {ratio:.2f} tok/词，未见异常虚报。"
                    ),
                    details={
                        "words": words,
                        "reported_output_tokens": bill_res.output_tokens,
                        "reasoning_tokens": bill_res.reasoning_tokens,
                        "tokens_per_word": round(ratio, 2),
                    },
                    score_impact=4,
                )
            )

    return evidences, tok_vector, family_guess
