"""Official Reference API Cost Estimator for Detecting Hidden Relay Price Markups.

Provides transparent approximate USD/CNY reference costs based on standard
public list prices so users can compare against what their relay actually deducted.
"""

from __future__ import annotations

from typing import Any

# (substring_pattern, input_usd_per_1m, output_usd_per_1m, label)
# Ordered from most specific (2026 latest lineup) to legacy fallbacks
_PRICE_TABLE: list[tuple[str, float, float, str]] = [
    # --- 2026 Anthropic Claude 5.x Lineup ---
    ("claude-fable", 8.0, 40.0, "Claude Fable 5.x 参考价 ($8/$40 per 1M)"),
    ("claude-opus-5", 4.0, 20.0, "Claude Opus 5.x 参考价 ($4/$20 per 1M)"),
    ("claude-sonnet-5", 2.0, 10.0, "Claude Sonnet 5.x 参考价 ($2/$10 per 1M)"),
    ("claude-haiku-5", 0.1, 0.5, "Claude Haiku 5.x 参考价 ($0.10/$0.50 per 1M)"),
    # --- 2026 OpenAI GPT-6.x Lineup ---
    ("gpt-6.2-astra", 8.0, 40.0, "GPT-6.2 Astra 参考价 ($8/$40 per 1M)"),
    ("gpt-6-astra", 8.0, 40.0, "GPT-6 Astra 参考价 ($8/$40 per 1M)"),
    ("astra", 8.0, 40.0, "GPT-6 Astra 参考价 ($8/$40 per 1M)"),
    ("gpt-6.2-sol", 2.0, 10.0, "GPT-6.2 Sol 参考价 ($2/$10 per 1M)"),
    ("gpt-6.1-sol", 2.0, 10.0, "GPT-6.1 Sol 参考价 ($2/$10 per 1M)"),
    ("gpt-6.1-terra", 1.0, 5.0, "GPT-6.1 Terra 参考价 ($1/$5 per 1M)"),
    ("gpt-6-luna", 0.1, 0.5, "GPT-6 Luna 参考价 ($0.10/$0.50 per 1M)"),
    ("gpt-6", 2.0, 10.0, "GPT-6 系列参考价 ($2/$10 per 1M)"),
    # --- 2026 Google Gemini 4 / 3.x Lineup ---
    ("gemini-4-neon", 3.0, 15.0, "Gemini 4 Neon 参考价 ($3/$15 per 1M)"),
    ("gemini-4-argon", 3.0, 15.0, "Gemini 4 Argon 参考价 ($3/$15 per 1M)"),
    ("gemini-4-hydrogen", 1.5, 7.5, "Gemini 4 Hydrogen 参考价 ($1.5/$7.5 per 1M)"),
    ("gemini-3.8-flash", 0.75, 3.75, "Gemini 3.8 Flash 参考价 ($0.75/$3.75 per 1M)"),
    ("gemini-3.5-flash-lite", 0.3, 2.5, "Gemini 3.5 Flash-Lite 参考价 ($0.3/$2.5 per 1M)"),
    ("gemini-3.1-pro", 2.0, 12.0, "Gemini 3.1 Pro 参考价 ($2/$12 per 1M)"),
    ("gemini-3", 2.0, 12.0, "Gemini 3 系列参考价 ($2/$12 per 1M)"),
    ("gemini-4", 3.0, 15.0, "Gemini 4 系列参考价 ($3/$15 per 1M)"),
    # --- 2026 DeepSeek / Qwen / GLM Open-Weight & API ---
    ("deepseek-v4.1-flash", 0.14, 0.55, "DeepSeek-V4.1 Flash 参考价 ($0.14/$0.55 per 1M)"),
    ("deepseek-v4", 0.4, 1.6, "DeepSeek-V4 参考价 ($0.4/$1.6 per 1M)"),
    ("qwen3.8", 0.35, 1.4, "Qwen3.8 参考价 ($0.35/$1.4 per 1M)"),
    ("qwen3", 0.3, 1.2, "Qwen3 参考价 ($0.3/$1.2 per 1M)"),
    ("glm-5", 0.45, 1.8, "GLM-5 系列参考价 ($0.45/$1.8 per 1M)"),
    # --- Legacy 2024-2025 Fallbacks ---
    ("claude-opus-4", 15.0, 75.0, "Claude Opus 4.x 参考价 ($15/$75 per 1M)"),
    ("claude-3-opus", 15.0, 75.0, "Claude 3 Opus 参考价 ($15/$75 per 1M)"),
    ("claude-sonnet-4", 3.0, 15.0, "Claude Sonnet 4.x 参考价 ($3/$15 per 1M)"),
    ("claude-3-7-sonnet", 3.0, 15.0, "Claude 3.7 Sonnet 参考价 ($3/$15 per 1M)"),
    ("claude-3-5-sonnet", 3.0, 15.0, "Claude 3.5 Sonnet 参考价 ($3/$15 per 1M)"),
    ("claude-haiku-4", 1.0, 5.0, "Claude Haiku 4.x 参考价 ($1/$5 per 1M)"),
    ("claude-3-5-haiku", 0.8, 4.0, "Claude 3.5 Haiku 参考价 ($0.8/$4 per 1M)"),
    ("gpt-5-mini", 0.25, 2.0, "GPT-5 Mini 参考价 ($0.25/$2 per 1M)"),
    ("gpt-5-nano", 0.05, 0.4, "GPT-5 Nano 参考价 ($0.05/$0.4 per 1M)"),
    ("gpt-5", 1.25, 10.0, "GPT-5 参考价 ($1.25/$10 per 1M)"),
    ("gpt-4.1-mini", 0.4, 1.6, "GPT-4.1 Mini 参考价 ($0.4/$1.6 per 1M)"),
    ("gpt-4.1", 2.0, 8.0, "GPT-4.1 参考价 ($2/$8 per 1M)"),
    ("gpt-4o-mini", 0.15, 0.6, "GPT-4o Mini 参考价 ($0.15/$0.6 per 1M)"),
    ("gpt-4o", 2.5, 10.0, "GPT-4o 参考价 ($2.5/$10 per 1M)"),
    ("o3-mini", 1.1, 4.4, "o3-mini 参考价 ($1.1/$4.4 per 1M)"),
    ("o4-mini", 1.1, 4.4, "o4-mini 参考价 ($1.1/$4.4 per 1M)"),
    ("o3", 2.0, 8.0, "o3 参考价 ($2/$8 per 1M)"),
    ("o1", 15.0, 60.0, "o1 参考价 ($15/$60 per 1M)"),
    ("gemini-2.5-pro", 1.25, 10.0, "Gemini 2.5 Pro 参考价 ($1.25/$10 per 1M)"),
    ("gemini-2.5-flash", 0.3, 2.5, "Gemini 2.5 Flash 参考价 ($0.3/$2.5 per 1M)"),
    ("deepseek-reasoner", 0.55, 2.19, "DeepSeek-R1 参考价 ($0.55/$2.19 per 1M)"),
    ("deepseek", 0.27, 1.1, "DeepSeek 参考价 ($0.27/$1.1 per 1M)"),
    ("qwen", 0.4, 1.2, "Qwen 参考价 ($0.4/$1.2 per 1M)"),
    ("glm", 0.5, 1.5, "GLM 参考价 ($0.5/$1.5 per 1M)"),
]

_USD_TO_CNY = 7.25


def estimate_audit_cost(model_name: str, telemetry: dict[str, Any]) -> dict[str, Any]:
    """Compute approximate official-list-price reference cost for the audit run."""
    ml = (model_name or "").lower()
    in_price, out_price, tier_note = 2.0, 8.0, "通用中大型模型估算参考价 ($2/$8 per 1M)"
    matched = False
    for pat, ip, op, note in _PRICE_TABLE:
        if pat in ml:
            in_price, out_price, tier_note = ip, op, note
            matched = True
            break

    in_tok = int(telemetry.get("input_tokens") or 0)
    out_tok = int(telemetry.get("output_tokens") or 0)
    cache_read = int(telemetry.get("cache_read_tokens") or 0)
    # Approximate discount for cached input reads (typically 10% of base input)
    billable_in = max(0, in_tok - cache_read) + cache_read * 0.1

    usd = (billable_in / 1_000_000.0) * in_price + (out_tok / 1_000_000.0) * out_price
    cny = usd * _USD_TO_CNY

    return {
        "matched_model_price": matched,
        "price_reference": tier_note,
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "cache_read_tokens": cache_read,
        "estimated_usd": round(usd, 5),
        "estimated_cny": round(cny, 4),
    }
