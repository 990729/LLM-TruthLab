"""Context Window Cliff Ladder & Memory Heatmap Probe.

Tests stepped context lengths (e.g. 4K, 16K, 32K, 64K tokens) with 3 independent
random passcodes placed at Head (5%), Middle (50%), and Tail (95%) depths to
expose silent sliding-window clipping, hard truncation, and Lost-in-the-Middle.
"""

from __future__ import annotations

import json
import random
from typing import Any, Callable

from .client import RelayClient
from .models import AuditConfig, EvidenceItem
from .probes_iq import _extract_json_obj

ProgressCb = Callable[[str, str], None]

_FILLER_TEMPLATES = [
    "Sector telemetry checksum validated across distributed storage shard with zero parity faults recorded.",
    "Periodic cooling loop diagnostic confirmed nominal pressure gradients across primary heat exchangers.",
    "Optical backbone ring redundancy verified sub-millisecond failover response during scheduled audit.",
    "Automated snapshot archival rotated encrypted ledger segments to cold regional replica clusters.",
    "Telemetry scheduler synchronized epoch counters across auxiliary gateway relays without drift.",
]


def _build_cliff_document(target_k_tokens: int, rng: random.Random) -> tuple[str, dict[str, str], int]:
    """Build an archive of ~target_k_tokens*1000 tokens with 3 depth-pinned secrets."""
    # Each line is ~22 tokens (~92 chars)
    n_lines = max(40, int((target_k_tokens * 1000) / 22))
    head_code = f"HEAD-{rng.randint(1000, 9999)}-{rng.choice('ABCDEFGH')}"
    mid_code = f"MID-{rng.randint(1000, 9999)}-{rng.choice('JKLMNPQR')}"
    tail_code = f"TAIL-{rng.randint(1000, 9999)}-{rng.choice('STUVWXYZ')}"

    p_head = max(2, int(n_lines * 0.05))
    p_mid = max(p_head + 5, int(n_lines * 0.50))
    p_tail = min(n_lines - 3, max(p_mid + 5, int(n_lines * 0.95)))

    lines: list[str] = []
    for i in range(n_lines):
        if i == p_head:
            lines.append(f"[ENTRY-{i:05d}] CRITICAL BEACON ALPHA (HEAD): The verified Head Passcode is {head_code}.")
        elif i == p_mid:
            lines.append(f"[ENTRY-{i:05d}] CRITICAL BEACON BETA (MIDDLE): The verified Middle Passcode is {mid_code}.")
        elif i == p_tail:
            lines.append(f"[ENTRY-{i:05d}] CRITICAL BEACON GAMMA (TAIL): The verified Tail Passcode is {tail_code}.")
        else:
            lines.append(
                f"[ENTRY-{i:05d}] {_FILLER_TEMPLATES[i % len(_FILLER_TEMPLATES)]} Seq={(i * 29 + 11) % 991:03d}."
            )
    doc = "\n".join(lines)
    est_tokens = len(doc) // 4
    return doc, {"head": head_code, "mid": mid_code, "tail": tail_code}, est_tokens


def run_context_cliff_ladder(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[EvidenceItem, dict[str, Any]]:
    """Run stepped context window recall tests and produce a memory heatmap."""
    max_k = max(4, min(128, int(config.context_cliff_max_k or 16)))
    all_tiers = [4, 16, 32, 64, 128]
    tiers = [t for t in all_tiers if t <= max_k]
    if not tiers:
        tiers = [4]

    rng = random.Random()
    rows: list[dict[str, Any]] = []
    truncation_flags: list[str] = []

    for tier_k in tiers:
        if cancel_check and cancel_check():
            break
        if emit:
            emit("context_cliff", f"上下文断崖测绘：正在压测 {tier_k}K Token 窗口（首/中/尾三点召回）...")
        doc, codes, est_tok = _build_cliff_document(tier_k, rng)
        prompt = (
            "Read the operational log below and extract the THREE verified passcodes: "
            "Head Passcode (Beacon Alpha), Middle Passcode (Beacon Beta), and Tail Passcode (Beacon Gamma).\n\n"
            f"{doc}\n\n"
            'Reply ONLY with strict JSON: {"head": "...", "mid": "...", "tail": "..."}'
        )
        res = client.chat(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=160,
            temperature=0.0,
        )
        if not res.ok:
            rows.append(
                {
                    "tier_k": tier_k,
                    "est_tokens": est_tok,
                    "reported_input_tokens": res.input_tokens,
                    "status_code": res.status_code,
                    "latency_ms": round(res.latency_ms, 1),
                    "head_ok": False,
                    "mid_ok": False,
                    "tail_ok": False,
                    "error": res.error[:180],
                }
            )
            truncation_flags.append(f"{tier_k}K 档位直接报错 (HTTP {res.status_code})")
            break

        obj = _extract_json_obj(res.text) or {}
        txt_up = (res.text or "").upper()
        head_ok = codes["head"] in str(obj.get("head", "")).upper() or codes["head"] in txt_up
        mid_ok = codes["mid"] in str(obj.get("mid", "")).upper() or codes["mid"] in txt_up
        tail_ok = codes["tail"] in str(obj.get("tail", "")).upper() or codes["tail"] in txt_up

        # Check silent input token clipping (sent ~est_tok but reported < 55% of est_tok!)
        silent_clip = res.input_tokens > 0 and res.input_tokens < int(est_tok * 0.55)
        if silent_clip:
            truncation_flags.append(
                f"{tier_k}K 档位发送约 {est_tok:,} tok，但服务端仅计入 {res.input_tokens:,} input_tokens（高度疑似网关偷偷截断上下文！）"
            )
        elif not head_ok and tail_ok:
            truncation_flags.append(f"{tier_k}K 档位出现「头部遗忘 / 滑动窗口丢头」(Head=FAIL, Tail=PASS)")
        elif head_ok and tail_ok and not mid_ok:
            truncation_flags.append(f"{tier_k}K 档位出现「中段失忆 / Lost in the Middle」")
        elif not (head_ok or mid_ok or tail_ok):
            truncation_flags.append(f"{tier_k}K 档位三点全失忆")

        rows.append(
            {
                "tier_k": tier_k,
                "est_tokens": est_tok,
                "reported_input_tokens": res.input_tokens,
                "status_code": res.status_code,
                "latency_ms": round(res.latency_ms, 1),
                "head_ok": head_ok,
                "mid_ok": mid_ok,
                "tail_ok": tail_ok,
                "silent_clip_suspected": silent_clip,
            }
        )

    full_pass_tiers = [r["tier_k"] for r in rows if r["head_ok"] and r["mid_ok"] and r["tail_ok"]]
    max_verified_k = max(full_pass_tiers) if full_pass_tiers else 0

    cliff_data = {
        "max_tested_k": max_k,
        "max_verified_k": max_verified_k,
        "rows": rows,
        "flags": truncation_flags,
    }

    status = "FAIL" if any("偷截断" in f or "直接报错" in f or "丢头" in f for f in truncation_flags) else (
        "WARN" if truncation_flags else "PASS"
    )
    ev = EvidenceItem(
        id="cap_context_cliff",
        layer="L3_CAPABILITY",
        title=f"上下文断崖阶梯测绘（最高 {max_k}K Token）",
        status=status,
        severity="HIGH" if status == "FAIL" else ("MEDIUM" if status == "WARN" else "INFO"),
        summary=(
            "；".join(truncation_flags)
            if truncation_flags
            else f"上下文阶梯全通！最高 {max_verified_k}K Token 首/中/尾三点精准召回，未发现隐形截断或中段失忆。"
        ),
        details=cliff_data,
        score_impact=-20 if status == "FAIL" else (-8 if status == "WARN" else 8),
    )
    return ev, cliff_data
