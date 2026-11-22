"""A/B Dual-Endpoint Arena & Same-Relay Alias Fraud Detector.

Runs two endpoints (or two model names on the same relay, e.g. Opus vs Sonnet)
using the exact same IQ seed and behavioral probes, then computes direct A↔B
JSD divergence, tokenizer distance, logprobs overlap, and IQ head-to-head.
"""

from __future__ import annotations

import random
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

from .baselines import (
    BaselineStore,
    compare_distributions,
    compare_logprobs_signatures,
    compare_tokenizer_vectors,
)
from .models import AuditConfig, AuditReport
from .runner import run_full_audit

EventCallback = Callable[[dict[str, Any]], None]


def run_ab_arena(
    cfg_a: AuditConfig,
    cfg_b: AuditConfig,
    *,
    baseline_store: BaselineStore | None = None,
    on_event: EventCallback | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run synchronized A/B audit on two targets and synthesize head-to-head comparison."""
    arena_id = f"arena_{uuid.uuid4().hex[:10]}"
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()

    # Force identical IQ seed for 100% fair A vs B comparison!
    shared_seed = cfg_a.iq_seed if cfg_a.iq_seed is not None else (
        cfg_b.iq_seed if cfg_b.iq_seed is not None else random.randint(100000, 999999)
    )
    cfg_a.iq_seed = shared_seed
    cfg_b.iq_seed = shared_seed

    prog_state = {"A": 0, "B": 0}

    def emit(phase: str, message: str, progress: int | None = None) -> None:
        if on_event:
            ev: dict[str, Any] = {
                "type": "progress",
                "phase": phase,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if progress is not None:
                ev["progress"] = progress
            on_event(ev)

    def _side_cb(tag: str):
        def _cb(ev: dict[str, Any]) -> None:
            if ev.get("type") == "progress":
                p = int(ev.get("progress") or prog_state[tag])
                prog_state[tag] = p
                avg_p = int((prog_state["A"] + prog_state["B"]) / 2)
                emit(f"arena_{tag}", f"[{tag} · {cfg_a.model if tag == 'A' else cfg_b.model}] {ev.get('message', '')}", min(96, avg_p))
        return _cb

    emit("arena_start", f"启动 A/B 双端同台对决（共享动态智商 Seed={shared_seed}）...", 3)

    store = baseline_store or BaselineStore()
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(run_full_audit, cfg_a, store, _side_cb("A"), cancel_check)
        fut_b = pool.submit(run_full_audit, cfg_b, store, _side_cb("B"), cancel_check)
        rep_a: AuditReport = fut_a.result()
        rep_b: AuditReport = fut_b.result()

    emit("arena_compare", "正在计算 A ↔ B 直接 JSD 散度、词表距离与同题智商逐项对比...", 98)

    mean_jsd, per_task_jsd = compare_distributions(
        rep_a.fingerprint.distributions, rep_b.fingerprint.distributions
    )
    tok_l1 = compare_tokenizer_vectors(
        rep_a.fingerprint.tokenizer_vector, rep_b.fingerprint.tokenizer_vector
    )
    lp_cmp = compare_logprobs_signatures(
        rep_a.fingerprint.logprobs_signature, rep_b.fingerprint.logprobs_signature
    )

    iq_a = rep_a.iq.total_score if rep_a.iq else None
    iq_b = rep_b.iq.total_score if rep_b.iq else None
    iq_delta = round(iq_a - iq_b, 1) if (iq_a is not None and iq_b is not None) else None

    same_claimed_model = cfg_a.model.strip().lower() == cfg_b.model.strip().lower()

    # Determine A vs B relationship verdict!
    if rep_a.verdict.authenticity_code == "ERROR" or rep_b.verdict.authenticity_code == "ERROR":
        rel_code = "INCOMPLETE_ERROR"
        rel_label = "至少一端连接失败，无法完成对比"
        rel_summary = "请检查失败端点的地址、Key 或模型名后重试。"
    elif mean_jsd is None:
        rel_code = "NO_DISTRIBUTION"
        rel_label = "未采集分布指纹，仅可对比协议与智商"
        rel_summary = "未启用单 Token 指纹采样，无法计算直接 JSD 同源度。"
    else:
        same_backend_strong = mean_jsd <= 0.16 and (tok_l1 is None or tok_l1 <= 0.08)
        same_backend_likely = mean_jsd <= 0.28 and (tok_l1 is None or tok_l1 <= 0.14)
        if lp_cmp and lp_cmp.get("top1_match_rate", 0) >= 0.92 and (lp_cmp.get("mean_logprob_l1") or 9) <= 0.08:
            same_backend_strong = True
        if lp_cmp and lp_cmp.get("top1_match_rate", 0) < 0.45:
            same_backend_strong = False
            same_backend_likely = False

        if not same_claimed_model and same_backend_strong:
            rel_code = "ALIAS_FRAUD_DETECTED"
            rel_label = "⚠ 抓获高危「别名套娃」！A 与 B 极可能为同一底层模型"
            rel_summary = (
                f"A (`{cfg_a.model}`) 与 B (`{cfg_b.model}`) 宣称是不同模型，但直接分布散度 JSD 仅 {mean_jsd:.4f}"
                + (f"、词表偏差 {tok_l1:.4f}" if tok_l1 is not None else "")
                + "！高度疑似中转站将便宜模型改名别名冒充高价旗舰！"
            )
        elif same_claimed_model and same_backend_strong:
            rel_code = "SAME_UNDERLYING_MODEL"
            rel_label = "强证据支持：A 与 B 背后为同一底层模型"
            rel_summary = (
                f"两个端点服务同一宣称模型 `{cfg_a.model}`，直接分布散度 JSD = {mean_jsd:.4f}（高度同源）"
                + (f"，同题智商差 {iq_delta:+.1f} 分" if iq_delta is not None else "")
                + "。"
            )
        elif same_backend_likely:
            rel_code = "SIMILAR_OR_NOISY"
            rel_label = "分布接近 · 可能同源（含轻微量化/采样波动）"
            rel_summary = (
                f"A 与 B 分布散度 JSD = {mean_jsd:.4f}"
                + (f"，词表偏差 {tok_l1:.4f}" if tok_l1 is not None else "")
                + "。建议切换「深度模式」加大样本数以进一步拉开统计显著性。"
            )
        else:
            if same_claimed_model:
                rel_code = "DIFFERENT_MODEL_FRAUD"
                rel_label = "🚨 货不对板！A 与 B 宣称同模型但底层完全不同"
                rel_summary = (
                    f"两端均请求 `{cfg_a.model}`，但行为分布 JSD 高达 {mean_jsd:.4f}"
                    + (f"、词表偏差 {tok_l1:.4f}" if tok_l1 is not None else "")
                    + "！证明至少有一端存在换模/套壳/严重篡改！"
                )
            else:
                rel_code = "DISTINCT_MODELS_OK"
                rel_label = "正常区分：A 与 B 确为不同底层模型"
                rel_summary = (
                    f"A (`{cfg_a.model}`) 与 B (`{cfg_b.model}`) 行为分布显著分离 (JSD = {mean_jsd:.4f})，"
                    "符合不同模型应有的指纹差异，未见简单别名套娃。"
                )

    # Head-to-head question comparison
    h2h_questions = []
    if rep_a.iq and rep_b.iq:
        b_map = {q.id: q for q in rep_b.iq.questions}
        for qa in rep_a.iq.questions:
            qb = b_map.get(qa.id)
            h2h_questions.append(
                {
                    "id": qa.id,
                    "dimension_label": qa.dimension_label,
                    "title": qa.title,
                    "max_score": qa.max_score,
                    "score_a": qa.score,
                    "passed_a": qa.passed,
                    "latency_a": qa.latency_ms,
                    "score_b": qb.score if qb else 0,
                    "passed_b": qb.passed if qb else False,
                    "latency_b": qb.latency_ms if qb else 0,
                }
            )

    result = {
        "arena_id": arena_id,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(time.perf_counter() - t0, 2),
        "shared_iq_seed": shared_seed,
        "same_claimed_model": same_claimed_model,
        "comparison": {
            "relation_code": rel_code,
            "relation_label": rel_label,
            "relation_summary": rel_summary,
            "mean_jsd": mean_jsd,
            "per_task_jsd": per_task_jsd,
            "tokenizer_l1": tok_l1,
            "logprobs_compare": lp_cmp,
            "iq_a": iq_a,
            "iq_b": iq_b,
            "iq_delta": iq_delta,
            "h2h_questions": h2h_questions,
        },
        "report_a": rep_a.to_dict(),
        "report_b": rep_b.to_dict(),
    }
    emit("complete", "A/B 同台对决完成！", 100)
    return result
