"""Audit Runner v2.0 orchestrating all forensic, attribution, context-cliff & 8-dim IQ engines."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .attribution import infer_underlying_attribution
from .baselines import BaselineStore
from .client import RelayClient
from .models import AuditConfig, AuditReport, EvidenceItem, FingerprintSummary, VerdictSummary
from .net_forensics import analyze_network_headers
from .plain_report import build_local_plain_summary, generate_ai_plain_summary
from .pricing import estimate_audit_cost
from .probes_advanced import (
    probe_concurrency_fallback,
    probe_knowledge_cutoff,
    probe_multiturn_agent_loop,
    probe_parameter_obedience,
    probe_reasoning_and_crypto_ext,
    probe_regex_brand_masking,
    probe_smart_routing_trap,
    probe_sse_timing,
)
from .probes_billing import (
    audit_usage_physics_sanity,
    probe_assistant_prefill,
    probe_billing_multiplier,
    probe_chart_vision_anti_ocr,
    probe_client_cloaking,
    probe_native_pdf,
    probe_output_cap,
    probe_quantization_precision,
)
from .probes_context import run_context_cliff_ladder
from .probes_fingerprint import run_fingerprint_probes
from .probes_iq import run_iq_suite
from .probes_protocol import run_protocol_probes
from .probes_tokenizer import run_tokenizer_probes
from .probes_v11 import (
    audit_too_fast_flagship_physics,
    probe_hires_vision_downscale,
    probe_logit_bias_vocab_snipe,
    probe_multiturn_system_persistence,
    probe_parallel_tool_and_recovery,
    probe_prompt_cache_physics,
)
from .verdict import synthesize_verdict

EventCallback = Callable[[dict[str, Any]], None]


def run_full_audit(
    config: AuditConfig,
    baseline_store: BaselineStore | None = None,
    on_event: EventCallback | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> AuditReport:
    """Execute the full v2.0 zero-trust fingerprinting, attribution & 8-dim IQ audit pipeline."""
    store = baseline_store or BaselineStore()
    audit_id = f"aud_{uuid.uuid4().hex[:10]}"
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()

    def emit(phase: str, message: str, progress: int | None = None, extra: dict[str, Any] | None = None) -> None:
        if on_event:
            ev: dict[str, Any] = {
                "type": "progress",
                "phase": phase,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if progress is not None:
                ev["progress"] = progress
            if extra:
                ev.update(extra)
            on_event(ev)

    client = RelayClient(config)
    evidences: list[EvidenceItem] = []
    engine_clues: list[str] = []
    tok_vector: dict[str, Any] = {}
    tok_family = "unknown"
    fp_summary = FingerprintSummary()
    iq_summary = None
    stream_metrics: dict[str, Any] = {}
    context_cliff: dict[str, Any] | None = None
    budget_hit = False

    def should_stop() -> bool:
        nonlocal budget_hit
        if cancel_check and cancel_check():
            return True
        if config.budget_cap_cny and config.budget_cap_cny > 0:
            spent = client.current_estimated_cny()
            if spent >= config.budget_cap_cny:
                if not budget_hit:
                    budget_hit = True
                    emit(
                        "budget_cap",
                        f"触发预算熔断上限（当前估算 ¥{spent:.4f} ≥ 上限 ¥{config.budget_cap_cny:.2f}），自动停止后续探针并生成当前报告！",
                        94,
                    )
                return True
        return False

    try:
        # Phase 0: Connectivity & Protocol Auto-Detection
        emit("connect", f"正在连接 {config.base_url} 并识别协议 ({config.protocol})...", 3)
        detected_proto, conn_res = client.detect_protocol()

        if not conn_res.ok:
            evidences.append(
                EvidenceItem(
                    id="connectivity_fail",
                    layer="L1_PROTOCOL",
                    title="API 连通性与鉴权校验",
                    status="FAIL",
                    severity="CRITICAL",
                    summary=f"无法连通目标接口或鉴权失败 (协议={detected_proto}, HTTP {conn_res.status_code}): {conn_res.error[:240]}",
                    details={"url": conn_res.url, "status_code": conn_res.status_code, "error": conn_res.error},
                    score_impact=-50,
                )
            )
            verdict = VerdictSummary(
                authenticity_code="ERROR",
                authenticity_label="连接失败 / 鉴权被拒",
                trust_score=0,
                confidence="HIGH",
                headline=f"目标端点请求失败 (HTTP {conn_res.status_code})，请检查 API 地址、Key、模型名及协议类型。",
                detected_protocol=detected_proto,
                suspected_anomalies=[conn_res.error[:260]],
                recommendations=[
                    "确认 Base URL 是否正确（如 https://api.xxx.com 或 https://api.xxx.com/v1）。",
                    "确认 API Key 余额充足且拥有调用该模型的权限。",
                    "如中转站使用非标准路径，请尝试手动切换协议下拉框（OpenAI 兼容 / Anthropic / Gemini）。",
                ],
            )
            return AuditReport(
                audit_id=audit_id,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                duration_sec=round(time.perf_counter() - t0, 2),
                config=config.safe_dict(),
                verdict=verdict,
                evidences=evidences,
                fingerprint=fp_summary,
                iq=None,
                attribution={},
                context_cliff=None,
                stream_metrics={},
                telemetry=client.telemetry,
            )

        emit(
            "connect_ok",
            f"连通成功！识别协议：{detected_proto}（首呼耗时 {conn_res.latency_ms:.0f}ms，返回模型字段：`{conn_res.returned_model or '未返回'}`）",
            8,
        )

        if client.telemetry.get("protocol_notes"):
            engine_clues.extend(client.telemetry["protocol_notes"])

        # Phase 1: L1 Cryptographic, Protocol, SSE Micro-Timing, Parameter Obedience & Reasoning Budget
        if config.run_protocol and not (cancel_check and cancel_check()):
            emit("protocol", "阶段 1/5：执行 L1 密码学验签、协议边界、缓存阶梯、工具与视觉取证...", 13)
            p_evs, p_clues = run_protocol_probes(
                client,
                config,
                emit=lambda step, msg: emit(step, msg, 18),
            )
            evidences.extend(p_evs)
            engine_clues.extend(p_clues)

            if not (cancel_check and cancel_check()):
                sse_ev, stream_metrics = probe_sse_timing(
                    client, config, emit=lambda step, msg: emit(step, msg, 22)
                )
                evidences.append(sse_ev)

            if config.run_param_obedience and not (cancel_check and cancel_check()):
                po_evs = probe_parameter_obedience(
                    client, config, emit=lambda step, msg: emit(step, msg, 26)
                )
                evidences.extend(po_evs)

            if not (cancel_check and cancel_check()):
                rc_evs = probe_reasoning_and_crypto_ext(
                    client, config, emit=lambda step, msg: emit(step, msg, 28)
                )
                evidences.extend(rc_evs)

            if config.run_regex_canary and not (cancel_check and cancel_check()):
                evidences.append(
                    probe_regex_brand_masking(client, config, emit=lambda step, msg: emit(step, msg, 30))
                )

            if config.run_agent_loop and config.mode in ("standard", "deep") and not (cancel_check and cancel_check()):
                evidences.append(
                    probe_multiturn_agent_loop(client, config, emit=lambda step, msg: emit(step, msg, 31))
                )

            if config.run_concurrency and config.mode in ("standard", "deep") and not (cancel_check and cancel_check()):
                evidences.append(
                    probe_concurrency_fallback(client, config, emit=lambda step, msg: emit(step, msg, 30))
                )

            if config.mode in ("standard", "deep") and not (cancel_check and cancel_check()):
                evidences.append(
                    probe_client_cloaking(client, config, emit=lambda step, msg: emit(step, msg, 30))
                )
                pf_ev = probe_assistant_prefill(client, config, emit=lambda step, msg: emit(step, msg, 31))
                if pf_ev is not None:
                    evidences.append(pf_ev)

            if config.run_pdf_probe and config.mode in ("standard", "deep") and not (cancel_check and cancel_check()):
                pdf_ev = probe_native_pdf(client, config, emit=lambda step, msg: emit(step, msg, 31))
                if pdf_ev is not None:
                    evidences.append(pdf_ev)

            if config.run_vision and config.mode in ("standard", "deep") and not should_stop():
                evidences.append(
                    probe_chart_vision_anti_ocr(client, config, emit=lambda step, msg: emit(step, msg, 32))
                )
                if config.run_vision_hires and not should_stop():
                    evidences.append(
                        probe_hires_vision_downscale(client, config, emit=lambda step, msg: emit(step, msg, 32))
                    )

            if config.run_v11_probes and not should_stop():
                lb_ev = probe_logit_bias_vocab_snipe(client, config, emit=lambda step, msg: emit(step, msg, 32))
                if lb_ev is not None:
                    evidences.append(lb_ev)
                if config.mode in ("standard", "deep") and not should_stop():
                    cp_ev = probe_prompt_cache_physics(client, config, emit=lambda step, msg: emit(step, msg, 32))
                    if cp_ev is not None:
                        evidences.append(cp_ev)
                if config.mode in ("standard", "deep") and not should_stop():
                    evidences.append(
                        probe_multiturn_system_persistence(client, config, emit=lambda step, msg: emit(step, msg, 32))
                    )
                if config.run_agent_loop and config.mode in ("standard", "deep") and not should_stop():
                    evidences.append(
                        probe_parallel_tool_and_recovery(client, config, emit=lambda step, msg: emit(step, msg, 32))
                    )

            if config.run_output_cap and not should_stop():
                evidences.append(
                    probe_output_cap(client, config, emit=lambda step, msg: emit(step, msg, 32))
                )

            emit("protocol_done", f"阶段 1 完成，累计采集 {len(evidences)} 项协议与能力证据。", 33)

        # Phase 2: Tokenizer Boundary & Billing Forensics
        if config.run_tokenizer and not should_stop():
            emit("tokenizer", "阶段 2/5：执行 Tokenizer 词表差分、单 Token 截断与计费膨胀审计...", 36)
            t_evs, tok_vector, tok_family = run_tokenizer_probes(
                client,
                config,
                emit=lambda step, msg: emit(step, msg, 42),
            )
            evidences.extend(t_evs)
            if config.run_billing_mult and config.mode in ("standard", "deep") and not should_stop():
                evidences.append(
                    probe_billing_multiplier(client, config, emit=lambda step, msg: emit(step, msg, 44))
                )
            if config.run_quant_precision and config.mode in ("standard", "deep") and not should_stop():
                evidences.append(
                    probe_quantization_precision(client, config, emit=lambda step, msg: emit(step, msg, 45))
                )
            emit("tokenizer_done", f"阶段 2 完成，词表特征倾向：{tok_family}", 46)

        # Phase 3: L2 Single-Token Behavioral Fingerprint, Smart-Routing Trap & Knowledge Cutoff
        if config.run_fingerprint and not should_stop():
            emit("fingerprint", "阶段 3/5：采集单 Token 行为分布指纹、T=0 一致性、Logprobs 与基线 JSD 比对...", 49)
            f_evs, fp_summary = run_fingerprint_probes(
                client,
                config,
                tokenizer_vector=tok_vector,
                tokenizer_family=tok_family,
                baseline_store=store,
                emit=lambda step, msg: emit(step, msg, 58),
                cancel_check=should_stop,
            )
            evidences.extend(f_evs)

            if config.run_smart_routing and not should_stop():
                sr_ev, sl_jsd = probe_smart_routing_trap(
                    client,
                    config,
                    short_distributions=fp_summary.distributions,
                    emit=lambda step, msg: emit(step, msg, 64),
                )
                evidences.append(sr_ev)
                fp_summary.short_vs_long_jsd = sl_jsd

            emit("fingerprint_done", f"阶段 3 完成，共采集 {fp_summary.total_samples} 个分布样本。", 68)
        else:
            fp_summary.tokenizer_vector = tok_vector
            fp_summary.tokenizer_family_guess = tok_family

        if config.run_cutoff and not should_stop():
            cut_ev, cut_info = probe_knowledge_cutoff(
                client, config, emit=lambda step, msg: emit(step, msg, 71)
            )
            evidences.append(cut_ev)
            fp_summary.cutoff_estimate = cut_info

        # Phase 4: Optional Context Cliff Ladder Heatmap
        if config.run_context_cliff and not should_stop():
            emit("context_cliff", f"阶段 4/5：执行上下文断崖阶梯压测（最高 {config.context_cliff_max_k}K）...", 74)
            cc_ev, context_cliff = run_context_cliff_ladder(
                client,
                config,
                emit=lambda step, msg: emit(step, msg, 78),
                cancel_check=should_stop,
            )
            evidences.append(cc_ev)

        # Phase 5: 10-Dimension Anti-Contamination Dynamic IQ Evaluation
        if config.run_iq and not should_stop():
            emit("iq", "阶段 5/5：启动动态反污染工程智商测评（含 SQLite / 外科补丁 / RAG 防幻觉 / 二维空间）...", 81)
            iq_evs, iq_summary = run_iq_suite(
                client,
                config,
                emit=lambda step, msg: emit(step, msg, 92),
                cancel_check=should_stop,
            )
            evidences.extend(iq_evs)
            emit(
                "iq_done",
                f"智商测评完成！综合得分 {iq_summary.total_score}/100 ({iq_summary.tier_label})。",
                96,
            )

        # Telemetry latency percentiles, jitter CV & histogram bins
        lats = sorted(client.telemetry.get("latencies_ms") or [])
        ttfts = sorted(client.telemetry.get("ttfts_ms") or [])
        tel_out = dict(client.telemetry)
        avg_lat = round(sum(lats) / len(lats), 1) if lats else 0.0
        tel_out["avg_latency_ms"] = avg_lat
        tel_out["min_latency_ms"] = lats[0] if lats else 0.0
        tel_out["p50_latency_ms"] = lats[len(lats) // 2] if lats else 0.0
        tel_out["p95_latency_ms"] = lats[min(len(lats) - 1, int(len(lats) * 0.95))] if lats else 0.0
        tel_out["p99_latency_ms"] = lats[min(len(lats) - 1, int(len(lats) * 0.99))] if lats else 0.0
        tel_out["max_latency_ms"] = lats[-1] if lats else 0.0
        tel_out["avg_ttft_ms"] = round(sum(ttfts) / len(ttfts), 1) if ttfts else None
        if len(lats) >= 6 and avg_lat > 0:
            var = sum((x - avg_lat) ** 2 for x in lats) / len(lats)
            cv = round((var ** 0.5) / avg_lat, 3)
            # 8-bucket latency histogram
            lo, hi = lats[0], max(lats[-1], lats[0] + 1.0)
            step = (hi - lo) / 8.0
            bins = [0] * 8
            for v_lat in lats:
                bi = min(7, int((v_lat - lo) / step))
                bins[bi] += 1
            tel_out["latency_jitter_cv"] = cv
            tel_out["latency_histogram"] = {
                "min_ms": round(lo, 1),
                "max_ms": round(hi, 1),
                "bins": bins,
            }
            tel_out["bimodal_latency_suspected"] = bool(cv >= 0.85 and tel_out["p95_latency_ms"] > tel_out["p50_latency_ms"] * 3.0)
        tel_out["cost_estimate"] = estimate_audit_cost(config.model, tel_out)
        net_info = analyze_network_headers(tel_out.get("server_headers") or {})
        tel_out["network_forensics"] = net_info
        if net_info.get("clues"):
            engine_clues.extend(net_info["clues"])
        tel_out.pop("latencies_ms", None)
        tel_out.pop("ttfts_ms", None)

        phys_ev = audit_usage_physics_sanity(tel_out, stream_metrics)
        if phys_ev is not None:
            evidences.append(phys_ev)
        tps_ev = audit_too_fast_flagship_physics(config, stream_metrics, iq_summary)
        if tps_ev is not None:
            evidences.append(tps_ev)

        tel_out["stealth_mode"] = bool(config.stealth_mode)
        tel_out["budget_cap_cny"] = float(config.budget_cap_cny or 0.0)
        tel_out["budget_cap_hit"] = bool(budget_hit)
        if budget_hit:
            est_cny = (tel_out.get("cost_estimate") or {}).get("estimated_cny", 0.0)
            evidences.append(
                EvidenceItem(
                    id="budget_cap_guard",
                    layer="L4_CONSISTENCY",
                    title="预算上限熔断保护触发",
                    status="INFO",
                    severity="INFO",
                    summary=f"本次累计官方估算花费 ¥{est_cny:.4f} 已触及设定上限 ¥{config.budget_cap_cny:.2f}，已安全熔断后续探针并基于已采集证据出具报告。",
                    details={"estimated_cny": est_cny, "budget_cap_cny": config.budget_cap_cny},
                    score_impact=0,
                )
            )

        # Synthesize Underlying Model Attribution + Zero-Trust Verdict
        emit("verdict", "正在执行底层模型家族归因推演并汇总零信任仲裁结论...", 98)
        attribution = infer_underlying_attribution(
            claimed_model=config.model,
            detected_protocol=detected_proto,
            evidences=evidences,
            fingerprint=fp_summary,
            iq=iq_summary,
            telemetry=tel_out,
        )
        verdict = synthesize_verdict(
            detected_protocol=detected_proto,
            model=config.model,
            evidences=evidences,
            engine_clues=engine_clues,
            fingerprint=fp_summary,
            iq=iq_summary,
            attribution=attribution,
        )

        # Plain-Language ("大白话") Summary (default ON: uses audited key, with zero-jargon local fallback)
        if config.run_plain_summary and not (cancel_check and cancel_check()):
            emit("plain_summary", "正在调用当前 Key 将技术证据翻译为通俗大白话总结...", 99)
            plain_summary = generate_ai_plain_summary(
                client,
                config,
                verdict=verdict,
                evidences=evidences,
                fingerprint=fp_summary,
                iq=iq_summary,
                attribution=attribution,
                telemetry=tel_out,
            )
        else:
            plain_summary = build_local_plain_summary(
                model=config.model,
                verdict=verdict,
                evidences=evidences,
                fingerprint=fp_summary,
                iq=iq_summary,
                attribution=attribution,
                telemetry=tel_out,
            )

        report = AuditReport(
            audit_id=audit_id,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration_sec=round(time.perf_counter() - t0, 2),
            config=config.safe_dict(),
            verdict=verdict,
            evidences=evidences,
            fingerprint=fp_summary,
            iq=iq_summary,
            attribution=attribution,
            context_cliff=context_cliff,
            stream_metrics=stream_metrics,
            telemetry=tel_out,
            plain_summary=plain_summary,
        )
        emit("complete", "全部体检完成！", 100)
        return report
    finally:
        client.close()
