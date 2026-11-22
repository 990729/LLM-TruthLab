"""Multi-Relay Batch Leaderboard & Automatic N×N Cross-Target JSD Matrix.

Audits 2..12 endpoints/models with a shared dynamic IQ seed, ranks them on a
Trust + IQ + Latency leaderboard, and computes an N×N pairwise JSD similarity
matrix to expose alias clusters (multiple priced models pointing to the same
underlying backend).
"""

from __future__ import annotations

import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .baselines import BaselineStore, compare_distributions, compare_tokenizer_vectors
from .models import AuditConfig, AuditReport
from .runner import run_full_audit

EventCallback = Callable[[dict[str, Any]], None]


def run_batch_leaderboard(
    targets: list[dict[str, Any]],
    *,
    mode: str = "quick",
    run_iq: bool = True,
    run_protocol: bool = True,
    shared_seed: int | None = None,
    baseline_store: BaselineStore | None = None,
    on_event: EventCallback | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run batch audit across multiple relay targets and build N×N similarity matrix."""
    batch_id = f"batch_{uuid.uuid4().hex[:10]}"
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    seed = shared_seed if shared_seed is not None else random.randint(100000, 999999)
    store = baseline_store or BaselineStore()

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

    total = len(targets)
    emit("batch_start", f"启动批量红黑榜横评（共 {total} 个目标，共享智商 Seed={seed}）...", 2)

    reports: list[tuple[str, AuditReport]] = []
    for idx, item in enumerate(targets, start=1):
        if cancel_check and cancel_check():
            break
        label = str(item.get("label") or f"#{idx} {item.get('model', '')}").strip()
        base_pct = int(((idx - 1) / max(1, total)) * 92) + 3
        span = max(1, int(92 / max(1, total)))

        cfg = AuditConfig(
            base_url=str(item.get("base_url") or "").strip(),
            api_key=str(item.get("api_key") or "").strip(),
            model=str(item.get("model") or "").strip(),
            protocol=str(item.get("protocol") or "auto"),
            mode=mode,
            run_protocol=run_protocol,
            run_tokenizer=run_protocol,
            run_fingerprint=True,
            run_iq=run_iq,
            run_vision=False,
            run_long_context=False,
            run_param_obedience=run_protocol,
            run_smart_routing=False,
            run_cutoff=run_protocol,
            run_context_cliff=False,
            iq_seed=seed,
        )

        def _sub_ev(ev: dict[str, Any], _lbl=label, _bp=base_pct, _sp=span, _i=idx) -> None:
            if ev.get("type") == "progress":
                p = int(ev.get("progress") or 0)
                mapped = min(95, _bp + int((p / 100.0) * _sp))
                emit("batch_item", f"[{_i}/{total} {_lbl}] {ev.get('message', '')}", mapped)

        rep = run_full_audit(cfg, baseline_store=store, on_event=_sub_ev, cancel_check=cancel_check)
        reports.append((label, rep))

    emit("batch_matrix", "正在计算 N×N 两两 JSD 同源聚类矩阵并生成红黑榜...", 97)

    # Build N×N JSD matrix and flag suspicious alias clusters
    n = len(reports)
    matrix: list[list[float | None]] = [[None] * n for _ in range(n)]
    alias_alerts: list[str] = []

    for i in range(n):
        matrix[i][i] = 0.0
        for j in range(i + 1, n):
            lbl_i, rep_i = reports[i]
            lbl_j, rep_j = reports[j]
            jsd, _ = compare_distributions(
                rep_i.fingerprint.distributions, rep_j.fingerprint.distributions
            )
            tok_l1 = compare_tokenizer_vectors(
                rep_i.fingerprint.tokenizer_vector, rep_j.fingerprint.tokenizer_vector
            )
            matrix[i][j] = jsd
            matrix[j][i] = jsd
            if jsd is not None:
                m_i = str(rep_i.config.get("model", "")).lower()
                m_j = str(rep_j.config.get("model", "")).lower()
                if m_i != m_j and jsd <= 0.16 and (tok_l1 is None or tok_l1 <= 0.08):
                    alias_alerts.append(
                        f"⚠ 疑似别名套娃：`{lbl_i}` ({m_i}) 与 `{lbl_j}` ({m_j}) 宣称不同模型，但 JSD 仅 {jsd:.4f}！"
                    )
                elif m_i == m_j and jsd >= 0.35:
                    alias_alerts.append(
                        f"🚨 同名不同源：`{lbl_i}` 与 `{lbl_j}` 均宣称 `{m_i}`，但 JSD 高达 {jsd:.4f}，至少有一家掺假！"
                    )

    rows = []
    for idx, (lbl, rep) in enumerate(reports):
        v = rep.verdict
        iq_s = rep.iq.total_score if rep.iq else None
        composite = round(v.trust_score * 0.6 + (iq_s if iq_s is not None else v.trust_score) * 0.4, 1)
        rows.append(
            {
                "index": idx,
                "label": lbl,
                "audit_id": rep.audit_id,
                "base_url": rep.config.get("base_url", ""),
                "model": rep.config.get("model", ""),
                "protocol": v.detected_protocol,
                "authenticity_code": v.authenticity_code,
                "authenticity_label": v.authenticity_label,
                "trust_score": v.trust_score,
                "iq_score": iq_s,
                "iq_tier": rep.iq.tier if rep.iq else None,
                "composite_score": composite,
                "avg_latency_ms": rep.telemetry.get("avg_latency_ms", 0.0),
                "tps": (rep.stream_metrics or {}).get("effective_tps", 0.0),
                "top_suspect": ((rep.attribution or {}).get("top_suspect") or {}).get("family_label", ""),
                "family_conflict": bool((rep.attribution or {}).get("family_conflict")),
                "anomalies_count": len(v.suspected_anomalies),
                "report": rep.to_dict(),
            }
        )

    ranked_rows = sorted(rows, key=lambda r: (r["composite_score"], r["trust_score"]), reverse=True)

    result = {
        "batch_id": batch_id,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(time.perf_counter() - t0, 2),
        "shared_iq_seed": seed,
        "labels": [lbl for lbl, _ in reports],
        "matrix_jsd": matrix,
        "alias_alerts": alias_alerts,
        "leaderboard": ranked_rows,
    }
    emit("complete", "批量红黑榜横评完成！", 100)
    return result
