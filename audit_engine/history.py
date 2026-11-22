"""Local Audit History Vault.

Automatically persists redacted AuditReport snapshots to ./history/ next to the
executable so users can compare a relay's behavior & IQ over time.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


def get_history_dir() -> Path:
    from .baselines import _writable_subdir

    return _writable_subdir("history")


class HistoryStore:
    def __init__(self, directory: Path | None = None, max_items: int = 80) -> None:
        self.dir = directory or get_history_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_items = max_items

    def save_report(self, report_dict: dict[str, Any]) -> str:
        aid = str(report_dict.get("audit_id") or "aud_unknown")
        target = self.dir / f"{aid}.json"
        target.write_text(json.dumps(report_dict, ensure_ascii=False, indent=2), encoding="utf-8")
        self._prune()
        return aid

    def _prune(self) -> None:
        files = sorted(self.dir.glob("aud_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in files[self.max_items :]:
            try:
                os.remove(old)
            except Exception:
                pass

    def list_reports(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in sorted(self.dir.glob("aud_*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                v = d.get("verdict") or {}
                cfg = d.get("config") or {}
                iq = d.get("iq") or {}
                attr = d.get("attribution") or {}
                out.append(
                    {
                        "audit_id": d.get("audit_id", p.stem),
                        "started_at": d.get("started_at", ""),
                        "duration_sec": d.get("duration_sec", 0),
                        "base_url": cfg.get("base_url", ""),
                        "model": cfg.get("model", ""),
                        "mode": cfg.get("mode", ""),
                        "protocol": v.get("detected_protocol", cfg.get("protocol", "")),
                        "authenticity_code": v.get("authenticity_code", ""),
                        "authenticity_label": v.get("authenticity_label", ""),
                        "trust_score": v.get("trust_score", 0),
                        "iq_score": iq.get("total_score"),
                        "iq_tier": iq.get("tier"),
                        "top_suspect": (attr.get("top_suspect") or {}).get("family_label", ""),
                    }
                )
            except Exception:
                continue
        return out

    def get_report(self, audit_id: str) -> dict[str, Any] | None:
        safe = "".join(c for c in audit_id if c.isalnum() or c in ("_", "-"))
        target = self.dir / f"{safe}.json"
        if not target.is_file():
            return None
        try:
            return json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            return None

    def delete_report(self, audit_id: str) -> bool:
        safe = "".join(c for c in audit_id if c.isalnum() or c in ("_", "-"))
        target = self.dir / f"{safe}.json"
        if target.is_file():
            os.remove(target)
            return True
        return False


def compare_history_reports(rep_old: dict[str, Any], rep_new: dict[str, Any]) -> dict[str, Any]:
    """Compare two historical audit reports to detect silent degradation or mid-week swaps."""
    from .baselines import compare_distributions, compare_tokenizer_vectors

    v1 = rep_old.get("verdict") or {}
    v2 = rep_new.get("verdict") or {}
    fp1 = rep_old.get("fingerprint") or {}
    fp2 = rep_new.get("fingerprint") or {}
    iq1 = rep_old.get("iq") or {}
    iq2 = rep_new.get("iq") or {}

    trust_delta = int(v2.get("trust_score") or 0) - int(v1.get("trust_score") or 0)
    iq_old = iq1.get("total_score")
    iq_new = iq2.get("total_score")
    iq_delta = round(float(iq_new) - float(iq_old), 1) if (iq_old is not None and iq_new is not None) else None

    jsd_drift, per_task = compare_distributions(
        fp1.get("distributions") or {}, fp2.get("distributions") or {}
    )
    tok_l1 = compare_tokenizer_vectors(
        fp1.get("tokenizer_vector") or {}, fp2.get("tokenizer_vector") or {}
    )

    dims_old = iq1.get("dimension_scores") or {}
    dims_new = iq2.get("dimension_scores") or {}
    dim_diffs = []
    for dk in sorted(set(dims_old.keys()) | set(dims_new.keys())):
        o_pct = (dims_old.get(dk) or {}).get("score_pct")
        n_pct = (dims_new.get(dk) or {}).get("score_pct")
        lbl = (dims_new.get(dk) or dims_old.get(dk) or {}).get("label", dk)
        delta = round(float(n_pct) - float(o_pct), 1) if (o_pct is not None and n_pct is not None) else None
        dim_diffs.append({"dimension": dk, "label": lbl, "old_pct": o_pct, "new_pct": n_pct, "delta": delta})

    old_anoms = set(v1.get("suspected_anomalies") or [])
    new_anoms = [a for a in (v2.get("suspected_anomalies") or []) if a not in old_anoms]

    degradation_flags: list[str] = []
    if jsd_drift is not None and jsd_drift >= 0.30:
        degradation_flags.append(f"分布显著漂移 (JSD={jsd_drift:.4f})，高度疑似前后两次背后已更换不同模型！")
    if tok_l1 is not None and tok_l1 >= 0.12:
        degradation_flags.append(f"词表向量发生变化 (L1={tok_l1:.4f})，疑似已切换底层模型家族！")
    if iq_delta is not None and iq_delta <= -12.0:
        degradation_flags.append(f"动态智商明显下滑 ({iq_old} → {iq_new}, {iq_delta:+.1f} 分)，疑似暗中降级或量化！")
    if trust_delta <= -15:
        degradation_flags.append(f"零信任可信分骤降 ({v1.get('trust_score')} → {v2.get('trust_score')}, {trust_delta:+d})！")

    return {
        "old_id": rep_old.get("audit_id"),
        "new_id": rep_new.get("audit_id"),
        "old_time": rep_old.get("started_at"),
        "new_time": rep_new.get("started_at"),
        "old_model": (rep_old.get("config") or {}).get("model"),
        "new_model": (rep_new.get("config") or {}).get("model"),
        "old_trust": v1.get("trust_score"),
        "new_trust": v2.get("trust_score"),
        "trust_delta": trust_delta,
        "old_iq": iq_old,
        "new_iq": iq_new,
        "iq_delta": iq_delta,
        "jsd_drift": jsd_drift,
        "per_task_jsd": per_task,
        "tokenizer_l1": tok_l1,
        "dim_diffs": dim_diffs,
        "new_anomalies": new_anoms,
        "degradation_flags": degradation_flags,
        "verdict_note": (
            "⚠ 检测到明显退化或暗中换模信号：" + "；".join(degradation_flags)
            if degradation_flags
            else "前后两次体检整体特征稳定，未见显著换模或降智退化。"
        ),
    }
