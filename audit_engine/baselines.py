"""Baseline fingerprint persistence & comparison library.

Allows users to record verified official API runs as ground-truth reference
baselines (saved next to the executable in ./baselines/) and import/export them.
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _writable_subdir(name: str) -> Path:
    """Resolve persistent storage next to .exe if writable, else fall back to %LOCALAPPDATA%\\LLM-TruthLab."""
    candidates: list[Path] = []
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / name)
    else:
        candidates.append(Path(__file__).resolve().parent.parent / name)
    local_app = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if local_app:
        candidates.append(Path(local_app) / "LLM-TruthLab" / name)
    candidates.append(Path.home() / ".llm-truthlab" / name)

    for cand in candidates:
        try:
            cand.mkdir(parents=True, exist_ok=True)
            probe = cand / ".write_check"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return cand
        except Exception:
            continue
    return candidates[-1]


def get_app_data_dir() -> Path:
    """Resolve persistent storage directory next to the .exe (with safe LocalAppData fallback)."""
    return _writable_subdir("baselines")


def _safe_slug(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", name.strip())
    return s[:48] or "baseline"


def jensen_shannon_divergence(dist_p: dict[str, int], dist_q: dict[str, int]) -> float:
    """Compute base-2 Jensen-Shannon Divergence in [0.0, 1.0]."""
    total_p = sum(dist_p.values())
    total_q = sum(dist_q.values())
    if total_p <= 0 or total_q <= 0:
        return 1.0

    keys = set(dist_p.keys()) | set(dist_q.keys())
    kl_pm = 0.0
    kl_qm = 0.0
    for k in keys:
        p = dist_p.get(k, 0) / total_p
        q = dist_q.get(k, 0) / total_q
        m = 0.5 * (p + q)
        if p > 0 and m > 0:
            kl_pm += p * math.log2(p / m)
        if q > 0 and m > 0:
            kl_qm += q * math.log2(q / m)

    jsd = 0.5 * (kl_pm + kl_qm)
    return max(0.0, min(1.0, jsd))


def compare_distributions(
    target_dists: dict[str, dict[str, int]],
    ref_dists: dict[str, dict[str, int]],
) -> tuple[float | None, dict[str, float]]:
    """Compare two multi-task single-token distribution maps via mean JSD."""
    common_tasks = sorted(set(target_dists.keys()) & set(ref_dists.keys()))
    per_task: dict[str, float] = {}
    for t in common_tasks:
        if target_dists[t] and ref_dists[t]:
            per_task[t] = round(jensen_shannon_divergence(target_dists[t], ref_dists[t]), 4)
    if not per_task:
        return None, {}
    mean_jsd = round(sum(per_task.values()) / len(per_task), 4)
    return mean_jsd, per_task


def compare_tokenizer_vectors(v1: dict[str, Any], v2: dict[str, Any]) -> float | None:
    """Return normalized L1 mismatch (0.0 = identical tokenizer vector, higher = different)."""
    d1 = v1.get("deltas") or {}
    d2 = v2.get("deltas") or {}
    keys = sorted(set(d1.keys()) & set(d2.keys()))
    if not keys:
        return None
    diffs = []
    for k in keys:
        a, b = float(d1[k]), float(d2[k])
        denom = max(1.0, max(a, b))
        diffs.append(abs(a - b) / denom)
    return round(sum(diffs) / len(diffs), 4)


def compare_logprobs_signatures(
    sig1: list[dict[str, Any]], sig2: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Compare top-token logprobs signatures from fixed prompts."""
    if not sig1 or not sig2:
        return None
    by_id1 = {x.get("prompt_id"): x for x in sig1 if x.get("prompt_id")}
    by_id2 = {x.get("prompt_id"): x for x in sig2 if x.get("prompt_id")}
    common = sorted(set(by_id1.keys()) & set(by_id2.keys()))
    if not common:
        return None

    exact_top1 = 0
    total_pos = 0
    lp_deltas: list[float] = []
    for pid in common:
        toks1 = by_id1[pid].get("tokens") or []
        toks2 = by_id2[pid].get("tokens") or []
        for t1, t2 in zip(toks1, toks2):
            total_pos += 1
            if t1.get("token") == t2.get("token"):
                exact_top1 += 1
                lp1 = float(t1.get("logprob", 0.0))
                lp2 = float(t2.get("logprob", 0.0))
                lp_deltas.append(abs(lp1 - lp2))

    if total_pos == 0:
        return None
    return {
        "positions_compared": total_pos,
        "top1_match_rate": round(exact_top1 / total_pos, 4),
        "mean_logprob_l1": round(sum(lp_deltas) / len(lp_deltas), 4) if lp_deltas else None,
    }


class BaselineStore:
    """Manage local JSON baseline profiles."""

    def __init__(self, directory: Path | None = None) -> None:
        self.dir = directory or get_app_data_dir()
        self.dir.mkdir(parents=True, exist_ok=True)

    def list_baselines(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("id"):
                    items.append(
                        {
                            "id": data["id"],
                            "name": data.get("name", p.stem),
                            "model": data.get("model", ""),
                            "protocol": data.get("protocol", ""),
                            "notes": data.get("notes", ""),
                            "created_at": data.get("created_at", ""),
                            "total_samples": data.get("fingerprint", {}).get("total_samples", 0),
                            "has_logprobs": bool(data.get("fingerprint", {}).get("logprobs_signature")),
                            "tokenizer_family": data.get("fingerprint", {}).get("tokenizer_family_guess", ""),
                            "file": str(p),
                        }
                    )
            except Exception:
                continue
        items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return items

    def load_all_full(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("id"):
                    out.append(data)
            except Exception:
                continue
        return out

    def get(self, baseline_id: str) -> dict[str, Any] | None:
        for data in self.load_all_full():
            if data.get("id") == baseline_id:
                return data
        return None

    def save_from_report(
        self,
        report_dict: dict[str, Any],
        name: str,
        notes: str = "",
    ) -> dict[str, Any]:
        bid = f"bl_{uuid.uuid4().hex[:10]}"
        cfg = report_dict.get("config") or {}
        fp = report_dict.get("fingerprint") or {}
        payload = {
            "schema_version": 1,
            "id": bid,
            "name": name.strip() or f"{cfg.get('model', 'model')} Official",
            "model": cfg.get("model", ""),
            "protocol": (report_dict.get("verdict") or {}).get("detected_protocol", cfg.get("protocol", "")),
            "notes": notes.strip(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "fingerprint": {
                "task_count": fp.get("task_count", 0),
                "samples_per_task": fp.get("samples_per_task", 0),
                "total_samples": fp.get("total_samples", 0),
                "distributions": fp.get("distributions") or {},
                "logprobs_signature": fp.get("logprobs_signature") or [],
                "tokenizer_vector": fp.get("tokenizer_vector") or {},
                "tokenizer_family_guess": fp.get("tokenizer_family_guess", ""),
            },
            "iq_reference": {
                "total_score": (report_dict.get("iq") or {}).get("total_score"),
                "tier": (report_dict.get("iq") or {}).get("tier"),
            },
        }
        fname = f"{_safe_slug(payload['name'])}_{bid}.json"
        target = self.dir / fname
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return payload

    def import_json(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw_data, dict) or "fingerprint" not in raw_data:
            raise ValueError("无效的基线 JSON 格式：缺少 fingerprint 字段")
        data = dict(raw_data)
        if not data.get("id"):
            data["id"] = f"bl_{uuid.uuid4().hex[:10]}"
        if not data.get("name"):
            data["name"] = data.get("model", "Imported Baseline")
        if not data.get("created_at"):
            data["created_at"] = datetime.now(timezone.utc).isoformat()
        fname = f"{_safe_slug(data['name'])}_{data['id']}.json"
        (self.dir / fname).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return data

    def delete(self, baseline_id: str) -> bool:
        for p in self.dir.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("id") == baseline_id:
                    os.remove(p)
                    return True
            except Exception:
                continue
        return False

    def match_against_all(
        self,
        distributions: dict[str, dict[str, int]],
        tokenizer_vector: dict[str, Any],
        logprobs_sig: list[dict[str, Any]],
        focus_id: str | None = None,
    ) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for bl in self.load_all_full():
            if focus_id and bl.get("id") != focus_id:
                continue
            bfp = bl.get("fingerprint") or {}
            mean_jsd, per_task = compare_distributions(distributions, bfp.get("distributions") or {})
            tok_l1 = compare_tokenizer_vectors(tokenizer_vector, bfp.get("tokenizer_vector") or {})
            lp_cmp = compare_logprobs_signatures(logprobs_sig, bfp.get("logprobs_signature") or [])

            # Combined verdict label for this baseline comparison
            verdict = "INCONCLUSIVE"
            if mean_jsd is not None:
                if mean_jsd <= 0.14 and (tok_l1 is None or tok_l1 <= 0.08):
                    verdict = "MATCH_STRONG"
                elif mean_jsd <= 0.26 and (tok_l1 is None or tok_l1 <= 0.15):
                    verdict = "MATCH_SIMILAR"
                else:
                    verdict = "MISMATCH"
                if lp_cmp and lp_cmp.get("top1_match_rate", 0) >= 0.95 and (lp_cmp.get("mean_logprob_l1") or 9) <= 0.08:
                    verdict = "MATCH_STRONG"
                elif lp_cmp and lp_cmp.get("top1_match_rate", 0) < 0.5:
                    verdict = "MISMATCH"

            matches.append(
                {
                    "baseline_id": bl.get("id"),
                    "baseline_name": bl.get("name"),
                    "baseline_model": bl.get("model"),
                    "mean_jsd": mean_jsd,
                    "per_task_jsd": per_task,
                    "tokenizer_l1": tok_l1,
                    "logprobs_compare": lp_cmp,
                    "verdict": verdict,
                }
            )

        matches.sort(key=lambda m: m["mean_jsd"] if m["mean_jsd"] is not None else 9.99)
        return matches
