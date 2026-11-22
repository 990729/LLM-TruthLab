"""L2 Statistical Behavioral Fingerprinting & Mixture-Router Detection.

Implements:
1. Single-Token Output Distribution Fingerprinting (arXiv:2607.10252 style)
   with Jensen-Shannon Divergence against saved official baselines.
2. Split-Half temporal drift & Temperature=0 determinism check (catches
   round-robin / probabilistic mixture relays).
3. Exact Top-K Logprobs signature extraction (when exposed by endpoint).
4. Low-weight indirect persona / refusal-style clue (explicitly marked non-conclusive).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from .baselines import BaselineStore, jensen_shannon_divergence
from .client import RelayClient
from .models import AuditConfig, EvidenceItem, FingerprintSummary

ProgressCb = Callable[[str, str], None]


_SINGLE_TOKEN_TASKS: list[dict[str, Any]] = [
    {
        "id": "rand_num_en",
        "label": "英文随机数 (1-100)",
        "prompt": "Pick a random integer between 1 and 100. Reply with ONLY the digits, nothing else.",
        "kind": "int",
    },
    {
        "id": "rand_num_zh",
        "label": "中文随机数 (1-100)",
        "prompt": "请从1到100之间随机选一个整数。只输出数字本身，不要任何标点或解释。",
        "kind": "int",
    },
    {
        "id": "color_en",
        "label": "英文直觉颜色",
        "prompt": "Name the first color that comes to mind. Reply with ONLY one single English word.",
        "kind": "word_en",
    },
    {
        "id": "letter_en",
        "label": "随机字母 (A-Z)",
        "prompt": "Pick a random uppercase English letter from A to Z. Reply with ONLY that single letter.",
        "kind": "letter",
    },
    {
        "id": "prime_en",
        "label": "随机两位质数",
        "prompt": "Pick a random prime number between 10 and 99. Reply with ONLY the digits.",
        "kind": "int",
    },
    {
        "id": "coin_en",
        "label": "抛硬币先验",
        "prompt": "Flip a fair coin in your head. Reply with ONLY one word: Heads or Tails.",
        "kind": "word_en",
    },
    {
        "id": "rps_en",
        "label": "石头剪刀布先验",
        "prompt": "Play one round of Rock Paper Scissors. Reply with ONLY one word: Rock, Paper, or Scissors.",
        "kind": "word_en",
    },
    {
        "id": "animal_zh",
        "label": "中文直觉动物",
        "prompt": "凭直觉说出一种常见动物的名称，只输出这个动物名（1到2个汉字），不要标点。",
        "kind": "zh",
    },
]

_LOGPROB_PROBES: list[dict[str, str]] = [
    {
        "id": "lp_science",
        "prompt": "Complete the next four words only: The speed of light in vacuum is approximately",
    },
    {
        "id": "lp_narrative",
        "prompt": "Complete the next four words only: Once upon a stormy winter midnight, the old lighthouse keeper",
    },
]


_STEALTH_PROMPT_VARIANTS: dict[str, list[str]] = {
    "rand_num_en": [
        "Choose a whole number from 1 to 100 at random. Output just the number.",
        "Give me one random integer in [1, 100]. Digits only, no extra characters.",
        "Think of an arbitrary integer between 1 and 100 and reply with only the number.",
    ],
    "rand_num_zh": [
        "随意想一个 1 到 100 的整数，只回复阿拉伯数字。",
        "在 1~100 之间任选一个整数，直接输出该数字，勿加其他文字。",
    ],
    "color_en": [
        "Say the very first color word you think of. One single English word only.",
        "Pick any single color name spontaneously. Reply with just that one word.",
    ],
    "letter_en": [
        "Select any single capital English letter A through Z. Output only that character.",
        "Give one random uppercase letter (A-Z). Reply with just the single letter.",
    ],
    "prime_en": [
        "Choose any two-digit prime number (10-99). Reply with digits only.",
        "Name a random prime integer between 10 and 99. Output only the number.",
    ],
    "coin_en": [
        "Simulate one coin toss and reply with only Heads or Tails.",
        "Pick Heads or Tails at random. Output just that single word.",
    ],
    "rps_en": [
        "Choose Rock, Paper, or Scissors for one game. Reply with just that word.",
        "Output one random choice from: Rock, Paper, Scissors. One word only.",
    ],
    "animal_zh": [
        "随口说一种常见动物的名字，只需1到2个汉字，不加标点。",
        "直接输出你脑中第一个浮现的动物名称（1-2字），不要解释。",
    ],
}


def _normalize_single_token_answer(raw: str, kind: str) -> str:
    s = (raw or "").strip()
    # Strip any accidental <think>...</think> blocks
    s = re.sub(r"<think>.*?</think>", "", s, flags=re.S | re.I).strip()
    if not s:
        return "<EMPTY>"
    if kind == "int":
        m = re.search(r"\b\d{1,3}\b", s)
        return m.group(0) if m else s[:12].lower()
    if kind == "letter":
        m = re.search(r"[A-Za-z]", s)
        return m.group(0).upper() if m else s[:6].upper()
    if kind == "word_en":
        m = re.search(r"[A-Za-z]+", s)
        return m.group(0).lower() if m else s[:16].lower()
    if kind == "zh":
        m = re.search(r"[\u4e00-\u9fff]{1,4}", s)
        return m.group(0) if m else s[:12]
    return s[:16].lower()


def _shannon_entropy(counts: dict[str, int]) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            ent -= p * math.log2(p)
    return round(ent, 3)


def _text_similarity(a: str, b: str) -> float:
    sa = set(re.findall(r"[a-zA-Z0-9\u4e00-\u9fff]+", a.lower()))
    sb = set(re.findall(r"[a-zA-Z0-9\u4e00-\u9fff]+", b.lower()))
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def run_fingerprint_probes(
    client: RelayClient,
    config: AuditConfig,
    tokenizer_vector: dict[str, Any],
    tokenizer_family: str,
    baseline_store: BaselineStore,
    emit: ProgressCb | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[list[EvidenceItem], FingerprintSummary]:
    """Run L2 behavioral fingerprinting, logprobs, T=0 consistency & baseline matching."""
    evidences: list[EvidenceItem] = []

    def notify(step: str, msg: str) -> None:
        if emit:
            emit(step, msg)

    mode_cfg = {
        "quick": (5, 6),      # 30 ultra-cheap calls
        "standard": (8, 12),  # 96 calls
        "deep": (8, 24),      # 192 calls
    }
    n_tasks, n_samples = mode_cfg.get(config.mode, (8, 12))
    tasks = _SINGLE_TOKEN_TASKS[:n_tasks]

    # ------------------------------------------------------------------
    # 1. Single-Token Output Distribution Sampling (One Token Is Enough)
    # ------------------------------------------------------------------
    total_calls = n_tasks * n_samples
    notify("fp_sampling", f"采集单 Token 行为分布指纹（{n_tasks} 任务 × {n_samples} 次 = {total_calls} 次极短采样）...")

    # Preserve chronological order per task for split-half mixture detection
    task_sequences: dict[str, list[str]] = {t["id"]: [""] * n_samples for t in tasks}
    jobs: list[tuple[dict[str, Any], int]] = []
    for sample_idx in range(n_samples):
        for t in tasks:
            jobs.append((t, sample_idx))

    completed = 0
    max_workers = max(1, min(config.max_concurrency, 8))

    def _run_one(task: dict[str, Any], sidx: int) -> tuple[str, int, str]:
        if cancel_check and cancel_check():
            return task["id"], sidx, ""
        prompt_text = task["prompt"]
        if config.stealth_mode:
            variants = _STEALTH_PROMPT_VARIANTS.get(task["id"])
            if variants:
                prompt_text = variants[sidx % len(variants)]
        res = client.chat(
            messages=[{"role": "user", "content": prompt_text}],
            max_tokens=20,
            temperature=1.0,
        )
        if not res.ok:
            return task["id"], sidx, ""
        return task["id"], sidx, _normalize_single_token_answer(res.text, task["kind"])

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = [pool.submit(_run_one, t, sidx) for t, sidx in jobs]
        for fut in as_completed(futs):
            if cancel_check and cancel_check():
                break
            tid, sidx, ans = fut.result()
            if ans:
                task_sequences[tid][sidx] = ans
            completed += 1
            if completed % max(1, total_calls // 6) == 0 or completed == total_calls:
                notify("fp_sampling", f"单 Token 指纹采样进度：{completed}/{total_calls}")

    distributions: dict[str, dict[str, int]] = {}
    valid_samples_total = 0
    split_half_jsds: list[float] = []
    family_clues: list[str] = []

    for t in tasks:
        seq = [x for x in task_sequences[t["id"]] if x and x != "<EMPTY>"]
        counts = dict(Counter(seq).most_common())
        distributions[t["id"]] = counts
        valid_samples_total += len(seq)
        if len(seq) >= 6:
            mid = len(seq) // 2
            h1 = dict(Counter(seq[:mid]))
            h2 = dict(Counter(seq[mid:]))
            split_half_jsds.append(jensen_shannon_divergence(h1, h2))

    split_half_jsd = round(sum(split_half_jsds) / len(split_half_jsds), 4) if split_half_jsds else None

    # Extract readable statistical bias clues (clearly presented as empirical distribution observations)
    if distributions.get("rand_num_en"):
        top_en = list(distributions["rand_num_en"].items())[:3]
        ent_en = _shannon_entropy(distributions["rand_num_en"])
        family_clues.append(
            f"英文随机数(1-100) Top 偏好: {', '.join(f'{k}({v}次)' for k, v in top_en)} | 熵={ent_en} bits"
        )
    if distributions.get("color_en"):
        top_c = list(distributions["color_en"].items())[:3]
        family_clues.append(
            f"直觉颜色偏好: {', '.join(f'{k}({v}次)' for k, v in top_c)}"
        )
    if distributions.get("letter_en"):
        top_l = list(distributions["letter_en"].items())[:3]
        family_clues.append(
            f"随机字母偏好: {', '.join(f'{k}({v}次)' for k, v in top_l)}"
        )
    if distributions.get("rand_num_zh"):
        top_zh = list(distributions["rand_num_zh"].items())[:3]
        family_clues.append(
            f"中文随机数 Top 偏好: {', '.join(f'{k}({v}次)' for k, v in top_zh)}"
        )

    # ------------------------------------------------------------------
    # 2. Temperature=0 Determinism & Mixture-Router Consistency Probe
    # ------------------------------------------------------------------
    notify("fp_consistency", "执行 T=0 确定性复现与多上游混流漂移检测...")
    t0_prompt = (
        "Generate exactly 4 distinct 3-word codenames for deep-sea submarines, "
        "separated by semicolons. No numbering, no extra text."
    )
    t0_outputs: list[str] = []
    t0_fps: list[str] = []
    for _ in range(3):
        r = client.chat(
            messages=[{"role": "user", "content": t0_prompt}],
            max_tokens=64,
            temperature=0.0,
            seed=42,
        )
        if r.ok and r.text.strip():
            t0_outputs.append(r.text.strip())
            if r.system_fingerprint:
                t0_fps.append(r.system_fingerprint)

    t0_consistency: float | None = None
    if len(t0_outputs) >= 2:
        sims = []
        for i in range(len(t0_outputs)):
            for j in range(i + 1, len(t0_outputs)):
                sims.append(_text_similarity(t0_outputs[i], t0_outputs[j]))
        t0_consistency = round(sum(sims) / len(sims), 4)
        unique_fps = set(t0_fps)
        # Note: Even official APIs can have minor MoE non-determinism, so flag only stark divergence (<0.40)
        if len(unique_fps) > 1:
            evidences.append(
                EvidenceItem(
                    id="fp_mixture_drift",
                    layer="L4_CONSISTENCY",
                    title="T=0 确定性与动态混流路由检测",
                    status="WARN",
                    severity="HIGH",
                    summary=(
                        f"连续 3 次请求返回了 {len(unique_fps)} 个不同的 `system_fingerprint` ({', '.join(sorted(unique_fps))})，"
                        f"T=0 文本一致性 {t0_consistency*100:.1f}%，存在多后端轮询/混流迹象！"
                    ),
                    details={
                        "t0_consistency": t0_consistency,
                        "system_fingerprints": sorted(unique_fps),
                        "outputs": t0_outputs,
                        "split_half_jsd": split_half_jsd,
                    },
                    score_impact=-15,
                )
            )
        elif t0_consistency < 0.38:
            evidences.append(
                EvidenceItem(
                    id="fp_mixture_drift",
                    layer="L4_CONSISTENCY",
                    title="T=0 确定性与动态混流路由检测",
                    status="WARN",
                    severity="MEDIUM",
                    summary=(
                        f"在 `temperature=0, seed=42` 条件下 3 次重复输出相似度仅 {t0_consistency*100:.1f}%（极低）！"
                        "可能是中转站忽略了 temperature 参数、暗中改写参数，或在多个不同底层模型之间混流路由。"
                    ),
                    details={
                        "t0_consistency": t0_consistency,
                        "outputs": t0_outputs,
                        "split_half_jsd": split_half_jsd,
                    },
                    score_impact=-12,
                )
            )
        else:
            evidences.append(
                EvidenceItem(
                    id="fp_mixture_drift",
                    layer="L4_CONSISTENCY",
                    title="T=0 确定性与动态混流路由检测",
                    status="PASS",
                    severity="INFO",
                    summary=(
                        f"T=0 重复输出一致性 {t0_consistency*100:.1f}%"
                        + (f"，前半/后半分布内部 JSD={split_half_jsd:.3f}" if split_half_jsd is not None else "")
                        + "，未观测到明显短时多模型混流切换。"
                    ),
                    details={
                        "t0_consistency": t0_consistency,
                        "outputs": t0_outputs,
                        "split_half_jsd": split_half_jsd,
                    },
                    score_impact=5,
                )
            )

    # ------------------------------------------------------------------
    # 3. Exact Logprobs Signature Probe (OpenAI-compatible endpoints)
    # ------------------------------------------------------------------
    logprobs_sig: list[dict[str, Any]] = []
    logprobs_supported = False
    if client.protocol == "openai_chat":
        notify("fp_logprobs", "探测 Top-K Logprobs 精确概率分布指纹...")
        for lp_probe in _LOGPROB_PROBES:
            r = client.chat(
                messages=[{"role": "user", "content": lp_probe["prompt"]}],
                max_tokens=5,
                temperature=0.0,
                seed=42,
                logprobs=True,
                top_logprobs=5,
            )
            if r.ok and r.logprobs:
                logprobs_supported = True
                compact_tokens = []
                for pos in r.logprobs[:5]:
                    top_list = [
                        {"token": x.get("token", ""), "logprob": round(float(x.get("logprob", 0.0)), 4)}
                        for x in (pos.get("top_logprobs") or [])[:5]
                    ]
                    compact_tokens.append(
                        {
                            "token": pos.get("token", ""),
                            "logprob": round(float(pos.get("logprob", 0.0)), 4),
                            "top": top_list,
                        }
                    )
                logprobs_sig.append({"prompt_id": lp_probe["id"], "tokens": compact_tokens})

        evidences.append(
            EvidenceItem(
                id="fp_logprobs_extract",
                layer="L2_FINGERPRINT",
                title="Logprobs 底层概率指纹提取",
                status="PASS" if logprobs_supported else "INFO",
                severity="INFO",
                summary=(
                    f"成功提取 {len(logprobs_sig)} 组 Top-5 Logprobs 精确对数概率指纹（与官方基线比对可揪出微调/量化替换）。"
                    if logprobs_supported
                    else "端点未返回 `logprobs`（部分推理模型/Claude/中转站关闭此字段），已自动切换为无 Logprobs 单 Token JSD 分布指纹。"
                ),
                details={"logprobs_supported": logprobs_supported, "signature": logprobs_sig},
                score_impact=4 if logprobs_supported else 0,
            )
        )

    # ------------------------------------------------------------------
    # 4. Match Against Saved Official Baselines (Exact JSD + Tokenizer + Logprobs)
    # ------------------------------------------------------------------
    notify("fp_baseline_match", "与本地已录官方基线指纹库执行 JSD 散度比对...")
    baseline_matches = baseline_store.match_against_all(
        distributions=distributions,
        tokenizer_vector=tokenizer_vector,
        logprobs_sig=logprobs_sig,
        focus_id=config.compare_baseline_id or None,
    )

    if baseline_matches:
        best = baseline_matches[0]
        b_verdict = best["verdict"]
        jsd_val = best["mean_jsd"]
        if b_verdict == "MATCH_STRONG":
            evidences.append(
                EvidenceItem(
                    id="fp_baseline_comparison",
                    layer="L2_FINGERPRINT",
                    title="官方基线指纹库 JSD 散度比对",
                    status="PASS",
                    severity="CRITICAL",
                    summary=(
                        f"高度匹配本地基线 `{best['baseline_name']}` ({best['baseline_model']})！"
                        f"平均 JSD = {jsd_val:.4f}（越接近 0 越同源），词表偏差 = {best['tokenizer_l1']}。"
                    ),
                    details={"best_match": best, "all_matches": baseline_matches[:5]},
                    score_impact=26,
                )
            )
        elif b_verdict == "MATCH_SIMILAR":
            evidences.append(
                EvidenceItem(
                    id="fp_baseline_comparison",
                    layer="L2_FINGERPRINT",
                    title="官方基线指纹库 JSD 散度比对",
                    status="WARN",
                    severity="MEDIUM",
                    summary=(
                        f"与最近基线 `{best['baseline_name']}` 存在一定偏移 (JSD = {jsd_val:.4f})，"
                        "可能是同系不同版本、采样量较小导致的统计波动，或存在量化/轻度混流（建议深度模式复测）。"
                    ),
                    details={"best_match": best, "all_matches": baseline_matches[:5]},
                    score_impact=2,
                )
            )
        else:
            evidences.append(
                EvidenceItem(
                    id="fp_baseline_comparison",
                    layer="L2_FINGERPRINT",
                    title="官方基线指纹库 JSD 散度比对",
                    status="FAIL",
                    severity="CRITICAL",
                    summary=(
                        f"与选定/本地基线 `{best['baseline_name']}` 分布显著不符！"
                        f"平均 JSD = {jsd_val:.4f}，词表偏差 = {best['tokenizer_l1']}，高度疑似非同一底层模型！"
                    ),
                    details={"best_match": best, "all_matches": baseline_matches[:5]},
                    score_impact=-32,
                )
            )
    else:
        evidences.append(
            EvidenceItem(
                id="fp_single_token_profile",
                layer="L2_FINGERPRINT",
                title="单 Token 行为分布指纹采集（One-Token JSD）",
                status="INFO",
                severity="INFO",
                summary=(
                    f"已完成 {valid_samples_total} 次单 Token 行为分布采样（本地尚无已录官方基线可作比对）。"
                    "提示：用官方/可信渠道跑一次并点击「录为官方基线」，即可对任何中转站做精确 JSD 验真！"
                ),
                details={
                    "valid_samples": valid_samples_total,
                    "family_clues": family_clues,
                    "distributions": distributions,
                },
                score_impact=0,
            )
        )

    fp_summary = FingerprintSummary(
        task_count=len(tasks),
        samples_per_task=n_samples,
        total_samples=valid_samples_total,
        distributions=distributions,
        split_half_jsd=split_half_jsd,
        t0_consistency_rate=t0_consistency,
        logprobs_supported=logprobs_supported,
        logprobs_signature=logprobs_sig,
        baseline_matches=baseline_matches,
        family_clues=family_clues,
        tokenizer_vector=tokenizer_vector,
        tokenizer_family_guess=tokenizer_family,
    )
    return evidences, fp_summary
