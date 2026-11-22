"""Zero-Trust Verdict Arbiter & Self-Contained HTML Report Generator.

Core principle: Skeptical by default ("不相信直到有证据"). Never certifies a
relay as authentic based on self-reported strings; requires cryptographic proof
or official-baseline JSD/logprobs verification for VERIFIED_STRONG.
"""

from __future__ import annotations

import html
import json
from typing import Any

from .models import (
    AuditReport,
    EvidenceItem,
    FingerprintSummary,
    IQSummary,
    VerdictSummary,
)


def synthesize_verdict(
    *,
    detected_protocol: str,
    model: str,
    evidences: list[EvidenceItem],
    engine_clues: list[str],
    fingerprint: FingerprintSummary,
    iq: IQSummary | None,
    attribution: dict[str, Any] | None = None,
) -> VerdictSummary:
    """Arbitrate zero-trust authenticity verdict from all collected evidence layers."""
    # Start skeptical at 50 (unproven), adjust only by evidence impact
    trust = 50
    strong_proofs: list[str] = []
    anomalies: list[str] = []
    recommendations: list[str] = []

    critical_fails = 0
    high_fails = 0
    medium_warns = 0
    has_crypto_proof = False
    has_baseline_strong_match = False

    for ev in evidences:
        trust += ev.score_impact
        if ev.id in ("crypto_thinking_signature", "crypto_openai_encrypted_reasoning") and ev.status == "PASS":
            has_crypto_proof = True
            strong_proofs.append(f"[密码学铁证] {ev.summary}")
        elif ev.id == "crypto_gemini_thought" and ev.status == "PASS" and (ev.details or {}).get("has_thought_signature"):
            has_crypto_proof = True
            strong_proofs.append(f"[密码学铁证] {ev.summary}")
        elif ev.id == "fp_baseline_comparison" and ev.status == "PASS":
            has_baseline_strong_match = True
            strong_proofs.append(f"[官方基线匹配] {ev.summary}")
        elif ev.status == "PASS" and ev.score_impact >= 6:
            strong_proofs.append(f"[{ev.layer}] {ev.title}: {ev.summary}")

        if ev.status == "FAIL":
            anomalies.append(f"[{ev.severity}] {ev.title}: {ev.summary}")
            if ev.severity == "CRITICAL":
                critical_fails += 1
            elif ev.severity == "HIGH":
                high_fails += 1
            else:
                medium_warns += 1
        elif ev.status == "WARN":
            anomalies.append(f"[异常提示] {ev.title}: {ev.summary}")
            if ev.severity in ("CRITICAL", "HIGH"):
                high_fails += 1
            else:
                medium_warns += 1

    # Cap trust score cleanly
    if critical_fails > 0:
        trust = min(trust, 30)
    elif high_fails >= 2:
        trust = min(trust, 42)
    elif not (has_crypto_proof or has_baseline_strong_match):
        # Zero-trust rule: without cryptographic proof OR official baseline JSD match,
        # trust score cannot claim near-100% certainty!
        trust = min(trust, 78)

    trust = max(0, min(100, int(round(trust))))

    # Determine final authenticity code
    if critical_fails >= 1 or high_fails >= 2 or (anomalies and trust < 38):
        code = "LIKELY_FAKE_OR_WATERED"
        label = "高危避坑 · 高度疑似掺水 / 换模"
        confidence = "HIGH" if (critical_fails >= 1 or high_fails >= 2) else "MEDIUM"
        headline = (
            f"抓到 {critical_fails} 项硬破绽、{high_fails} 项高危异常，这个中转接口很可能有掺水、偷偷换便宜模型或假账单行为，不建议充大钱。"
        )
    elif high_fails == 1 or medium_warns >= 2 or (medium_warns == 1 and trust < 52):
        code = "SUSPICIOUS"
        label = "有点异常 · 疑似混流或改写"
        confidence = "MEDIUM"
        headline = (
            "没抓到彻底造假的实锤，但发现了一些明显异常（比如偶尔混流切模、卡顿抖动大、或实测智商偏低），建议先小额试用。"
        )
    elif has_crypto_proof or has_baseline_strong_match:
        code = "VERIFIED_STRONG"
        label = "硬核验真 · 确认真源"
        confidence = "HIGH"
        proof_kind = (
            "官方加密签名验真 + 官方指纹比对"
            if (has_crypto_proof and has_baseline_strong_match)
            else ("官方加密签名验真" if has_crypto_proof else "官方行为指纹比对")
        )
        headline = (
            f"已拿到「{proof_kind}」硬证据，且拆字习惯、接口行为和实测智商全部正常，可以放心用！"
        )
    else:
        code = "CONSISTENT_UNPROVEN"
        label = "表现正常 · 未见造假"
        confidence = "MEDIUM"
        headline = (
            "拆字习惯、接口表现和实测智商都挺正常，没查出掺水或换模破绽（按严格规则，没对比官方指纹库前最高给 78 分，日常可放心试用）。"
        )

    # Actionable recommendations
    if not has_baseline_strong_match and not fingerprint.baseline_matches:
        recommendations.append(
            "【强推荐】用任意官方/绝对可信渠道跑一次本工具并点击「录为官方基线」，之后只需几分钱即可用 JSD 分布散度精准抓出任何同系/跨系替换！"
        )
    if "claude" in model.lower() and detected_protocol != "anthropic":
        recommendations.append(
            "当前通过 OpenAI 兼容协议测 Claude，会丢失 Anthropic 原生 Thinking Signature 密码学验签；如中转站支持 `/v1/messages`，强烈建议切换为 Anthropic 协议复测！"
        )
    if code in ("LIKELY_FAKE_OR_WATERED", "SUSPICIOUS"):
        recommendations.append(
            "建议切换至「深度模式」并固定同一 IQ Seed 复测 2 次，排查中转站是否存在“短请求真源 + 长请求/高峰期混流掺假”的动态路由策略。"
        )
    if iq and iq.claimed_tier_mismatch:
        recommendations.append(
            "实测动态智商显著低于宣称档位，建议检查该中转站是否暗中压低了 reasoning_effort / thinking budget 或用便宜轻量版模型替代。"
        )
    if attribution and attribution.get("family_conflict"):
        top_sus = attribution.get("top_suspect") or {}
        anomalies.append(
            f"[底层归因冲突] 请求 `{model}`，但多维硬特征最指向「{top_sus.get('family_label')}」(相对置信度 {top_sus.get('confidence_pct')}%)。"
        )
        recommendations.append(
            "可使用「A/B 同台对决」将本端点与官方或该中转站的便宜模型做直接 JSD 散度比对，锁定是否为改名套娃。"
        )

    all_clues = list(dict.fromkeys(engine_clues + fingerprint.family_clues[:2]))

    return VerdictSummary(
        authenticity_code=code,
        authenticity_label=label,
        trust_score=trust,
        confidence=confidence,
        headline=headline,
        detected_protocol=detected_protocol,
        detected_engine_clues=all_clues,
        detected_tokenizer_family=fingerprint.tokenizer_family_guess,
        suspected_anomalies=anomalies,
        strong_proofs=strong_proofs,
        recommendations=recommendations,
    )


def anonymize_report_dict(rep: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy report dict and mask custom relay domain names for safe public sharing."""
    import copy
    import re

    out = copy.deepcopy(rep)
    raw_url = str((out.get("config") or {}).get("base_url") or "")
    m = re.match(r"^(https?://)([^/]+)(.*)$", raw_url)
    host = m.group(2) if m else ""
    if out.get("config") is not None:
        out["config"]["base_url"] = f"{m.group(1)}relay-masked.example{m.group(3)}" if m else "https://relay-masked.example"
        out["config"]["anonymize_domain"] = True

    if host and len(host) >= 4:
        def _scrub(obj: Any) -> Any:
            if isinstance(obj, str):
                return obj.replace(host, "relay-masked.example")
            if isinstance(obj, list):
                return [_scrub(x) for x in obj]
            if isinstance(obj, dict):
                return {k: _scrub(v) for k, v in obj.items()}
            return obj

        out["verdict"] = _scrub(out.get("verdict"))
        out["evidences"] = _scrub(out.get("evidences"))
    return out


def render_html_report(report: AuditReport | dict[str, Any], *, anonymize_domain: bool = False) -> str:
    """Export a completely self-contained, offline-readable HTML forensic report."""
    d = report.to_dict() if isinstance(report, AuditReport) else dict(report)
    if anonymize_domain or (d.get("config") or {}).get("anonymize_domain"):
        d = anonymize_report_dict(d)
    v = d["verdict"]
    cfg = d["config"]
    iq = d.get("iq")
    fp = d.get("fingerprint") or {}
    tel = d.get("telemetry") or {}
    attr = d.get("attribution") or {}
    cliff = d.get("context_cliff")

    badge_colors = {
        "VERIFIED_STRONG": ("#10b981", "rgba(16,185,129,0.14)"),
        "CONSISTENT_UNPROVEN": ("#38bdf8", "rgba(56,189,248,0.14)"),
        "SUSPICIOUS": ("#f59e0b", "rgba(245,158,11,0.14)"),
        "LIKELY_FAKE_OR_WATERED": ("#ef4444", "rgba(239,68,68,0.14)"),
        "ERROR": ("#ef4444", "rgba(239,68,68,0.14)"),
    }
    fg, bg = badge_colors.get(v["authenticity_code"], ("#94a3b8", "rgba(148,163,184,0.14)"))

    def esc(x: Any) -> str:
        return html.escape(str(x if x is not None else ""))

    ev_rows = []
    for ev in d.get("evidences") or []:
        st = ev["status"]
        st_color = {
            "PASS": "#10b981",
            "WARN": "#f59e0b",
            "FAIL": "#ef4444",
            "INFO": "#38bdf8",
            "SKIP": "#64748b",
        }.get(st, "#94a3b8")
        details_pretty = esc(json.dumps(ev.get("details") or {}, ensure_ascii=False, indent=2))
        ev_rows.append(
            f"""
            <div class="card ev-card">
              <div class="ev-head">
                <span class="pill" style="color:{st_color};border-color:{st_color}">{esc(st)}</span>
                <span class="layer-tag">{esc(ev['layer'])}</span>
                <strong>{esc(ev['title'])}</strong>
                <span class="impact">分值影响: {ev['score_impact']:+d}</span>
              </div>
              <p class="ev-sum">{esc(ev['summary'])}</p>
              <details>
                <summary>查看原始取证数据</summary>
                <pre>{details_pretty}</pre>
              </details>
            </div>
            """
        )

    iq_html = ""
    if iq:
        dim_bars = []
        for dk, dv in (iq.get("dimension_scores") or {}).items():
            pct = float(dv.get("score_pct", 0))
            dim_bars.append(
                f"""
                <div class="dim-row">
                  <div class="dim-label">{esc(dv.get('label', dk))} ({dv.get('passed')}/{dv.get('count')} 题)</div>
                  <div class="bar-bg"><div class="bar-fill" style="width:{pct:.1f}%"></div></div>
                  <div class="dim-val">{pct:.1f}%</div>
                </div>
                """
            )
        q_rows = []
        for q in iq.get("questions") or []:
            q_col = "#10b981" if q["passed"] else "#ef4444"
            q_rows.append(
                f"""
                <tr>
                  <td><span class="pill" style="color:{q_col};border-color:{q_col}">{'PASS' if q['passed'] else 'FAIL'}</span></td>
                  <td>{esc(q['dimension_label'])}</td>
                  <td>{esc(q['title'])}</td>
                  <td>{q['score']}/{q['max_score']}</td>
                  <td>{q['latency_ms']}ms</td>
                  <td>{esc(q['grading_notes'])}</td>
                </tr>
                """
            )
        iq_html = f"""
        <h2>四、反污染动态智商测评 (Seed: {esc(iq.get('seed'))})</h2>
        <div class="card">
          <div class="iq-hero">
            <div><div class="big">{esc(iq.get('total_score'))}<span class="unit">/100</span></div><div class="sub">综合智商得分</div></div>
            <div><div class="big">{esc(iq.get('iq_index'))}</div><div class="sub">等效智商指数</div></div>
            <div><div class="big">{esc(iq.get('tier'))} 级</div><div class="sub">{esc(iq.get('tier_label'))}</div></div>
          </div>
          <div class="dims">{''.join(dim_bars)}</div>
          <table>
            <thead><tr><th>结果</th><th>维度</th><th>题目</th><th>得分</th><th>耗时</th><th>判分说明</th></tr></thead>
            <tbody>{''.join(q_rows)}</tbody>
          </table>
        </div>
        """

    dist_blocks = []
    for tid, counts in (fp.get("distributions") or {}).items():
        top_items = ", ".join(f"{k}: {c}" for k, c in list(counts.items())[:8])
        dist_blocks.append(f"<li><code>{esc(tid)}</code> → {esc(top_items)}</li>")

    attr_html = ""
    cands = attr.get("candidates") or []
    if cands:
        attr_rows = []
        for c in cands[:6]:
            pct = float(c.get("confidence_pct", 0))
            rs = "；".join(c.get("reasons") or [])
            attr_rows.append(
                f"<tr><td><strong>{esc(c.get('family_label'))}</strong></td>"
                f"<td><strong>{pct:.1f}%</strong></td><td>{esc(rs)}</td></tr>"
            )
        attr_html = f"""
        <h2>五、底层真实模型家族归因推演</h2>
        <div class="card">
          <table>
            <thead><tr><th>候选家族</th><th>相对置信度</th><th>支撑证据</th></tr></thead>
            <tbody>{''.join(attr_rows)}</tbody>
          </table>
          <p class="sub" style="margin-top:8px;">{esc(attr.get('note', ''))}</p>
        </div>
        """

    cliff_html = ""
    if cliff and cliff.get("rows"):
        c_rows = []
        for r in cliff["rows"]:
            cell = lambda ok: '<span style="color:#10b981;font-weight:700;">PASS</span>' if ok else '<span style="color:#ef4444;font-weight:700;">FAIL</span>'
            c_rows.append(
                f"<tr><td>{esc(r['tier_k'])}K</td><td>{int(r.get('est_tokens', 0)):,}</td>"
                f"<td>{int(r.get('reported_input_tokens', 0)):,}</td>"
                f"<td>{cell(r.get('head_ok'))}</td><td>{cell(r.get('mid_ok'))}</td><td>{cell(r.get('tail_ok'))}</td>"
                f"<td>{esc(r.get('latency_ms'))}ms</td></tr>"
            )
        cliff_html = f"""
        <h2>六、上下文断崖记忆热力表 (最高验证 {esc(cliff.get('max_verified_k'))}K)</h2>
        <div class="card">
          <table>
            <thead><tr><th>档位</th><th>发送估算</th><th>上报输入</th><th>头部(5%)</th><th>中段(50%)</th><th>尾部(95%)</th><th>耗时</th></tr></thead>
            <tbody>{''.join(c_rows)}</tbody>
          </table>
        </div>
        """

    ce = tel.get("cost_estimate") or {}
    nf = tel.get("network_forensics") or {}
    net_cost_html = f"""
    <div class="grid" style="margin-top:10px;">
      <div class="stat"><div class="k">出口边缘节点 / 网关栈</div><div class="v" style="font-size:13.5px;">{esc(nf.get('edge_pop') or '未暴露节点')} · {esc(nf.get('gateway_guess') or '-')}</div></div>
      <div class="stat"><div class="k">延迟 P50 / P95 / P99 (抖动 CV)</div><div class="v" style="font-size:13.5px;">{esc(tel.get('p50_latency_ms', 0))} / {esc(tel.get('p95_latency_ms', 0))} / {esc(tel.get('p99_latency_ms', 0))} ms (CV={esc(tel.get('latency_jitter_cv', '-'))})</div></div>
      <div class="stat"><div class="k">官方公开价折算参考成本</div><div class="v" style="font-size:14px;">${esc(ce.get('estimated_usd', 0))} / ¥{esc(ce.get('estimated_cny', 0))}</div></div>
    </div>
    """ if (ce or nf) else ""

    plain = d.get("plain_summary") or {}
    plain_html = ""
    if plain.get("content"):
        plain_html = f"""
  <div class="card" style="border-color:rgba(244,244,245,0.22);background:#111827;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <strong style="font-size:15px;color:#f8fafc;">大白话体检结论（10 秒看懂）</strong>
      <span class="sub">{esc(plain.get('source_label', ''))}</span>
    </div>
    <div style="white-space:pre-line;font-size:14px;line-height:1.75;color:#e2e8f0;">{esc(plain.get('content', ''))}</div>
  </div>
"""

    mlm = (attr or {}).get("most_likely_model") or {}
    mlm_stat_html = (
        f'<div class="stat"><div class="k">最可能真实模型 (置信度 {esc(mlm.get("confidence_pct", 0))}%)</div>'
        f'<div class="v" style="font-size:15px;color:#38bdf8;">{esc(mlm.get("model_name", "未判定"))}</div></div>'
        if mlm.get("model_name")
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>LLM API 中转站零信任指纹与智商体检报告 - {esc(cfg.get('model'))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; background:#0b1120; color:#e2e8f0; margin:0; padding:28px; line-height:1.6; }}
  .wrap {{ max-width:1080px; margin:0 auto; }}
  h1 {{ margin:0 0 6px; font-size:24px; }}
  h2 {{ margin:26px 0 12px; font-size:18px; color:#93c5fd; border-bottom:1px solid #1e293b; padding-bottom:6px; }}
  .meta {{ color:#94a3b8; font-size:13px; margin-bottom:20px; }}
  .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px; padding:18px; margin-bottom:14px; }}
  .verdict-box {{ border-left:5px solid {fg}; background:{bg}; }}
  .badge {{ display:inline-block; padding:4px 12px; border-radius:999px; font-weight:700; color:{fg}; border:1px solid {fg}; font-size:14px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:12px; margin-top:14px; }}
  .stat {{ background:#0f172a; border:1px solid #1e293b; border-radius:8px; padding:12px; }}
  .stat .k {{ font-size:12px; color:#94a3b8; }}
  .stat .v {{ font-size:18px; font-weight:700; margin-top:4px; }}
  .ev-head {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .pill {{ display:inline-block; padding:2px 8px; border-radius:6px; font-size:12px; font-weight:700; border:1px solid; }}
  .layer-tag {{ font-size:11px; color:#94a3b8; background:#1e293b; padding:2px 7px; border-radius:4px; }}
  .impact {{ margin-left:auto; font-size:12px; color:#94a3b8; }}
  .ev-sum {{ margin:10px 0 6px; }}
  pre {{ background:#020617; color:#cbd5e1; padding:12px; border-radius:8px; overflow:auto; font-size:12px; max-height:300px; }}
  details summary {{ cursor:pointer; color:#60a5fa; font-size:12px; }}
  .iq-hero {{ display:flex; gap:36px; flex-wrap:wrap; margin-bottom:18px; }}
  .big {{ font-size:32px; font-weight:800; color:#f8fafc; }}
  .unit {{ font-size:15px; color:#94a3b8; }}
  .sub {{ font-size:12px; color:#94a3b8; }}
  .dim-row {{ display:grid; grid-template-columns:200px 1fr 60px; align-items:center; gap:10px; margin:8px 0; font-size:13px; }}
  .bar-bg {{ height:10px; background:#1e293b; border-radius:999px; overflow:hidden; }}
  .bar-fill {{ height:100%; background:linear-gradient(90deg, #38bdf8, #818cf8); }}
  table {{ width:100%; border-collapse:collapse; margin-top:16px; font-size:13px; }}
  th, td {{ border-bottom:1px solid #1e293b; padding:8px; text-align:left; vertical-align:top; }}
  th {{ color:#94a3b8; font-weight:600; }}
  code {{ background:#1e293b; padding:2px 5px; border-radius:4px; font-size:12px; }}
  ul {{ margin:6px 0; padding-left:20px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>LLM API 中转站零信任指纹与智商体检报告</h1>
  <div class="meta">
    审计编号: <code>{esc(d['audit_id'])}</code> | 目标地址: <code>{esc(cfg.get('base_url'))}</code> |
    请求模型: <code>{esc(cfg.get('model'))}</code> | 协议: <code>{esc(v.get('detected_protocol'))}</code> |
    模式: <code>{esc(cfg.get('mode'))}</code> | 耗时: {esc(d['duration_sec'])}s
  </div>

  <div class="card verdict-box">
    <span class="badge">{esc(v['authenticity_label'])}</span>
    <p style="font-size:15px;margin:10px 0 6px;"><strong>{esc(v['headline'])}</strong></p>
    <div class="grid">
      <div class="stat"><div class="k">零信任可信度分</div><div class="v">{esc(v['trust_score'])} / 100</div></div>
      {mlm_stat_html}
      <div class="stat"><div class="k">推断词表家族</div><div class="v" style="font-size:14px;">{esc(v['detected_tokenizer_family'])}</div></div>
      <div class="stat"><div class="k">总请求 / 成功</div><div class="v">{esc(tel.get('total_requests', 0))} / {esc(tel.get('ok_requests', 0))}</div></div>
      <div class="stat"><div class="k">累计 Token (In / Out)</div><div class="v" style="font-size:15px;">{int(tel.get('input_tokens', 0)):,} / {int(tel.get('output_tokens', 0)):,}</div></div>
    </div>
    {net_cost_html}
  </div>
  {plain_html}
  <h2>一、底层线索与核验建议</h2>
  <div class="card">
    <p><strong>识别到的引擎与分布线索：</strong></p>
    <ul>{''.join(f'<li>{esc(c)}</li>' for c in (v.get('detected_engine_clues') or ['暂无额外底层引擎线索']))}</ul>
    <p><strong>操作建议：</strong></p>
    <ul>{''.join(f'<li>{esc(r)}</li>' for r in (v.get('recommendations') or ['当前无特别补充建议。']))}</ul>
  </div>

  <h2>二、全维度取证证据链</h2>
  {''.join(ev_rows)}

  <h2>三、单 Token 行为分布指纹摘要</h2>
  <div class="card">
    <p>采样总数: <strong>{esc(fp.get('total_samples', 0))}</strong> |
       前半/后半漂移 JSD: <code>{esc(fp.get('split_half_jsd'))}</code> |
       T=0 一致性: <code>{esc(fp.get('t0_consistency_rate'))}</code></p>
    <ul>{''.join(dist_blocks) or '<li>未启用单 Token 指纹采样</li>'}</ul>
  </div>

  {iq_html}
  {attr_html}
  {cliff_html}
</div>
</body>
</html>
"""


def render_arena_html(arena: dict[str, Any]) -> str:
    """Export an offline self-contained HTML report for an A/B Dual-Endpoint Arena duel."""
    c = arena.get("comparison") or {}
    ra = arena.get("report_a") or {}
    rb = arena.get("report_b") or {}

    def esc(x: Any) -> str:
        return html.escape(str(x if x is not None else ""))

    code = c.get("relation_code", "")
    col = "#ef4444" if code in ("ALIAS_FRAUD_DETECTED", "DIFFERENT_MODEL_FRAUD", "INCOMPLETE_ERROR") else (
        "#10b981" if code in ("SAME_UNDERLYING_MODEL", "DISTINCT_MODELS_OK") else "#f59e0b"
    )
    jsd_rows = "".join(
        f"<tr><td><code>{esc(k)}</code></td><td><strong>{float(v):.4f}</strong></td></tr>"
        for k, v in (c.get("per_task_jsd") or {}).items()
    )
    q_rows = "".join(
        f"<tr><td>{esc(q['dimension_label'])}</td><td>{esc(q['title'])}</td>"
        f"<td>{q['score_a']}/{q['max_score']} ({q['latency_a']}ms)</td>"
        f"<td>{q['score_b']}/{q['max_score']} ({q['latency_b']}ms)</td></tr>"
        for q in (c.get("h2h_questions") or [])
    )
    return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"/>
<title>LLM-TruthLab A/B 同台对决报告 - {esc(arena.get('arena_id'))}</title>
<style>
body{{font-family:"Segoe UI","Microsoft YaHei",sans-serif;background:#0b1120;color:#e2e8f0;margin:0;padding:28px;line-height:1.6}}
.wrap{{max-width:1040px;margin:0 auto}}.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:18px;margin-bottom:14px}}
.hero{{border-left:5px solid {col}}}.badge{{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700;color:{col};border:1px solid {col}}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-top:12px}}
.stat{{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:10px}}.k{{font-size:12px;color:#94a3b8}}.v{{font-size:18px;font-weight:700}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{border-bottom:1px solid #1e293b;padding:8px;text-align:left}}th{{color:#94a3b8}}
code{{background:#1e293b;padding:2px 5px;border-radius:4px}}
</style></head><body><div class="wrap">
<h1>LLM-TruthLab A/B 同台对决与别名打假报告</h1>
<p style="color:#94a3b8;font-size:13px;">编号: <code>{esc(arena.get('arena_id'))}</code> | 共享智商 Seed: <code>{esc(arena.get('shared_iq_seed'))}</code> | 耗时: {esc(arena.get('duration_sec'))}s</p>
<div class="card hero">
  <span class="badge">{esc(c.get('relation_label'))}</span>
  <p><strong>{esc(c.get('relation_summary'))}</strong></p>
  <div class="grid">
    <div class="stat"><div class="k">A ↔ B 直接 JSD 散度</div><div class="v" style="color:{col}">{esc(c.get('mean_jsd'))}</div></div>
    <div class="stat"><div class="k">词表偏差 L1</div><div class="v">{esc(c.get('tokenizer_l1'))}</div></div>
    <div class="stat"><div class="k">端点 A ({esc((ra.get('config') or {}).get('model'))})</div><div class="v">智商 {esc(c.get('iq_a'))} / 可信 {esc((ra.get('verdict') or {}).get('trust_score'))}</div></div>
    <div class="stat"><div class="k">端点 B ({esc((rb.get('config') or {}).get('model'))})</div><div class="v">智商 {esc(c.get('iq_b'))} / 可信 {esc((rb.get('verdict') or {}).get('trust_score'))}</div></div>
  </div>
</div>
<div class="card"><h3>分任务单 Token JSD 散度</h3><table><thead><tr><th>任务</th><th>JSD (base-2)</th></tr></thead><tbody>{jsd_rows or '<tr><td colspan="2">无数据</td></tr>'}</tbody></table></div>
<div class="card"><h3>同 Seed 智商逐题对决</h3><table><thead><tr><th>维度</th><th>题目</th><th>端点 A</th><th>端点 B</th></tr></thead><tbody>{q_rows or '<tr><td colspan="4">未开启智商对比</td></tr>'}</tbody></table></div>
</div></body></html>"""


def render_batch_html(batch: dict[str, Any]) -> str:
    """Export an offline self-contained HTML report for a Batch Leaderboard & N×N Matrix."""
    def esc(x: Any) -> str:
        return html.escape(str(x if x is not None else ""))

    alerts = "".join(f"<li>{esc(a)}</li>" for a in (batch.get("alias_alerts") or []))
    lb_rows = "".join(
        f"<tr><td><strong>#{i+1}</strong></td><td><strong>{esc(r['label'])}</strong> ({esc(r['model'])})</td>"
        f"<td>{esc(r['authenticity_label'])}</td><td><strong>{esc(r['composite_score'])}</strong></td>"
        f"<td>{esc(r['trust_score'])}/100</td><td>{esc(r.get('iq_score'))} ({esc(r.get('iq_tier'))})</td>"
        f"<td>{esc(r.get('avg_latency_ms'))}ms</td><td>{esc(r.get('top_suspect'))}</td></tr>"
        for i, r in enumerate(batch.get("leaderboard") or [])
    )
    labels = batch.get("labels") or []
    mat = batch.get("matrix_jsd") or []
    mat_head = "".join(f"<th>{esc(l)}</th>" for l in labels)
    mat_body = ""
    for i, lbl in enumerate(labels):
        cells = ""
        for j in range(len(labels)):
            val = (mat[i] or [])[j] if i < len(mat) else None
            if i == j:
                cells += "<td style='text-align:center;color:#64748b'>—</td>"
            elif val is None:
                cells += "<td style='text-align:center;color:#64748b'>N/A</td>"
            else:
                bg = "rgba(239,68,68,0.22)" if val <= 0.16 else ("rgba(245,158,11,0.16)" if val <= 0.30 else "rgba(16,185,129,0.12)")
                cells += f"<td style='text-align:center;background:{bg}'><strong>{val:.3f}</strong></td>"
        mat_body += f"<tr><td><strong>{esc(lbl)}</strong></td>{cells}</tr>"

    return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"/>
<title>LLM-TruthLab 中转站红黑榜与 N×N 同源矩阵 - {esc(batch.get('batch_id'))}</title>
<style>
body{{font-family:"Segoe UI","Microsoft YaHei",sans-serif;background:#0b1120;color:#e2e8f0;margin:0;padding:28px;line-height:1.6}}
.wrap{{max-width:1120px;margin:0 auto}}.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:18px;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{border-bottom:1px solid #1e293b;padding:8px;text-align:left}}th{{color:#94a3b8}}
code{{background:#1e293b;padding:2px 5px;border-radius:4px}}
</style></head><body><div class="wrap">
<h1>LLM-TruthLab 批量中转站红黑榜与 N×N JSD 同源矩阵</h1>
<p style="color:#94a3b8;font-size:13px;">编号: <code>{esc(batch.get('batch_id'))}</code> | 共享智商 Seed: <code>{esc(batch.get('shared_iq_seed'))}</code> | 耗时: {esc(batch.get('duration_sec'))}s</p>
{f'<div class="card" style="border-left:4px solid #ef4444;background:rgba(239,68,68,0.1);"><h3>🚨 同源/别名套娃预警</h3><ul>{alerts}</ul></div>' if alerts else ''}
<div class="card"><h3>🏆 综合红黑排行榜</h3><table><thead><tr><th>排名</th><th>目标</th><th>结论</th><th>综合分</th><th>可信分</th><th>智商</th><th>平均延迟</th><th>归因首推</th></tr></thead><tbody>{lb_rows}</tbody></table></div>
<div class="card"><h3>N×N 两两单 Token JSD 热力矩阵（≤0.16 标红提示高度疑似同一底层模型）</h3><table><thead><tr><th>目标 \\ JSD</th>{mat_head}</tr></thead><tbody>{mat_body}</tbody></table></div>
</div></body></html>"""
