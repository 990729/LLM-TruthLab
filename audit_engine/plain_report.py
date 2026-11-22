"""Plain-Language ("大白话") Audit Report Translator & AI Summarizer.

Translates technical forensic evidence (JSD, tokenizer vectors, error schemas,
logit_bias, prompt cache physics, IQ dimensions) into crystal-clear everyday
Chinese that anyone can understand in 10 seconds — using the audited API key
by default (with deterministic zero-jargon local fallback).
"""

from __future__ import annotations

import re
from typing import Any

from .client import RelayClient
from .models import AuditConfig, EvidenceItem, FingerprintSummary, IQSummary, VerdictSummary


def _translate_anomaly_plain(raw: str) -> str:
    """Turn technical anomaly lines into plain everyday Chinese."""
    low = raw.lower()
    if "篡改" in raw and ("签名" in raw or "thinking" in low):
        return "思考加密签名是假的/没经过官方验证（高度怀疑不是官方原版通道）。"
    if "<think>" in low:
        return "回复里直接漏出了开源模型的 `<think>` 思考标签，几乎肯定是拿国产/开源模型冒充的。"
    if "正则" in raw or "洗白" in raw:
        return "中转站在后台偷偷写了敏感词替换，把别的模型名字强行改成你买的品牌名。"
    if "tiktoken" in low or "假算" in raw or "单 token 仅吐" in raw:
        return "账单是假算的：故意按贵模型的算法扣你钱，但背后跑的是便宜模型的词表。"
    if "隐藏" in raw and "system" in low:
        return "中转站背着你偷偷塞了一段隐藏指令，既多花你的钱又可能篡改回答。"
    if "倍率" in raw and "注水" in raw:
        return "输入 Token 计数明显偏高，怀疑中转站在后台悄悄把计费翻倍了。"
    if "temperature=99" in low or "非法参数" in raw:
        return "你传了一个明显胡写错的参数（temperature=99），正常官方接口会直接报错拒收，但它居然照单全收——说明中转网关（或网页逆向号池）偷偷把你的参数删掉/改掉了。"
    if "stop" in low and ("忽略" in raw or "未生效" in raw):
        return "你设置的「停止词」完全没起作用，说明中转站把部分高级参数给吞掉了。"
    if "logit_bias" in low:
        return "高级采样参数（logit_bias）被静默忽略了——常见于「网页版逆向号池」、网关删参数，或者背后换成了不支持该参数的模型。"
    if "cache_read=0" in low or "轮询" in raw:
        return "连续发一模一样的长内容却命中不了缓存，高度像「多账号轮询的网页逆向号池」而不是正经独享 API。"
    if "过快" in raw or "tok/s" in low:
        return "吐字速度异常得快，快得不像真正的重型旗舰，怀疑偷偷换成了同系列便宜轻量版。"
    if "降采样" in raw or "1024" in raw:
        return "发给它的高清大图细节读不出来，怀疑中转站在后台偷偷把图片压缩糊了来省钱。"
    if "失忆" in raw or "遗忘首轮" in raw:
        return "多轮聊天几句就忘了最开始交代的事，怀疑中转站偷偷截断了聊天记录或中途换号了。"
    if "假流式" in raw:
        return "看起来像一个字一个字往外蹦，其实是后台卡着全算完再一口气倒出来的「假流式」。"
    if "归因冲突" in raw:
        return "综合各项细微特征来看，背后模型和它标的名字对不太上（如果置信度低于 50% 只算轻微怀疑，建议用「双端对决」复核）。"
    if "档位背离" in raw or "智商偏低" in raw:
        return "实测做题智商明显配不上它卖的高价旗舰名头，可能被降级、重度量化或偷砍了思考深度。"
    if "视觉" in raw or "图片" in raw:
        return "看不懂动态生成的测试图片，可能背后换成了不支持看图的纯文本模型。"
    if "断代" in raw or "时间线" in raw:
        return "连近期公开的大事件都不知道，高度怀疑是拿前年的老旧模型改名冒充新旗舰。"
    return re.sub(r"^\[[^\]]+\]\s*", "", raw).strip()


def build_local_plain_summary(
    *,
    model: str,
    verdict: VerdictSummary,
    evidences: list[EvidenceItem],
    fingerprint: FingerprintSummary,
    iq: IQSummary | None,
    attribution: dict[str, Any],
    telemetry: dict[str, Any],
) -> dict[str, Any]:
    """Deterministic zero-jargon everyday Chinese summary (zero tokens, always available)."""
    code = verdict.authenticity_code
    iq_score = iq.total_score if iq else None
    cost_cny = float(((telemetry.get("cost_estimate") or {}).get("estimated_cny")) or 0.0)
    anomalies = verdict.suspected_anomalies or []

    # 1. One-sentence plain verdict
    if code == "VERIFIED_STRONG":
        tldr = f"放心用！这个 `{model}` 通过了硬核防伪验真，没查出掺水或换模破绽。"
    elif code == "LIKELY_FAKE_OR_WATERED":
        tldr = f"快跑！这个 `{model}` 查出了致命假货破绽，高度怀疑在掺水、套壳或拿便宜模型冒充。"
    elif code == "SUSPICIOUS":
        if iq_score is not None and iq_score >= 85.0:
            tldr = (
                f"脑子是真的好使（考了 {iq_score} 分顶尖水平），但通道不太规矩——"
                "中转站偷偷改写或删掉了部分请求参数（常见于网页逆向号池或中转兼容层），不算原汁原味官源直连。"
            )
        else:
            tldr = f"有点可疑！这个 `{model}` 查出了明显异常（改参数、混流或表现不稳），建议谨慎充钱。"
    elif code == "ERROR":
        tldr = f"压根没连上这个接口，请先检查网址、API Key、余额或模型名字有没有填错。"
    else:
        if iq_score is not None and iq_score >= 85.0:
            tldr = f"整体表现挺像真旗舰（实测智商 {iq_score} 分，没查出造假破绽），但因为没对比官方指纹库，程序按严格标准暂时不敢拍胸脯保 100% 真。"
        else:
            tldr = f"暂时没查出明显造假破绽，但还缺少一锤定音的铁证，建议有条件时对比一次官方基线。"

    # 2. IQ plain translation
    if iq is not None:
        if iq.total_score >= 88:
            iq_plain = f"实测干活能力非常强，动态新题考了 {iq.total_score}/100 分（顶尖旗舰水准），绝对不是拿便宜笨模型糊弄人。"
        elif iq.total_score >= 74:
            iq_plain = f"实测干活能力不错，考了 {iq.total_score}/100 分（主力中高端水准），日常写代码和推理够用。"
        elif iq.total_score >= 56:
            iq_plain = f"实测脑子偏一般，只考了 {iq.total_score}/100 分（轻量/入门模型水准）；如果按高价旗舰收费，性价比很亏。"
        else:
            iq_plain = f"实测智商明显拉胯，只考了 {iq.total_score}/100 分，严重不符高阶模型应有表现，极可能被降级或重度阉割。"
    else:
        iq_plain = "这次没开智商测试，只做了防伪体检。"

    # 3. Translated issues
    plain_issues: list[str] = []
    seen: set[str] = set()
    for a in anomalies[:5]:
        tr = _translate_anomaly_plain(a)
        if tr not in seen:
            seen.add(tr)
            plain_issues.append(tr)

    # 4. Actionable everyday advice
    if code == "LIKELY_FAKE_OR_WATERED":
        advice = "建议别往这个站充大钱；如果想看它到底拿哪个便宜模型顶替，去「双端对决」拿它自家便宜模型对比一下就能当场抓现行。"
    elif code == "SUSPICIOUS" and iq_score is not None and iq_score >= 85.0:
        advice = "如果只是日常对话/写代码且价格便宜，智商过关可以小额按需用；但别指望它严格遵守高级 API 参数，如担心拿别家旗舰顶替，去「双端对决」花几毛钱对比一下就能确认。"
    elif code == "VERIFIED_STRONG":
        advice = "当前表现稳健，可以正常使用；担心以后「先真后假」的话，可以偶尔用「历史档案纵比」或「金丝雀盯盘」复查。"
    else:
        advice = "建议拿官方渠道跑一次「闪电打假」并存成基线，以后花几分钱就能一眼看出任何中转站是不是原装货。"

    mlm = (attribution or {}).get("most_likely_model") or {}
    mlm_name = str(mlm.get("model_name") or model)
    mlm_conf = mlm.get("confidence_pct", 0)
    mlm_basis = str(mlm.get("basis") or "")

    lines = [
        f"【一句话结论】{tldr}",
        f"【最可能真实模型】{mlm_name}（置信度 {mlm_conf}%；依据：{mlm_basis or '综合词表、协议与智商表现'}）",
        f"【干活水平】{iq_plain}",
    ]
    if plain_issues:
        lines.append("【查出的问题】")
        for idx, it in enumerate(plain_issues, 1):
            lines.append(f"  {idx}. {it}")
    else:
        lines.append("【查出的问题】这次检测没有抓到明显造假或改参数的毛病。")
    lines.append(f"【实用建议】{advice}")
    if cost_cny > 0:
        lines.append(f"【费用参考】这次检测按官方公开价大约值 ¥{cost_cny:.3f}，你可以对照中转站后台扣费看看有没有被悄悄加价。")

    return {
        "source": "local_fallback",
        "source_label": "本地规则大白话翻译",
        "tldr": tldr,
        "content": "\n".join(lines),
        "model_used": "",
    }


def generate_ai_plain_summary(
    client: RelayClient,
    config: AuditConfig,
    *,
    verdict: VerdictSummary,
    evidences: list[EvidenceItem],
    fingerprint: FingerprintSummary,
    iq: IQSummary | None,
    attribution: dict[str, Any],
    telemetry: dict[str, Any],
) -> dict[str, Any]:
    """Call the user's configured API key to write a crystal-clear plain-Chinese summary."""
    fallback = build_local_plain_summary(
        model=config.model,
        verdict=verdict,
        evidences=evidences,
        fingerprint=fingerprint,
        iq=iq,
        attribution=attribution,
        telemetry=telemetry,
    )

    top_sus = (attribution or {}).get("top_suspect") or {}
    mlm = (attribution or {}).get("most_likely_model") or {}
    cost = (telemetry or {}).get("cost_estimate") or {}
    nf = (telemetry or {}).get("network_forensics") or {}

    facts_lines = [
        f"- 宣称模型: {config.model}",
        f"- 置信度最高的推测真实模型: {mlm.get('model_name', '未知')} (置信度 {mlm.get('confidence_pct', 0)}%, 依据: {mlm.get('basis', '')})",
        f"- 仲裁结论: {verdict.authenticity_label} ({verdict.authenticity_code}), 可信分 {verdict.trust_score}/100 (注: 无密码学铁证且无本地官方基线对比时上限锁定78分)",
        f"- 协议与词表特征: {verdict.detected_protocol} | {verdict.detected_tokenizer_family}",
        f"- 动态智商实测: {f'{iq.total_score}/100 ({iq.tier_label})' if iq else '未测试'}",
        f"- 底层归因第一候选家族: {top_sus.get('family_label', '未知')} (相对置信度 {top_sus.get('confidence_pct', 0)}%, 冲突={attribution.get('family_conflict', False)})",
        f"- 网络机房/网关: {nf.get('edge_pop') or '未知'} / {', '.join(nf.get('gateway_stack') or []) or '未知'}",
        f"- 消耗与官价参考: 输入 {telemetry.get('input_tokens', 0)} / 输出 {telemetry.get('output_tokens', 0)} tokens, 官价约 ¥{cost.get('estimated_cny', 0)}",
        f"- 检出异常 ({len(verdict.suspected_anomalies)}条): " + ("；".join(verdict.suspected_anomalies[:6]) if verdict.suspected_anomalies else "无"),
        f"- 强证据 ({len(verdict.strong_proofs)}条): " + ("；".join(verdict.strong_proofs[:4]) if verdict.strong_proofs else "无"),
    ]

    sys_prompt = (
        "你是一位客观犀利、绝不护短的第三方 API 质检翻译官。"
        "你的唯一任务是把下面的技术体检数据翻译成普通人 10 秒就能看懂的「大白话中文结论」。\n"
        "严格要求：\n"
        "1. 绝对不能替接口辩解、洗白或篡改事实，事实里有什么问题必须直说。\n"
        "2. 禁止堆砌生涩英文术语（不要直接甩 JSD、BPE、Schema、TTFT、logit_bias 等名词，要翻译成人话，比如“偷偷删了你传的参数”“按贵模型假算账单”“可能是网页逆向号池”）。\n"
        "3. 如果出现「智商很高（如85+）但可信分只有70多且报参数被洗」，一定要通俗解释清楚：脑子确实是真旗舰水平，但通道不干净（大概率是中转改了参数或走了网页逆向号池）。\n"
        "4. 严格按以下 5 行格式输出，总字数控制在 180–300 字，清爽易读，不要写多余开场白或 Markdown 标题：\n"
        "【一句话结论】...\n"
        "【最可能真实模型】<直接写出上面数据里置信度最高的最新模型名与置信度%，用一句人话解释原因>\n"
        "【干活水平】...\n"
        "【查出的问题】...\n"
        "【给你的建议】..."
    )

    try:
        res = client.chat(
            system=sys_prompt,
            messages=[{"role": "user", "content": "请把以下检测事实翻译成大白话体检结论：\n" + "\n".join(facts_lines)}],
            max_tokens=512,
            temperature=0.2,
        )
        txt = re.sub(r"<think>.*?</think>", "", (res.text or ""), flags=re.S | re.I).strip()
        if res.ok and len(txt) >= 40 and ("【" in txt or "结论" in txt or "建议" in txt):
            # Extract first line as tldr
            first_ln = txt.splitlines()[0].strip()
            tldr = re.sub(r"^【[^】]+】\s*", "", first_ln).strip() or fallback["tldr"]
            return {
                "source": "llm",
                "source_label": f"AI 大白话总结（由当前 Key · {config.model} 生成）",
                "tldr": tldr,
                "content": txt,
                "model_used": config.model,
            }
    except Exception:
        pass

    return fallback
