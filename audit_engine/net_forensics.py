"""Network Edge & HTTP Header Forensics (CF-Ray IATA Geo-Decoder + Gateway Stack Fingerprinter)."""

from __future__ import annotations

import re
from typing import Any

# Common Cloudflare PoP IATA airport codes mapped to human-readable regions
_IATA_MAP: dict[str, str] = {
    "HKG": "中国香港 (HKG)",
    "TPE": "中国台北 (TPE)",
    "MFM": "中国澳门 (MFM)",
    "SIN": "新加坡 (SIN)",
    "NRT": "日本东京·成田 (NRT)",
    "HND": "日本东京·羽田 (HND)",
    "KIX": "日本大阪 (KIX)",
    "ICN": "韩国首尔 (ICN)",
    "SJC": "美国加州·圣何塞 (SJC)",
    "LAX": "美国加州·洛杉矶 (LAX)",
    "SFO": "美国加州·旧金山 (SFO)",
    "SEA": "美国西雅图 (SEA)",
    "IAD": "美国弗吉尼亚·美东 (IAD)",
    "EWR": "美国纽瓦克·美东 (EWR)",
    "ORD": "美国芝加哥 (ORD)",
    "DFW": "美国达拉斯 (DFW)",
    "LHR": "英国伦敦 (LHR)",
    "FRA": "德国法兰克福 (FRA)",
    "AMS": "荷兰阿姆斯特丹 (AMS)",
    "CDG": "法国巴黎 (CDG)",
    "SYD": "澳大利亚悉尼 (SYD)",
    "YVR": "加拿大温哥华 (YVR)",
}


def analyze_network_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Decode edge PoP geolocation (cf-ray), CDN/proxy software, and official vendor headers."""
    h = {k.lower(): str(v) for k, v in (headers or {}).items()}
    clues: list[str] = []
    edge_pop = ""
    gateway_guess = "未知/直连"

    cf_ray = h.get("cf-ray", "")
    if cf_ray:
        m = re.search(r"-([A-Z]{3})$", cf_ray.strip().upper())
        if m:
            code = m.group(1)
            edge_pop = _IATA_MAP.get(code, f"Cloudflare 节点 ({code})")
            clues.append(f"Cloudflare 边缘接入节点：{edge_pop} (`cf-ray: {cf_ray}`)")
        else:
            clues.append(f"经过 Cloudflare 边缘代理 (`cf-ray: {cf_ray}`)")

    server = h.get("server", "").lower()
    if "cloudflare" in server:
        gateway_guess = "Cloudflare 边缘代理"
    elif "envoy" in server or "gws" in server or "esf" in server:
        gateway_guess = "Google / Envoy 云原生网关"
        clues.append(f"服务端头 `{h.get('server')}`（常见于 Google/Anthropic/云托管边缘）")
    elif "openresty" in server or "nginx" in server:
        gateway_guess = f"自建反代 ({h.get('server')})"
        clues.append(f"检测到自建反向代理头 `server: {h.get('server')}`")
    elif "caddy" in server or "traefik" in server:
        gateway_guess = f"自建网关 ({h.get('server')})"
        clues.append(f"检测到自建网关 `server: {h.get('server')}`")

    for hk, hv in h.items():
        if "oneapi" in hk or "one-api" in hk:
            gateway_guess = "OneAPI 中转系统"
            clues.append(f"暴露 OneAPI 响应头 `{hk}: {hv}`")
        elif "newapi" in hk or "new-api" in hk:
            gateway_guess = "NewAPI 中转系统"
            clues.append(f"暴露 NewAPI 响应头 `{hk}: {hv}`")
        elif "veloera" in hk or "rixapi" in hk:
            gateway_guess = f"第三方魔改中转网关 ({hk})"
            clues.append(f"暴露第三方中转头 `{hk}: {hv}`")

    if "anthropic-organization-id" in h:
        clues.append("存在官方 `anthropic-organization-id` 响应头")
    if "openai-processing-ms" in h:
        clues.append(f"存在官方 `openai-processing-ms: {h['openai-processing-ms']}ms` 处理耗时头")

    return {
        "edge_pop": edge_pop,
        "gateway_guess": gateway_guess,
        "server": h.get("server", ""),
        "cf_ray": cf_ray,
        "clues": list(dict.fromkeys(clues)),
    }
