"""Continuous Canary Monitor for Detecting Intermittent Mixing & Peak-Hour Degradation.

Periodically executes ultra-cheap canary probes (SSE timing + metadata + micro
single-token distribution + 1 dynamic mini-IQ check) and raises drift alerts
when a relay silently switches backends or degrades over time.
"""

from __future__ import annotations

import random
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import httpx

from .baselines import jensen_shannon_divergence
from .client import RelayClient
from .models import AuditConfig
from .probes_fingerprint import _normalize_single_token_answer
from .probes_iq import _build_anti_bias_crystal, _build_anti_bias_pricing, _build_math_crt


def send_webhook_alert(webhook_url: str, title: str, lines: list[str]) -> tuple[bool, str]:
    """Send alert notification to Feishu / DingTalk / WeCom / Discord / Slack / Generic webhook."""
    url = (webhook_url or "").strip()
    if not url or not url.startswith(("http://", "https://")):
        return False, "无效的 Webhook URL"

    text = f"[{title}]\n" + "\n".join(f"- {ln}" for ln in lines)
    low = url.lower()
    if "feishu" in low or "larksuite" in low:
        payload: dict[str, Any] = {"msg_type": "text", "content": {"text": text}}
    elif "dingtalk" in low or "oapi.dingtalk" in low:
        payload = {"msgtype": "text", "text": {"content": text}}
    elif "qyapi.weixin" in low:
        payload = {"msgtype": "text", "text": {"content": text}}
    elif "discord.com" in low or "discordapp.com" in low:
        payload = {"content": text}
    else:
        payload = {"text": text, "title": title, "alerts": lines}

    try:
        resp = httpx.post(url, json=payload, timeout=8.0)
        if 200 <= resp.status_code < 300:
            return True, f"HTTP {resp.status_code}"
        return False, f"HTTP {resp.status_code}: {resp.text[:120]}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


class CanaryMonitor:
    """Thread-safe background canary watcher for a single target endpoint."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None
        self.running = False
        self.monitor_id = ""
        self.config_safe: dict[str, Any] = {}
        self.interval_sec = 180
        self.webhook_url = ""
        self.webhook_logs: list[dict[str, Any]] = []
        self.ticks: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self._anchor_model = ""
        self._anchor_id_prefix = ""
        self._anchor_sys_fp = ""
        self._anchor_dist: dict[str, Counter[str]] = {"num": Counter(), "color": Counter()}
        self._anchor_latency_ms: float | None = None

    def start(self, config: AuditConfig, interval_sec: int = 180, webhook_url: str = "") -> dict[str, Any]:
        self.stop()
        with self._lock:
            self._stop_evt.clear()
            self.running = True
            self.monitor_id = f"mon_{uuid.uuid4().hex[:8]}"
            self.config_safe = config.safe_dict()
            self.interval_sec = max(15, min(3600, int(interval_sec)))
            self.webhook_url = (webhook_url or "").strip()
            self.webhook_logs = []
            self.ticks = []
            self.alerts = []
            self._anchor_model = ""
            self._anchor_id_prefix = ""
            self._anchor_sys_fp = ""
            self._anchor_dist = {"num": Counter(), "color": Counter()}
            self._anchor_latency_ms = None

        self._thread = threading.Thread(
            target=self._loop, args=(config,), name=f"canary-{self.monitor_id}", daemon=True
        )
        self._thread.start()
        return self.status()

    def stop(self) -> dict[str, Any]:
        self._stop_evt.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=2.0)
        with self._lock:
            self.running = False
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            wh = self.webhook_url
            wh_masked = (wh[:28] + "..." + wh[-6:]) if len(wh) > 40 else wh
            return {
                "running": self.running,
                "monitor_id": self.monitor_id,
                "config": self.config_safe,
                "interval_sec": self.interval_sec,
                "webhook_configured": bool(wh),
                "webhook_masked": wh_masked,
                "webhook_logs": list(self.webhook_logs[-20:]),
                "tick_count": len(self.ticks),
                "ticks": list(self.ticks[-100:]),
                "alerts": list(self.alerts[-50:]),
                "anchors": {
                    "model": self._anchor_model,
                    "id_prefix": self._anchor_id_prefix,
                    "system_fingerprint": self._anchor_sys_fp,
                    "latency_ms": self._anchor_latency_ms,
                },
            }

    def run_single_tick(self, config: AuditConfig) -> dict[str, Any]:
        """Execute one lightweight canary check and record any drift alerts."""
        client = RelayClient(config)
        tick_alerts: list[str] = []
        ts = datetime.now(timezone.utc).isoformat()
        try:
            proto, conn = client.detect_protocol()
            if not conn.ok:
                tick = {
                    "index": len(self.ticks) + 1,
                    "timestamp": ts,
                    "ok": False,
                    "error": conn.error[:180],
                    "latency_ms": round(conn.latency_ms, 1),
                    "ttft_ms": None,
                    "tps": 0.0,
                    "iq_ok": False,
                    "jsd_vs_anchor": None,
                    "alerts": [f"连通失败 HTTP {conn.status_code}: {conn.error[:100]}"],
                }
                self._commit_tick(tick, tick["alerts"])
                return tick

            # 1. Quick streaming check for TTFT, TPS, ID prefix & fingerprint
            sr = client.chat(
                messages=[{"role": "user", "content": "Explain DNS resolution in 2 short sentences."}],
                max_tokens=72,
                temperature=0.0,
                stream=True,
            )
            sm = sr.stream_metrics or {}
            ret_model = sr.returned_model or conn.returned_model
            id_prefix = client._id_prefix(sr.response_id or conn.response_id)
            sys_fp = sr.system_fingerprint or conn.system_fingerprint

            if "<think>" in (sr.text or ""):
                tick_alerts.append("正文突然泄露 `<think>` 开源思考标签！")

            # 2. Micro distribution sample (3 num + 3 color)
            cur_num: Counter[str] = Counter()
            cur_col: Counter[str] = Counter()
            for _ in range(3):
                r1 = client.chat(
                    messages=[{"role": "user", "content": "Pick a random integer between 1 and 100. Reply digits only."}],
                    max_tokens=16,
                    temperature=1.0,
                )
                if r1.ok:
                    v1 = _normalize_single_token_answer(r1.text, "int")
                    if v1 and v1 != "<EMPTY>":
                        cur_num[v1] += 1
                r2 = client.chat(
                    messages=[{"role": "user", "content": "Name one color that comes to mind first. Reply one English word only."}],
                    max_tokens=16,
                    temperature=1.0,
                )
                if r2.ok:
                    v2 = _normalize_single_token_answer(r2.text, "word_en")
                    if v2 and v2 != "<EMPTY>":
                        cur_col[v2] += 1

            # 3. 1 dynamic mini-IQ question (rotated across 3 generators)
            rng = random.Random()
            q = rng.choice([_build_anti_bias_crystal, _build_anti_bias_pricing, _build_math_crt])(rng)
            iq_r = client.chat(
                messages=[{"role": "user", "content": q["prompt"]}],
                max_tokens=512,
                temperature=0.0,
            )
            iq_ok = False
            if iq_r.ok and iq_r.text:
                frac, _ = q["grader"](iq_r.text)
                iq_ok = frac >= 0.85
            if not iq_ok:
                tick_alerts.append(f"动态微智商抽检失败（题目: {q['title']}）")

            # Compare against anchor (first successful tick sets anchor)
            jsd_val: float | None = None
            with self._lock:
                if not self._anchor_model and ret_model:
                    self._anchor_model = ret_model
                elif self._anchor_model and ret_model and ret_model != self._anchor_model:
                    tick_alerts.append(f"返回模型名漂移：`{self._anchor_model}` → `{ret_model}`！")

                if not self._anchor_id_prefix and id_prefix:
                    self._anchor_id_prefix = id_prefix
                elif self._anchor_id_prefix and id_prefix and id_prefix != self._anchor_id_prefix:
                    tick_alerts.append(f"响应 ID 前缀突变：`{self._anchor_id_prefix}` → `{id_prefix}`（疑似切换上游！）")

                if not self._anchor_sys_fp and sys_fp:
                    self._anchor_sys_fp = sys_fp
                elif self._anchor_sys_fp and sys_fp and sys_fp != self._anchor_sys_fp:
                    tick_alerts.append(f"system_fingerprint 漂移：`{self._anchor_sys_fp}` → `{sys_fp}`")

                if self._anchor_latency_ms is None and sr.latency_ms > 0:
                    self._anchor_latency_ms = round(sr.latency_ms, 1)
                elif self._anchor_latency_ms and sr.latency_ms > max(3500.0, self._anchor_latency_ms * 3.5):
                    tick_alerts.append(f"响应延迟骤增：{sr.latency_ms:.0f}ms（基准 {self._anchor_latency_ms:.0f}ms）")

                if sum(self._anchor_dist["num"].values()) == 0:
                    self._anchor_dist["num"].update(cur_num)
                    self._anchor_dist["color"].update(cur_col)
                    jsd_val = 0.0
                else:
                    parts = []
                    if cur_num and self._anchor_dist["num"]:
                        parts.append(jensen_shannon_divergence(dict(cur_num), dict(self._anchor_dist["num"])))
                    if cur_col and self._anchor_dist["color"]:
                        parts.append(jensen_shannon_divergence(dict(cur_col), dict(self._anchor_dist["color"])))
                    jsd_val = round(sum(parts) / len(parts), 4) if parts else None
                    if jsd_val is not None and jsd_val >= 0.78:
                        tick_alerts.append(f"微采样分布剧烈漂移 (JSD={jsd_val:.3f})，疑似本轮被混流至其他模型！")

            tick = {
                "index": len(self.ticks) + 1,
                "timestamp": ts,
                "ok": True,
                "protocol": proto,
                "returned_model": ret_model,
                "id_prefix": id_prefix,
                "system_fingerprint": sys_fp,
                "latency_ms": round(sr.latency_ms, 1),
                "ttft_ms": sm.get("ttft_ms"),
                "tps": sm.get("effective_tps", 0.0),
                "fake_stream": bool(sm.get("fake_stream_suspected")),
                "iq_ok": iq_ok,
                "iq_title": q["title"],
                "jsd_vs_anchor": jsd_val,
                "sample_num": dict(cur_num),
                "sample_color": dict(cur_col),
                "alerts": tick_alerts,
            }
            self._commit_tick(tick, tick_alerts)
            return tick
        finally:
            client.close()

    def _commit_tick(self, tick: dict[str, Any], tick_alerts: list[str]) -> None:
        wh_url = ""
        model_lbl = ""
        with self._lock:
            self.ticks.append(tick)
            for a in tick_alerts:
                self.alerts.append(
                    {"tick": tick["index"], "timestamp": tick["timestamp"], "message": a}
                )
            wh_url = self.webhook_url
            model_lbl = str(self.config_safe.get("model") or "API")

        if tick_alerts and wh_url:
            def _push() -> None:
                ok, detail = send_webhook_alert(
                    wh_url,
                    f"LLM-TruthLab 金丝雀异常告警 · {model_lbl} (Tick #{tick['index']})",
                    tick_alerts,
                )
                with self._lock:
                    self.webhook_logs.append(
                        {"timestamp": tick["timestamp"], "tick": tick["index"], "ok": ok, "detail": detail}
                    )

            threading.Thread(target=_push, daemon=True).start()

    def _loop(self, config: AuditConfig) -> None:
        while not self._stop_evt.is_set():
            try:
                self.run_single_tick(config)
            except Exception as exc:
                self._commit_tick(
                    {
                        "index": len(self.ticks) + 1,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "ok": False,
                        "error": str(exc),
                        "latency_ms": 0.0,
                        "ttft_ms": None,
                        "tps": 0.0,
                        "iq_ok": False,
                        "jsd_vs_anchor": None,
                        "alerts": [f"巡检异常: {exc}"],
                    },
                    [f"巡检异常: {exc}"],
                )
            if self._stop_evt.wait(timeout=self.interval_sec):
                break
        with self._lock:
            self.running = False
