"""Unified multi-protocol HTTP client for OpenAI, Anthropic, and Gemini relays.

Captures complete low-level telemetry (headers, IDs, SSE event types, latency,
TTFT, token accounting, thinking blocks & cryptographic signatures, logprobs).
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from .models import AuditConfig, HttpTrace


@dataclass
class CompletionResult:
    ok: bool
    status_code: int
    text: str = ""
    thinking: str = ""
    thinking_signature: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    logprobs: list[dict[str, Any]] = field(default_factory=list)
    raw_json: dict[str, Any] | None = None
    raw_text: str = ""
    sse_events: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    latency_ms: float = 0.0
    ttft_ms: float | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    returned_model: str = ""
    response_id: str = ""
    system_fingerprint: str = ""
    service_tier: str = ""
    finish_reason: str = ""
    error: str = ""
    url: str = ""
    protocol_used: str = ""
    stream_metrics: dict[str, Any] = field(default_factory=dict)

    def to_trace(self, method: str = "POST", req_summary: dict[str, Any] | None = None) -> HttpTrace:
        return HttpTrace(
            method=method,
            url=self.url,
            status_code=self.status_code,
            latency_ms=round(self.latency_ms, 1),
            ttft_ms=round(self.ttft_ms, 1) if self.ttft_ms is not None else None,
            headers=self.headers,
            request_summary=req_summary or {},
            response_snippet=(self.raw_text or "")[:600],
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            reasoning_tokens=self.reasoning_tokens,
            cache_creation_tokens=self.cache_creation_tokens,
            cache_read_tokens=self.cache_read_tokens,
            returned_model=self.returned_model,
            response_id=self.response_id,
            system_fingerprint=self.system_fingerprint,
            error=self.error,
        )


def normalize_base_url(base_url: str) -> str:
    url = (base_url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def build_endpoint_url(base_url: str, protocol: str, model: str = "", stream: bool = False) -> str:
    """Resolve the exact endpoint URL from a user-provided base URL and protocol."""
    base = normalize_base_url(base_url)
    lower = base.lower()

    if protocol == "openai_chat":
        if lower.endswith("/chat/completions"):
            return base
        if lower.endswith("/v1/messages"):
            return base[: -len("/messages")] + "/chat/completions"
        if lower.endswith("/v1/responses"):
            return base[: -len("/responses")] + "/chat/completions"
        if lower.endswith("/v1"):
            return f"{base}/chat/completions"
        parsed = urlparse(base)
        if parsed.path in ("", "/"):
            return f"{base}/v1/chat/completions"
        # Preserve custom prefixes like /openai/v1 or /api/v1
        if parsed.path.rstrip("/").endswith(("/v1", "/v2", "/v3", "/v4")):
            return f"{base}/chat/completions"
        return f"{base}/v1/chat/completions"

    if protocol == "openai_responses":
        if lower.endswith("/responses"):
            return base
        if lower.endswith("/chat/completions"):
            return base[: -len("/chat/completions")] + "/responses"
        if lower.endswith("/v1"):
            return f"{base}/responses"
        return f"{base}/v1/responses"

    if protocol == "anthropic":
        if lower.endswith("/messages"):
            return base
        if lower.endswith("/chat/completions"):
            return base[: -len("/chat/completions")] + "/messages"
        if lower.endswith("/v1"):
            return f"{base}/messages"
        parsed = urlparse(base)
        if parsed.path.rstrip("/").endswith(("/v1", "/v2")):
            return f"{base}/messages"
        return f"{base}/v1/messages"

    if protocol == "gemini":
        action = "streamGenerateContent?alt=sse" if stream else "generateContent"
        if ":generatecontent" in lower or ":streamgeneratecontent" in lower:
            return base
        if "/v1beta" in lower or "/v1alpha" in lower:
            root = base.rstrip("/")
            if root.endswith("/models"):
                return f"{root}/{model}:{action}"
            return f"{root}/models/{model}:{action}"
        return f"{base}/v1beta/models/{model}:{action}"

    return base


def build_models_url(base_url: str) -> str:
    base = normalize_base_url(base_url)
    lower = base.lower()
    for suffix in ("/chat/completions", "/messages", "/responses"):
        if lower.endswith(suffix):
            return base[: -len(suffix)] + "/models"
    if lower.endswith("/v1"):
        return f"{base}/models"
    return f"{base}/v1/models"


class RelayClient:
    """Thread-safe multi-protocol client with telemetry accumulation."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config
        self.base_url = normalize_base_url(config.base_url)
        self.protocol = config.protocol
        self._anthropic_use_bearer = False
        self._prefer_max_completion_tokens = False
        self._rejects_custom_temperature = False

        limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
        client_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(config.timeout_sec, connect=15.0),
            "limits": limits,
            "follow_redirects": True,
            "verify": bool(config.verify_ssl),
        }
        if config.proxy_url and config.proxy_url.strip():
            client_kwargs["proxy"] = config.proxy_url.strip()
        self._http = httpx.Client(**client_kwargs)
        self._lock = threading.Lock()
        self.telemetry: dict[str, Any] = {
            "total_requests": 0,
            "ok_requests": 0,
            "failed_requests": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "reasoning_tokens": 0,
            "cache_creation_tokens": 0,
            "cache_read_tokens": 0,
            "latencies_ms": [],
            "ttfts_ms": [],
            "returned_models": {},
            "response_id_prefixes": {},
            "system_fingerprints": {},
            "server_headers": {},
            "protocol_notes": [],
        }

    def close(self) -> None:
        try:
            self._http.close()
        except Exception:
            pass

    def _record_telemetry(self, res: CompletionResult) -> None:
        with self._lock:
            t = self.telemetry
            t["total_requests"] += 1
            if res.ok:
                t["ok_requests"] += 1
            else:
                t["failed_requests"] += 1
            t["input_tokens"] += max(0, res.input_tokens)
            t["output_tokens"] += max(0, res.output_tokens)
            t["reasoning_tokens"] += max(0, res.reasoning_tokens)
            t["cache_creation_tokens"] += max(0, res.cache_creation_tokens)
            t["cache_read_tokens"] += max(0, res.cache_read_tokens)
            if res.latency_ms > 0:
                t["latencies_ms"].append(round(res.latency_ms, 1))
            if res.ttft_ms is not None and res.ttft_ms > 0:
                t["ttfts_ms"].append(round(res.ttft_ms, 1))
            if res.returned_model:
                t["returned_models"][res.returned_model] = (
                    t["returned_models"].get(res.returned_model, 0) + 1
                )
            if res.response_id:
                prefix = self._id_prefix(res.response_id)
                t["response_id_prefixes"][prefix] = (
                    t["response_id_prefixes"].get(prefix, 0) + 1
                )
            if res.system_fingerprint:
                t["system_fingerprints"][res.system_fingerprint] = (
                    t["system_fingerprints"].get(res.system_fingerprint, 0) + 1
                )
            for hk in (
                "server",
                "x-powered-by",
                "via",
                "cf-ray",
                "anthropic-organization-id",
                "openai-organization",
                "openai-version",
                "openai-processing-ms",
                "x-oneapi-request-id",
                "x-newapi-request-id",
                "x-request-id",
                "request-id",
                "x-ratelimit-limit-requests",
            ):
                if hk in res.headers:
                    t["server_headers"][hk] = res.headers[hk]

    @staticmethod
    def _id_prefix(rid: str) -> str:
        if not rid:
            return ""
        for sep in ("_", "-"):
            if sep in rid:
                head = rid.split(sep, 1)[0]
                if len(head) <= 16:
                    return head + sep
        return rid[:8] + "..."

    def _base_headers(self, protocol: str) -> dict[str, str]:
        if self.config.stealth_mode:
            if protocol == "anthropic":
                ua = "Anthropic/JS 0.39.0"
            elif protocol == "gemini":
                ua = "google-genai-sdk/1.5.0 gl-python/3.12"
            else:
                ua = "OpenAI/Python 1.72.0"
        else:
            ua = "LLM-Forensic-Audit/11.0"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": ua,
        }
        if protocol in ("openai_chat", "openai_responses"):
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        elif protocol == "anthropic":
            headers["anthropic-version"] = "2023-06-01"
            if self._anthropic_use_bearer:
                headers["Authorization"] = f"Bearer {self.config.api_key}"
            else:
                headers["x-api-key"] = self.config.api_key
        elif protocol == "gemini":
            headers["x-goog-api-key"] = self.config.api_key

        if self.config.extra_headers:
            headers.update(self.config.extra_headers)
        return headers

    def current_estimated_cny(self) -> float:
        """Compute live official-reference CNY spend from accumulated telemetry."""
        from .pricing import estimate_audit_cost

        with self._lock:
            snap = {
                "input_tokens": self.telemetry.get("input_tokens", 0),
                "output_tokens": self.telemetry.get("output_tokens", 0),
                "cache_read_tokens": self.telemetry.get("cache_read_tokens", 0),
            }
        return float(estimate_audit_cost(self.config.model, snap).get("estimated_cny") or 0.0)

    def detect_protocol(self) -> tuple[str, CompletionResult]:
        """Auto-detect active protocol and verify basic connectivity."""
        explicit = self.config.protocol
        if explicit != "auto":
            self.protocol = explicit
            res = self.chat(
                messages=[{"role": "user", "content": "Reply with OK"}],
                max_tokens=16,
                temperature=0.0,
            )
            return self.protocol, res

        lower_url = self.base_url.lower()
        lower_model = self.config.model.lower()

        candidates: list[str]
        if lower_url.endswith("/messages"):
            candidates = ["anthropic", "openai_chat"]
        elif lower_url.endswith("/chat/completions"):
            candidates = ["openai_chat", "anthropic"]
        elif lower_url.endswith("/responses"):
            candidates = ["openai_responses", "openai_chat"]
        elif "googleapis.com" in lower_url or "/v1beta" in lower_url or ":generatecontent" in lower_url:
            candidates = ["gemini", "openai_chat"]
        elif any(k in lower_model for k in ("claude", "fable")):
            candidates = ["anthropic", "openai_chat"]
        elif any(k in lower_model for k in ("gemini", "neon", "argon")):
            candidates = ["openai_chat", "gemini"]
        else:
            candidates = ["openai_chat", "anthropic", "gemini"]

        def _matches_protocol_schema(proto_name: str, r: CompletionResult) -> bool:
            if not (r.ok and isinstance(r.raw_json, dict)):
                return False
            rj = r.raw_json
            if proto_name == "anthropic":
                return isinstance(rj.get("content"), list)
            if proto_name == "openai_chat":
                return isinstance(rj.get("choices"), list)
            if proto_name == "openai_responses":
                return isinstance(rj.get("output"), list) or "output_text" in rj
            if proto_name == "gemini":
                return isinstance(rj.get("candidates"), list)
            return bool(r.text)

        last_res = CompletionResult(ok=False, status_code=0, error="No protocol succeeded")
        for proto in candidates:
            self.protocol = proto
            res = self.chat(
                messages=[{"role": "user", "content": "Reply with OK"}],
                max_tokens=16,
                temperature=0.0,
            )
            if _matches_protocol_schema(proto, res):
                return proto, res
            # If Anthropic returned 401 with x-api-key, try Bearer auth for relays
            if proto == "anthropic" and res.status_code == 401 and not self._anthropic_use_bearer:
                self._anthropic_use_bearer = True
                res2 = self.chat(
                    messages=[{"role": "user", "content": "Reply with OK"}],
                    max_tokens=16,
                    temperature=0.0,
                )
                if _matches_protocol_schema(proto, res2):
                    with self._lock:
                        self.telemetry["protocol_notes"].append(
                            "Anthropic 端点拒绝 x-api-key 但接受 Authorization: Bearer（典型第三方中转网关特征）"
                        )
                    return proto, res2
                self._anthropic_use_bearer = False
            last_res = res

        self.protocol = candidates[0]
        return self.protocol, last_res

    def raw_post(
        self,
        payload: dict[str, Any],
        protocol: str | None = None,
        extra_headers: dict[str, str] | None = None,
        stream: bool = False,
        endpoint_override: str | None = None,
    ) -> CompletionResult:
        """Send a raw JSON payload directly to the active protocol endpoint."""
        proto = protocol or self.protocol
        if proto == "auto":
            proto = "openai_chat"
        url = endpoint_override or build_endpoint_url(
            self.base_url, proto, model=self.config.model, stream=stream
        )
        headers = self._base_headers(proto)
        if extra_headers:
            headers.update(extra_headers)

        t0 = time.perf_counter()
        if stream:
            return self._post_stream(url, headers, payload, proto, t0)

        try:
            resp = self._http.post(url, headers=headers, json=payload)
            elapsed = (time.perf_counter() - t0) * 1000.0
            norm_headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_text = resp.text
            raw_json = None
            try:
                raw_json = resp.json()
            except Exception:
                raw_json = None

            res = self._parse_response(
                proto=proto,
                status_code=resp.status_code,
                raw_json=raw_json,
                raw_text=raw_text,
                headers=norm_headers,
                latency_ms=elapsed,
                url=url,
            )
            self._record_telemetry(res)
            return res
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000.0
            res = CompletionResult(
                ok=False,
                status_code=0,
                error=f"{type(exc).__name__}: {exc}",
                latency_ms=elapsed,
                url=url,
                protocol_used=proto,
            )
            self._record_telemetry(res)
            return res

    def _post_stream(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        proto: str,
        t0: float,
    ) -> CompletionResult:
        sse_events: list[str] = []
        text_parts: list[str] = []
        thinking_parts: list[str] = []
        sig_parts: list[str] = []
        raw_lines: list[str] = []
        chunk_times_ms: list[float] = []
        ttft_ms: float | None = None
        returned_model = ""
        response_id = ""
        system_fp = ""
        finish_reason = ""
        in_tok = out_tok = reas_tok = cc_tok = cr_tok = 0

        try:
            with self._http.stream("POST", url, headers=headers, json=payload) as resp:
                norm_headers = {k.lower(): v for k, v in resp.headers.items()}
                status = resp.status_code
                if status >= 400:
                    body = resp.read().decode("utf-8", errors="replace")
                    elapsed = (time.perf_counter() - t0) * 1000.0
                    raw_json = None
                    try:
                        raw_json = json.loads(body)
                    except Exception:
                        pass
                    res = self._parse_response(
                        proto=proto,
                        status_code=status,
                        raw_json=raw_json,
                        raw_text=body,
                        headers=norm_headers,
                        latency_ms=elapsed,
                        url=url,
                    )
                    self._record_telemetry(res)
                    return res

                current_event = ""
                for line in resp.iter_lines():
                    if not line:
                        continue
                    if len(raw_lines) < 40:
                        raw_lines.append(line)
                    if line.startswith("event:"):
                        current_event = line[6:].strip()
                        sse_events.append(current_event)
                        continue
                    if not line.startswith("data:"):
                        continue
                    data_str = line[5:].strip()
                    if data_str == "[DONE]":
                        sse_events.append("[DONE]")
                        break
                    try:
                        evt = json.loads(data_str)
                    except Exception:
                        continue

                    now_ms = (time.perf_counter() - t0) * 1000.0
                    if ttft_ms is None:
                        ttft_ms = now_ms

                    got_content_chunk = False
                    if proto == "openai_chat":
                        if not response_id and evt.get("id"):
                            response_id = str(evt["id"])
                        if not returned_model and evt.get("model"):
                            returned_model = str(evt["model"])
                        if not system_fp and evt.get("system_fingerprint"):
                            system_fp = str(evt["system_fingerprint"])
                        if not current_event:
                            sse_events.append(str(evt.get("object", "chunk")))
                        for ch in evt.get("choices") or []:
                            delta = ch.get("delta") or {}
                            if delta.get("content"):
                                text_parts.append(str(delta["content"]))
                                got_content_chunk = True
                            if delta.get("reasoning_content"):
                                thinking_parts.append(str(delta["reasoning_content"]))
                                got_content_chunk = True
                            if ch.get("finish_reason"):
                                finish_reason = str(ch["finish_reason"])
                        usage = evt.get("usage")
                        if isinstance(usage, dict):
                            in_tok = int(usage.get("prompt_tokens") or in_tok)
                            out_tok = int(usage.get("completion_tokens") or out_tok)
                            cd = usage.get("completion_tokens_details") or {}
                            if isinstance(cd, dict) and cd.get("reasoning_tokens"):
                                reas_tok = int(cd["reasoning_tokens"])
                            pd = usage.get("prompt_tokens_details") or {}
                            if isinstance(pd, dict) and pd.get("cached_tokens"):
                                cr_tok = int(pd["cached_tokens"])

                    elif proto == "anthropic":
                        etype = evt.get("type", current_event)
                        if etype == "message_start":
                            msg = evt.get("message") or {}
                            response_id = str(msg.get("id") or response_id)
                            returned_model = str(msg.get("model") or returned_model)
                            u = msg.get("usage") or {}
                            in_tok = int(u.get("input_tokens") or in_tok)
                            cc_tok = int(u.get("cache_creation_input_tokens") or cc_tok)
                            cr_tok = int(u.get("cache_read_input_tokens") or cr_tok)
                        elif etype == "content_block_delta":
                            delta = evt.get("delta") or {}
                            dt = delta.get("type", "")
                            if dt == "text_delta":
                                text_parts.append(str(delta.get("text", "")))
                                got_content_chunk = True
                            elif dt == "thinking_delta":
                                thinking_parts.append(str(delta.get("thinking", "")))
                                got_content_chunk = True
                            elif dt == "signature_delta":
                                sig_parts.append(str(delta.get("signature", "")))
                        elif etype == "message_delta":
                            d = evt.get("delta") or {}
                            if d.get("stop_reason"):
                                finish_reason = str(d["stop_reason"])
                            u = evt.get("usage") or {}
                            if u.get("output_tokens"):
                                out_tok = int(u["output_tokens"])

                    elif proto == "gemini":
                        sse_events.append("gemini_chunk")
                        if evt.get("modelVersion"):
                            returned_model = str(evt["modelVersion"])
                        for cand in evt.get("candidates") or []:
                            parts = ((cand.get("content") or {}).get("parts")) or []
                            for p in parts:
                                if p.get("thought"):
                                    thinking_parts.append(str(p.get("text", "")))
                                    got_content_chunk = True
                                elif p.get("text"):
                                    text_parts.append(str(p["text"]))
                                    got_content_chunk = True
                                if p.get("thoughtSignature"):
                                    sig_parts.append(str(p["thoughtSignature"]))
                            if cand.get("finishReason"):
                                finish_reason = str(cand["finishReason"])
                        um = evt.get("usageMetadata") or {}
                        if um:
                            in_tok = int(um.get("promptTokenCount") or in_tok)
                            out_tok = int(um.get("candidatesTokenCount") or out_tok)
                            reas_tok = int(um.get("thoughtsTokenCount") or reas_tok)

                    if got_content_chunk:
                        chunk_times_ms.append(now_ms)

                elapsed = (time.perf_counter() - t0) * 1000.0
                full_text = "".join(text_parts)
                full_think = "".join(thinking_parts)

                # Compute SSE micro-timing & fake-stream indicators
                itls = [
                    max(0.0, chunk_times_ms[i] - chunk_times_ms[i - 1])
                    for i in range(1, len(chunk_times_ms))
                ]
                sorted_itls = sorted(itls)
                gen_ms = max(1.0, (chunk_times_ms[-1] - chunk_times_ms[0])) if len(chunk_times_ms) >= 2 else max(1.0, elapsed - (ttft_ms or 0.0))
                est_tokens = out_tok if out_tok > 0 else max(len(chunk_times_ms), (len(full_text) + len(full_think)) // 4)
                eff_tps = round(est_tokens / max(0.02, gen_ms / 1000.0), 1) if est_tokens > 0 else 0.0
                burst_ratio = round(sum(1 for d in itls if d < 2.0) / len(itls), 3) if itls else 0.0
                itl_mean = round(sum(itls) / len(itls), 2) if itls else 0.0
                itl_p50 = round(sorted_itls[len(sorted_itls) // 2], 2) if sorted_itls else 0.0
                itl_p95 = round(sorted_itls[min(len(sorted_itls) - 1, int(len(sorted_itls) * 0.95))], 2) if sorted_itls else 0.0
                fake_stream = (
                    len(chunk_times_ms) >= 12
                    and (ttft_ms or 0.0) >= 600.0
                    and gen_ms <= max(75.0, (ttft_ms or 0.0) * 0.06)
                    and burst_ratio >= 0.80
                )
                stream_metrics = {
                    "chunk_count": len(chunk_times_ms),
                    "ttft_ms": round(ttft_ms, 1) if ttft_ms is not None else None,
                    "generation_ms": round(gen_ms, 1),
                    "total_ms": round(elapsed, 1),
                    "effective_tps": eff_tps,
                    "itl_mean_ms": itl_mean,
                    "itl_p50_ms": itl_p50,
                    "itl_p95_ms": itl_p95,
                    "burst_ratio": burst_ratio,
                    "fake_stream_suspected": fake_stream,
                    "chunk_timeline_sample_ms": [round(x - chunk_times_ms[0], 1) for x in chunk_times_ms[:48]] if chunk_times_ms else [],
                }

                res = CompletionResult(
                    ok=True,
                    status_code=status,
                    text=full_text,
                    thinking=full_think,
                    thinking_signature="".join(sig_parts),
                    raw_text="\n".join(raw_lines),
                    sse_events=sse_events[:120],
                    headers=norm_headers,
                    latency_ms=elapsed,
                    ttft_ms=ttft_ms,
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                    reasoning_tokens=reas_tok,
                    cache_creation_tokens=cc_tok,
                    cache_read_tokens=cr_tok,
                    returned_model=returned_model,
                    response_id=response_id,
                    system_fingerprint=system_fp,
                    finish_reason=finish_reason,
                    url=url,
                    protocol_used=proto,
                    stream_metrics=stream_metrics,
                )
                self._record_telemetry(res)
                return res
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000.0
            res = CompletionResult(
                ok=False,
                status_code=0,
                error=f"{type(exc).__name__}: {exc}",
                latency_ms=elapsed,
                ttft_ms=ttft_ms,
                url=url,
                protocol_used=proto,
            )
            self._record_telemetry(res)
            return res

    def _parse_response(
        self,
        proto: str,
        status_code: int,
        raw_json: dict[str, Any] | None,
        raw_text: str,
        headers: dict[str, str],
        latency_ms: float,
        url: str,
    ) -> CompletionResult:
        res = CompletionResult(
            ok=200 <= status_code < 300 and isinstance(raw_json, dict),
            status_code=status_code,
            raw_json=raw_json,
            raw_text=raw_text,
            headers=headers,
            latency_ms=latency_ms,
            url=url,
            protocol_used=proto,
        )

        if not isinstance(raw_json, dict):
            res.ok = False
            res.error = f"HTTP {status_code}: non-JSON response: {raw_text[:240]}"
            return res

        if status_code >= 400 or "error" in raw_json and raw_json["error"]:
            res.ok = False
            err = raw_json.get("error")
            if isinstance(err, dict):
                res.error = f"HTTP {status_code}: {err.get('type', '')} {err.get('message', raw_text[:200])}".strip()
            else:
                res.error = f"HTTP {status_code}: {str(err or raw_text)[:240]}"
            return res

        if proto == "openai_chat":
            res.response_id = str(raw_json.get("id") or "")
            res.returned_model = str(raw_json.get("model") or "")
            res.system_fingerprint = str(raw_json.get("system_fingerprint") or "")
            res.service_tier = str(raw_json.get("service_tier") or "")
            choices = raw_json.get("choices") or []
            if choices and isinstance(choices[0], dict):
                ch = choices[0]
                res.finish_reason = str(ch.get("finish_reason") or "")
                msg = ch.get("message") or {}
                content = msg.get("content")
                if isinstance(content, str):
                    res.text = content
                elif isinstance(content, list):
                    res.text = "".join(
                        str(p.get("text", "")) for p in content if isinstance(p, dict)
                    )
                if msg.get("reasoning_content"):
                    res.thinking = str(msg["reasoning_content"])
                elif msg.get("reasoning"):
                    res.thinking = str(msg["reasoning"])
                if isinstance(msg.get("tool_calls"), list):
                    res.tool_calls = msg["tool_calls"]
                lp = ch.get("logprobs")
                if isinstance(lp, dict) and isinstance(lp.get("content"), list):
                    res.logprobs = lp["content"]
            usage = raw_json.get("usage") or {}
            if isinstance(usage, dict):
                res.input_tokens = int(usage.get("prompt_tokens") or 0)
                res.output_tokens = int(usage.get("completion_tokens") or 0)
                cd = usage.get("completion_tokens_details") or {}
                if isinstance(cd, dict):
                    res.reasoning_tokens = int(cd.get("reasoning_tokens") or 0)
                pd = usage.get("prompt_tokens_details") or {}
                if isinstance(pd, dict):
                    res.cache_read_tokens = int(pd.get("cached_tokens") or 0)

        elif proto == "openai_responses":
            res.response_id = str(raw_json.get("id") or "")
            res.returned_model = str(raw_json.get("model") or "")
            res.service_tier = str(raw_json.get("service_tier") or "")
            text_parts: list[str] = []
            for item in raw_json.get("output") or []:
                itype = item.get("type")
                if itype == "message":
                    for c in item.get("content") or []:
                        if c.get("type") in ("output_text", "text"):
                            text_parts.append(str(c.get("text", "")))
                elif itype == "reasoning":
                    if item.get("encrypted_content"):
                        res.thinking_signature = str(item["encrypted_content"])
                    for s in item.get("summary") or []:
                        res.thinking += str(s.get("text", ""))
                elif itype == "function_call":
                    res.tool_calls.append(item)
            res.text = "".join(text_parts) or str(raw_json.get("output_text") or "")
            usage = raw_json.get("usage") or {}
            res.input_tokens = int(usage.get("input_tokens") or 0)
            res.output_tokens = int(usage.get("output_tokens") or 0)
            od = usage.get("output_tokens_details") or {}
            if isinstance(od, dict):
                res.reasoning_tokens = int(od.get("reasoning_tokens") or 0)

        elif proto == "anthropic":
            res.response_id = str(raw_json.get("id") or "")
            res.returned_model = str(raw_json.get("model") or "")
            res.finish_reason = str(raw_json.get("stop_reason") or "")
            text_parts = []
            thinking_parts = []
            for blk in raw_json.get("content") or []:
                if not isinstance(blk, dict):
                    continue
                btype = blk.get("type")
                if btype == "text":
                    text_parts.append(str(blk.get("text", "")))
                elif btype == "thinking":
                    thinking_parts.append(str(blk.get("thinking", "")))
                    if blk.get("signature"):
                        res.thinking_signature = str(blk["signature"])
                elif btype == "redacted_thinking":
                    if blk.get("data"):
                        res.thinking_signature = str(blk["data"])
                elif btype == "tool_use":
                    res.tool_calls.append(blk)
            res.text = "".join(text_parts)
            res.thinking = "".join(thinking_parts)
            usage = raw_json.get("usage") or {}
            if isinstance(usage, dict):
                res.input_tokens = int(usage.get("input_tokens") or 0)
                res.output_tokens = int(usage.get("output_tokens") or 0)
                res.cache_creation_tokens = int(usage.get("cache_creation_input_tokens") or 0)
                res.cache_read_tokens = int(usage.get("cache_read_input_tokens") or 0)

        elif proto == "gemini":
            res.returned_model = str(raw_json.get("modelVersion") or "")
            res.response_id = str(raw_json.get("responseId") or "")
            cands = raw_json.get("candidates") or []
            if cands and isinstance(cands[0], dict):
                cand = cands[0]
                res.finish_reason = str(cand.get("finishReason") or "")
                parts = ((cand.get("content") or {}).get("parts")) or []
                text_parts = []
                thinking_parts = []
                for p in parts:
                    if not isinstance(p, dict):
                        continue
                    if p.get("thought"):
                        thinking_parts.append(str(p.get("text", "")))
                    elif "text" in p:
                        text_parts.append(str(p["text"]))
                    elif "functionCall" in p:
                        res.tool_calls.append(p["functionCall"])
                    if p.get("thoughtSignature"):
                        res.thinking_signature = str(p["thoughtSignature"])
                res.text = "".join(text_parts)
                res.thinking = "".join(thinking_parts)
            um = raw_json.get("usageMetadata") or {}
            if isinstance(um, dict):
                res.input_tokens = int(um.get("promptTokenCount") or 0)
                res.output_tokens = int(um.get("candidatesTokenCount") or 0)
                res.reasoning_tokens = int(um.get("thoughtsTokenCount") or 0)
                res.cache_read_tokens = int(um.get("cachedContentTokenCount") or 0)

        return res

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str | None = None,
        max_tokens: int = 256,
        temperature: float | None = None,
        seed: int | None = None,
        logprobs: bool = False,
        top_logprobs: int | None = None,
        stream: bool = False,
        stop: list[str] | None = None,
        tools: list[dict[str, Any]] | None = None,
        extra_body: dict[str, Any] | None = None,
        protocol: str | None = None,
    ) -> CompletionResult:
        """High-level normalized chat call that translates cleanly across all protocols."""
        proto = protocol or self.protocol
        if proto == "auto":
            proto = "openai_chat"

        if proto == "openai_chat":
            msgs = []
            if system:
                msgs.append({"role": "system", "content": system})
            msgs.extend(messages)
            payload: dict[str, Any] = {"model": self.config.model, "messages": msgs}
            if self._prefer_max_completion_tokens:
                payload["max_completion_tokens"] = max_tokens
            else:
                payload["max_tokens"] = max_tokens
            if temperature is not None and not self._rejects_custom_temperature:
                payload["temperature"] = temperature
            if seed is not None:
                payload["seed"] = seed
            if logprobs:
                payload["logprobs"] = True
                if top_logprobs is not None:
                    payload["top_logprobs"] = top_logprobs
            if stream:
                payload["stream"] = True
                payload["stream_options"] = {"include_usage": True}
            if stop:
                payload["stop"] = stop
            if tools:
                payload["tools"] = tools
            if extra_body:
                payload.update(extra_body)

            res = self.raw_post(payload, protocol=proto, stream=stream)
            # Transparent retry for reasoning models that require max_completion_tokens / default temp
            if not res.ok and res.status_code == 400:
                err_low = (res.error or res.raw_text or "").lower()
                retry_needed = False
                if "max_completion_tokens" in err_low and "max_tokens" in payload:
                    self._prefer_max_completion_tokens = True
                    payload["max_completion_tokens"] = payload.pop("max_tokens")
                    retry_needed = True
                if "temperature" in err_low and "temperature" in payload:
                    self._rejects_custom_temperature = True
                    payload.pop("temperature", None)
                    retry_needed = True
                if "stream_options" in err_low and "stream_options" in payload:
                    payload.pop("stream_options", None)
                    retry_needed = True
                if retry_needed:
                    return self.raw_post(payload, protocol=proto, stream=stream)
            return res

        if proto == "openai_responses":
            inp = []
            if system:
                inp.append({"role": "developer", "content": system})
            inp.extend(messages)
            payload = {
                "model": self.config.model,
                "input": inp,
                "max_output_tokens": max_tokens,
            }
            if temperature is not None and not self._rejects_custom_temperature:
                payload["temperature"] = temperature
            if tools:
                payload["tools"] = tools
            if extra_body:
                payload.update(extra_body)
            return self.raw_post(payload, protocol=proto, stream=False)

        if proto == "anthropic":
            payload = {
                "model": self.config.model,
                "max_tokens": max_tokens,
                "messages": messages,
            }
            if system:
                payload["system"] = system
            if temperature is not None:
                payload["temperature"] = temperature
            if stream:
                payload["stream"] = True
            if stop:
                payload["stop_sequences"] = stop
            if tools:
                payload["tools"] = tools
            if extra_body:
                payload.update(extra_body)
            return self.raw_post(payload, protocol=proto, stream=stream)

        if proto == "gemini":
            contents = []
            for m in messages:
                role = "model" if m.get("role") == "assistant" else "user"
                c = m.get("content")
                if isinstance(c, str):
                    parts = [{"text": c}]
                elif isinstance(c, list):
                    parts = c
                else:
                    parts = [{"text": str(c)}]
                contents.append({"role": role, "parts": parts})
            gen_cfg: dict[str, Any] = {"maxOutputTokens": max_tokens}
            if temperature is not None:
                gen_cfg["temperature"] = temperature
            if stop:
                gen_cfg["stopSequences"] = stop
            payload = {"contents": contents, "generationConfig": gen_cfg}
            if system:
                payload["systemInstruction"] = {"parts": [{"text": system}]}
            if tools:
                payload["tools"] = tools
            if extra_body:
                payload.update(extra_body)
            return self.raw_post(payload, protocol=proto, stream=stream)

        return CompletionResult(ok=False, status_code=0, error=f"Unsupported protocol: {proto}")

    def list_models(self) -> tuple[int, list[str], dict[str, Any]]:
        """Probe /v1/models (best-effort; many relays disable or customize this)."""
        url = build_models_url(self.base_url)
        headers = self._base_headers(self.protocol if self.protocol != "auto" else "openai_chat")
        try:
            resp = self._http.get(url, headers=headers, timeout=12.0)
            data = resp.json() if resp.text else {}
            ids: list[str] = []
            if isinstance(data, dict) and isinstance(data.get("data"), list):
                ids = [str(x.get("id", "")) for x in data["data"] if isinstance(x, dict) and x.get("id")]
            return resp.status_code, ids, {"url": url, "count": len(ids)}
        except Exception as exc:
            return 0, [], {"url": url, "error": str(exc)}
