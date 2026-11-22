"""Local Transparent Passive Audit Proxy (v11.0).

Sits transparently on 127.0.0.1:<port> between your real IDE/Agent client
(Cursor, Claude Code, Cline, Cherry Studio, OpenAI/Anthropic SDK) and your
API relay. Forwards requests & SSE streams in real time with ZERO extra token
cost while passively monitoring:
- Exact TTFT, total latency, and effective tokens/sec
- Requested model vs returned model mismatch
- Mid-session silent backend swaps (system_fingerprint, response_id prefix, cf-ray PoP)
- Open-source `<think>` tag leaks
- Cumulative official-reference USD/CNY spend
"""

from __future__ import annotations

import json
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import httpx

from .net_forensics import analyze_network_headers
from .pricing import estimate_audit_cost


def _id_prefix(rid: str) -> str:
    if not rid:
        return ""
    for sep in ("_", "-"):
        if sep in rid:
            head = rid.split(sep, 1)[0]
            if len(head) <= 16:
                return head + sep
    return rid[:8]


def _pick_port(preferred: int) -> int:
    if preferred and preferred > 0:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", preferred))
                return preferred
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class PassiveAuditProxy:
    """Thread-safe local reverse proxy with passive forensic telemetry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.running = False
        self.listen_port = 0
        self.upstream_base_url = ""
        self.proxy_url = ""
        self.verify_ssl = True
        self.started_at = ""
        self.records: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self._anchors: dict[str, dict[str, str]] = {}  # requested_model -> {ret_model, id_prefix, sys_fp, pop}
        self._totals: dict[str, Any] = {
            "requests": 0,
            "errors": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "reasoning_tokens": 0,
            "cache_read_tokens": 0,
            "estimated_usd": 0.0,
            "estimated_cny": 0.0,
        }

    def start(
        self,
        upstream_base_url: str,
        *,
        port: int = 8899,
        proxy_url: str = "",
        verify_ssl: bool = True,
    ) -> dict[str, Any]:
        self.stop()
        clean_up = (upstream_base_url or "").strip().rstrip("/")
        if not clean_up:
            raise ValueError("upstream_base_url 不能为空")
        if not clean_up.startswith(("http://", "https://")):
            clean_up = "https://" + clean_up

        # Strip trailing /v1 if caller pasted .../v1 so incoming /v1/chat/completions won't double /v1/v1!
        # Wait: keep base normalized cleanly in _build_target_url
        actual_port = _pick_port(int(port or 0))
        handler_cls = self._make_handler()
        srv = ThreadingHTTPServer(("127.0.0.1", actual_port), handler_cls)
        srv.daemon_threads = True

        with self._lock:
            self._server = srv
            self.running = True
            self.listen_port = actual_port
            self.upstream_base_url = clean_up
            self.proxy_url = (proxy_url or "").strip()
            self.verify_ssl = bool(verify_ssl)
            self.started_at = datetime.now(timezone.utc).isoformat()

        t = threading.Thread(target=srv.serve_forever, name=f"passive-proxy-{actual_port}", daemon=True)
        t.start()
        self._thread = t
        return self.status()

    def stop(self) -> dict[str, Any]:
        srv = self._server
        with self._lock:
            self._server = None
            self.running = False
        if srv is not None:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        return self.status()

    def clear(self) -> dict[str, Any]:
        with self._lock:
            self.records = []
            self.alerts = []
            self._anchors = {}
            self._totals = {
                "requests": 0,
                "errors": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "cache_read_tokens": 0,
                "estimated_usd": 0.0,
                "estimated_cny": 0.0,
            }
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.running,
                "listen_url": f"http://127.0.0.1:{self.listen_port}" if self.running else "",
                "listen_port": self.listen_port,
                "upstream_base_url": self.upstream_base_url,
                "started_at": self.started_at,
                "totals": dict(self._totals),
                "anchors": dict(self._anchors),
                "alerts": list(self.alerts[-50:]),
                "records": list(self.records[-120:]),
            }

    def _build_target_url(self, req_path: str) -> str:
        up = self.upstream_base_url.rstrip("/")
        path = req_path if req_path.startswith("/") else "/" + req_path
        # Avoid /v1/v1 duplication when upstream already ends with /v1 and client also calls /v1/...
        if up.endswith("/v1") and path.startswith("/v1/"):
            return up[:-3] + path
        return up + path

    def _record_event(self, rec: dict[str, Any]) -> None:
        req_m = rec.get("requested_model") or "unknown"
        ret_m = rec.get("returned_model") or ""
        sys_fp = rec.get("system_fingerprint") or ""
        id_pref = rec.get("id_prefix") or ""
        pop = rec.get("edge_pop") or ""
        tps = float(rec.get("effective_tps") or 0.0)
        ts = rec.get("timestamp") or datetime.now(timezone.utc).isoformat()

        rec_alerts: list[str] = []
        if rec.get("think_leak"):
            rec_alerts.append("真实流量正文泄露 `<think>` 开源推理标签！")
        if req_m != "unknown" and ret_m and req_m.lower() not in ret_m.lower() and ret_m.lower() not in req_m.lower():
            rec_alerts.append(f"模型名不一致：请求 `{req_m}`，上游返回 `{ret_m}`")
        if ("opus" in req_m.lower() or "o1" in req_m.lower()) and tps >= 155.0:
            rec_alerts.append(f"吞吐异常偏高 ({tps:.1f} tok/s)，疑似高峰偷换轻量模型！")

        cost = estimate_audit_cost(
            req_m if req_m != "unknown" else ret_m,
            {
                "input_tokens": rec.get("input_tokens", 0),
                "output_tokens": rec.get("output_tokens", 0),
                "cache_read_tokens": rec.get("cache_read_tokens", 0),
            },
        )
        rec["estimated_usd"] = cost["estimated_usd"]
        rec["estimated_cny"] = cost["estimated_cny"]

        with self._lock:
            self._totals["requests"] += 1
            if not rec.get("ok"):
                self._totals["errors"] += 1
            self._totals["input_tokens"] += int(rec.get("input_tokens") or 0)
            self._totals["output_tokens"] += int(rec.get("output_tokens") or 0)
            self._totals["reasoning_tokens"] += int(rec.get("reasoning_tokens") or 0)
            self._totals["cache_read_tokens"] += int(rec.get("cache_read_tokens") or 0)
            self._totals["estimated_usd"] = round(self._totals["estimated_usd"] + cost["estimated_usd"], 5)
            self._totals["estimated_cny"] = round(self._totals["estimated_cny"] + cost["estimated_cny"], 4)

            if rec.get("ok") and req_m != "unknown":
                anc = self._anchors.setdefault(req_m, {})
                if ret_m:
                    if anc.get("ret_model") and anc["ret_model"] != ret_m:
                        rec_alerts.append(f"[{req_m}] 会话中途返回模型跳变：`{anc['ret_model']}` -> `{ret_m}`")
                    else:
                        anc["ret_model"] = ret_m
                if id_pref:
                    if anc.get("id_prefix") and anc["id_prefix"] != id_pref:
                        rec_alerts.append(f"[{req_m}] 响应 ID 前缀漂移：`{anc['id_prefix']}` -> `{id_pref}`（疑似切上游！）")
                    else:
                        anc["id_prefix"] = id_pref
                if sys_fp:
                    if anc.get("sys_fp") and anc["sys_fp"] != sys_fp:
                        rec_alerts.append(f"[{req_m}] system_fingerprint 跳变：`{anc['sys_fp']}` -> `{sys_fp}`")
                    else:
                        anc["sys_fp"] = sys_fp
                if pop:
                    if anc.get("pop") and anc["pop"] != pop:
                        rec_alerts.append(f"[{req_m}] 出口机房节点切换：`{anc['pop']}` -> `{pop}`")
                    else:
                        anc["pop"] = pop

            rec["alerts"] = rec_alerts
            self.records.append(rec)
            if len(self.records) > 200:
                self.records = self.records[-200:]
            for a in rec_alerts:
                self.alerts.append({"timestamp": ts, "model": req_m, "message": a})
            if len(self.alerts) > 100:
                self.alerts = self.alerts[-100:]

    def _make_handler(self):
        proxy = self

        class ProxyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:
                pass

            def _forward(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length) if length > 0 else b""

                req_json: dict[str, Any] = {}
                if body:
                    try:
                        parsed = json.loads(body.decode("utf-8"))
                        if isinstance(parsed, dict):
                            req_json = parsed
                    except Exception:
                        pass

                requested_model = str(req_json.get("model") or "")
                want_stream = bool(req_json.get("stream"))
                target_url = proxy._build_target_url(self.path)

                # Forward safe client headers (including caller's own Auth key in transit only)
                hop_by_hop = {
                    "host", "connection", "keep-alive", "proxy-authenticate",
                    "proxy-authorization", "te", "trailers", "transfer-encoding",
                    "upgrade", "content-length", "accept-encoding",
                }
                fwd_headers: dict[str, str] = {}
                for k, v in self.headers.items():
                    if k.lower() not in hop_by_hop:
                        fwd_headers[k] = v

                t0 = time.perf_counter()
                ttft_ms: float | None = None
                ret_model = ""
                resp_id = ""
                sys_fp = ""
                in_tok = out_tok = reas_tok = cr_tok = 0
                think_leak = False
                chunk_cnt = 0
                status_code = 502
                resp_hdrs_norm: dict[str, str] = {}
                err_msg = ""

                client_kwargs: dict[str, Any] = {
                    "timeout": httpx.Timeout(120.0, connect=20.0),
                    "verify": proxy.verify_ssl,
                    "follow_redirects": True,
                }
                if proxy.proxy_url:
                    client_kwargs["proxy"] = proxy.proxy_url

                try:
                    with httpx.Client(**client_kwargs) as hc:
                        with hc.stream(method, target_url, headers=fwd_headers, content=body if body else None) as upstream:
                            status_code = upstream.status_code
                            resp_hdrs_norm = {k.lower(): v for k, v in upstream.headers.items()}
                            ctype = upstream.headers.get("content-type", "application/json")
                            is_sse = "text/event-stream" in ctype.lower() or want_stream

                            if is_sse and status_code == 200:
                                self.send_response(status_code)
                                self.send_header("Content-Type", ctype)
                                self.send_header("Cache-Control", "no-cache")
                                self.send_header("Connection", "close")
                                self.close_connection = True
                                self.end_headers()

                                line_buf = ""
                                for raw_chunk in upstream.iter_bytes():
                                    if not raw_chunk:
                                        continue
                                    if ttft_ms is None:
                                        ttft_ms = (time.perf_counter() - t0) * 1000.0
                                    try:
                                        self.wfile.write(raw_chunk)
                                        self.wfile.flush()
                                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                                        break
                                    # Passively inspect SSE lines without blocking forwarding
                                    line_buf += raw_chunk.decode("utf-8", errors="ignore")
                                    while "\n" in line_buf:
                                        ln, line_buf = line_buf.split("\n", 1)
                                        ln = ln.strip()
                                        if not ln.startswith("data:"):
                                            continue
                                        ds = ln[5:].strip()
                                        if not ds or ds == "[DONE]":
                                            continue
                                        try:
                                            ev = json.loads(ds)
                                        except Exception:
                                            continue
                                        if not isinstance(ev, dict):
                                            continue
                                        chunk_cnt += 1
                                        if not ret_model and ev.get("model"):
                                            ret_model = str(ev["model"])
                                        if not resp_id and ev.get("id"):
                                            resp_id = str(ev["id"])
                                        if not sys_fp and ev.get("system_fingerprint"):
                                            sys_fp = str(ev["system_fingerprint"])
                                        # Check OpenAI delta / Anthropic delta / usage
                                        for ch in ev.get("choices") or []:
                                            d = (ch.get("delta") or {}) if isinstance(ch, dict) else {}
                                            if "<think>" in str(d.get("content") or ""):
                                                think_leak = True
                                        if ev.get("type") == "message_start":
                                            msg = ev.get("message") or {}
                                            ret_model = str(msg.get("model") or ret_model)
                                            resp_id = str(msg.get("id") or resp_id)
                                            u = msg.get("usage") or {}
                                            in_tok = int(u.get("input_tokens") or in_tok)
                                            cr_tok = int(u.get("cache_read_input_tokens") or cr_tok)
                                        elif ev.get("type") == "content_block_delta":
                                            d = ev.get("delta") or {}
                                            if "<think>" in str(d.get("text") or ""):
                                                think_leak = True
                                        elif ev.get("type") == "message_delta":
                                            u = ev.get("usage") or {}
                                            out_tok = int(u.get("output_tokens") or out_tok)
                                        usage = ev.get("usage")
                                        if isinstance(usage, dict):
                                            in_tok = int(usage.get("prompt_tokens") or usage.get("input_tokens") or in_tok)
                                            out_tok = int(usage.get("completion_tokens") or usage.get("output_tokens") or out_tok)
                                            cd = usage.get("completion_tokens_details") or {}
                                            if isinstance(cd, dict) and cd.get("reasoning_tokens"):
                                                reas_tok = int(cd["reasoning_tokens"])
                                            pd = usage.get("prompt_tokens_details") or {}
                                            if isinstance(pd, dict) and pd.get("cached_tokens"):
                                                cr_tok = int(pd["cached_tokens"])
                            else:
                                raw_resp = upstream.read()
                                ttft_ms = (time.perf_counter() - t0) * 1000.0
                                self.send_response(status_code)
                                self.send_header("Content-Type", ctype)
                                self.send_header("Content-Length", str(len(raw_resp)))
                                self.send_header("Connection", "close")
                                self.close_connection = True
                                self.end_headers()
                                self.wfile.write(raw_resp)

                                try:
                                    rj = json.loads(raw_resp.decode("utf-8", errors="ignore"))
                                except Exception:
                                    rj = None
                                if isinstance(rj, dict):
                                    ret_model = str(rj.get("model") or rj.get("modelVersion") or "")
                                    resp_id = str(rj.get("id") or "")
                                    sys_fp = str(rj.get("system_fingerprint") or "")
                                    u = rj.get("usage") or {}
                                    if isinstance(u, dict):
                                        in_tok = int(u.get("prompt_tokens") or u.get("input_tokens") or 0)
                                        out_tok = int(u.get("completion_tokens") or u.get("output_tokens") or 0)
                                        cd = u.get("completion_tokens_details") or {}
                                        if isinstance(cd, dict):
                                            reas_tok = int(cd.get("reasoning_tokens") or 0)
                                        pd = u.get("prompt_tokens_details") or {}
                                        if isinstance(pd, dict):
                                            cr_tok = int(pd.get("cached_tokens") or 0)
                                        cr_tok = int(u.get("cache_read_input_tokens") or cr_tok)
                                    # Scan text for <think> leak
                                    raw_s = raw_resp[:8000].decode("utf-8", errors="ignore")
                                    if "<think>" in raw_s:
                                        think_leak = True
                except Exception as exc:
                    err_msg = f"{type(exc).__name__}: {exc}"
                    err_body = json.dumps({"error": {"message": f"LLM-TruthLab Proxy upstream error: {err_msg}"}}).encode("utf-8")
                    try:
                        self.send_response(502)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(err_body)))
                        self.send_header("Connection", "close")
                        self.close_connection = True
                        self.end_headers()
                        self.wfile.write(err_body)
                    except Exception:
                        pass

                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                gen_s = max(0.05, (elapsed_ms - (ttft_ms or 0.0)) / 1000.0)
                eff_tps = round((out_tok or chunk_cnt) / gen_s, 1) if (out_tok or chunk_cnt) > 0 else 0.0
                net = analyze_network_headers(resp_hdrs_norm)

                proxy._record_event(
                    {
                        "id": f"px_{uuid.uuid4().hex[:8]}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "method": method,
                        "path": urlsplit(self.path).path,
                        "status_code": status_code,
                        "ok": 200 <= status_code < 300,
                        "stream": want_stream,
                        "requested_model": requested_model or "unknown",
                        "returned_model": ret_model,
                        "id_prefix": _id_prefix(resp_id),
                        "system_fingerprint": sys_fp,
                        "edge_pop": net.get("edge_pop") or "",
                        "edge_region": net.get("edge_region") or "",
                        "gateway_stack": net.get("gateway_stack") or [],
                        "latency_ms": round(elapsed_ms, 1),
                        "ttft_ms": round(ttft_ms, 1) if ttft_ms is not None else None,
                        "effective_tps": eff_tps,
                        "input_tokens": in_tok,
                        "output_tokens": out_tok,
                        "reasoning_tokens": reas_tok,
                        "cache_read_tokens": cr_tok,
                        "think_leak": think_leak,
                        "error": err_msg[:180],
                    }
                )

            def do_POST(self) -> None:
                self._forward("POST")

            def do_GET(self) -> None:
                self._forward("GET")

        return ProxyHandler
