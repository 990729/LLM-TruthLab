"""LLM-TruthLab v2.0 Desktop Application & CLI Entrypoint.

Features:
- Single-Endpoint Zero-Trust Audit (L1 Crypto/Protocol, Tokenizer, JSD, Cutoff, Context Cliff, 8-Dim IQ)
- A/B Dual-Endpoint Arena & Same-Relay Alias Fraud Detector
- Continuous Canary Monitor (Intermittent Mixing & Peak-Hour Degradation Watcher)
- Local Baseline Fingerprint Library & Local Audit History Vault
- Headless --cli mode for automation
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from audit_engine import __version__
from audit_engine.arena import run_ab_arena
from audit_engine.baselines import BaselineStore
from audit_engine.batch import run_batch_leaderboard
from audit_engine.client import RelayClient
from audit_engine.demo_sandbox import run_demo_sandbox_audit
from audit_engine.history import HistoryStore, compare_history_reports
from audit_engine.models import AuditConfig, AuditReport
from audit_engine.monitor import CanaryMonitor, send_webhook_alert
from audit_engine.proxy_server import PassiveAuditProxy
from audit_engine.runner import run_full_audit
from audit_engine.verdict import (
    anonymize_report_dict,
    render_arena_html,
    render_batch_html,
    render_html_report,
)


def _configure_safe_stdio() -> None:
    """Prevent UnicodeEncodeError (cp936/GBK) or NoneType stdout crashes in --windowed PyInstaller EXEs."""
    for stream_name in ("stdout", "stderr"):
        st = getattr(sys, stream_name, None)
        if st is None:
            try:
                setattr(sys, stream_name, open(os.devnull, "w", encoding="utf-8", errors="replace"))
            except Exception:
                pass
        elif hasattr(st, "reconfigure"):
            try:
                st.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _safe_print(*args: Any, **kwargs: Any) -> None:
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        msg = " ".join(str(a) for a in args)
        try:
            sys.stdout.write(msg.encode("ascii", errors="replace").decode("ascii") + "\n")
            sys.stdout.flush()
        except Exception:
            pass
    except Exception:
        pass


_configure_safe_stdio()


def _resource_path(rel_path: str) -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / rel_path  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent / rel_path


class AsyncJob:
    """Generic thread-safe SSE job supporting both Single Audit and A/B Arena."""

    def __init__(self, job_id: str, kind: str) -> None:
        self.job_id = job_id
        self.kind = kind  # "audit" | "arena"
        self.events: list[dict[str, Any]] = []
        self.cond = threading.Condition()
        self.cancel_flag = threading.Event()
        self.finished = False
        self.report: AuditReport | None = None
        self.arena_result: dict[str, Any] | None = None
        self.batch_result: dict[str, Any] | None = None

    def push(self, event: dict[str, Any]) -> None:
        with self.cond:
            self.events.append(event)
            self.cond.notify_all()

    def finish_audit(self, report: AuditReport) -> None:
        with self.cond:
            self.report = report
            self.finished = True
            self.events.append({"type": "done", "kind": "audit", "report": report.to_dict()})
            self.cond.notify_all()

    def finish_arena(self, arena_result: dict[str, Any]) -> None:
        with self.cond:
            self.arena_result = arena_result
            self.finished = True
            self.events.append({"type": "done", "kind": "arena", "arena": arena_result})
            self.cond.notify_all()

    def finish_batch(self, batch_result: dict[str, Any]) -> None:
        with self.cond:
            self.batch_result = batch_result
            self.finished = True
            self.events.append({"type": "done", "kind": "batch", "batch": batch_result})
            self.cond.notify_all()

    def fail(self, msg: str) -> None:
        with self.cond:
            self.finished = True
            self.events.append({"type": "error", "message": msg})
            self.cond.notify_all()


def _parse_audit_config(body: dict[str, Any]) -> AuditConfig:
    iq_seed = body.get("iq_seed")
    try:
        iq_seed_val = int(iq_seed) if iq_seed not in (None, "") else None
    except Exception:
        iq_seed_val = None
    try:
        cliff_k = int(body.get("context_cliff_max_k") or 16)
    except Exception:
        cliff_k = 16
    try:
        timeout_sec = max(10.0, min(300.0, float(body.get("timeout_sec") or 75.0)))
    except Exception:
        timeout_sec = 75.0
    try:
        max_conc = max(1, min(10, int(body.get("max_concurrency") or 4)))
    except Exception:
        max_conc = 4
    extra_hdrs = body.get("extra_headers")
    if isinstance(extra_hdrs, str) and extra_hdrs.strip():
        try:
            extra_hdrs = json.loads(extra_hdrs)
        except Exception:
            extra_hdrs = {}
    if not isinstance(extra_hdrs, dict):
        extra_hdrs = {}

    try:
        budget_cap = max(0.0, float(body.get("budget_cap_cny") or 0.0))
    except Exception:
        budget_cap = 0.0

    return AuditConfig(
        base_url=str(body.get("base_url") or "").strip(),
        api_key=str(body.get("api_key") or "").strip(),
        model=str(body.get("model") or "").strip(),
        protocol=str(body.get("protocol") or "auto"),
        mode=str(body.get("mode") or "standard"),
        run_protocol=bool(body.get("run_protocol", True)),
        run_tokenizer=bool(body.get("run_tokenizer", True)),
        run_fingerprint=bool(body.get("run_fingerprint", True)),
        run_iq=bool(body.get("run_iq", True)),
        run_vision=bool(body.get("run_vision", True)),
        run_long_context=bool(body.get("run_long_context", True)),
        run_param_obedience=bool(body.get("run_param_obedience", True)),
        run_smart_routing=bool(body.get("run_smart_routing", True)),
        run_cutoff=bool(body.get("run_cutoff", True)),
        run_regex_canary=bool(body.get("run_regex_canary", True)),
        run_agent_loop=bool(body.get("run_agent_loop", True)),
        run_concurrency=bool(body.get("run_concurrency", True)),
        run_billing_mult=bool(body.get("run_billing_mult", True)),
        run_quant_precision=bool(body.get("run_quant_precision", True)),
        run_pdf_probe=bool(body.get("run_pdf_probe", True)),
        run_output_cap=bool(body.get("run_output_cap", False)),
        run_context_cliff=bool(body.get("run_context_cliff", False)),
        context_cliff_max_k=cliff_k,
        run_v11_probes=bool(body.get("run_v11_probes", True)),
        run_vision_hires=bool(body.get("run_vision_hires", True)),
        stealth_mode=bool(body.get("stealth_mode", False)),
        budget_cap_cny=budget_cap,
        anonymize_domain=bool(body.get("anonymize_domain", False)),
        run_plain_summary=bool(body.get("run_plain_summary", True)),
        timeout_sec=timeout_sec,
        max_concurrency=max_conc,
        proxy_url=str(body.get("proxy_url") or "").strip(),
        verify_ssl=bool(body.get("verify_ssl", True)),
        compare_baseline_id=body.get("compare_baseline_id") or None,
        iq_seed=iq_seed_val,
        extra_headers={str(k): str(v) for k, v in extra_hdrs.items()},
    )


class AppState:
    def __init__(self, app_token: str) -> None:
        self.app_token = app_token
        self.baseline_store = BaselineStore()
        self.history_store = HistoryStore()
        self.monitor = CanaryMonitor()
        self.passive_proxy = PassiveAuditProxy()
        self.jobs: dict[str, AsyncJob] = {}
        self.jobs_lock = threading.Lock()
        self.last_heartbeat = time.time()
        self.window_closed_signal = threading.Event()
        self.index_html_bytes = _resource_path("web/index.html").read_bytes()

    def start_audit_job(self, cfg: AuditConfig) -> AsyncJob:
        jid = f"job_{uuid.uuid4().hex[:10]}"
        job = AsyncJob(jid, "audit")
        with self.jobs_lock:
            self.jobs[jid] = job

        def _worker() -> None:
            try:
                report = run_full_audit(
                    cfg,
                    baseline_store=self.baseline_store,
                    on_event=job.push,
                    cancel_check=job.cancel_flag.is_set,
                )
                try:
                    self.history_store.save_report(report.to_dict())
                except Exception:
                    pass
                job.finish_audit(report)
            except Exception as exc:
                job.fail(f"{type(exc).__name__}: {exc}")

        threading.Thread(target=_worker, name=f"audit-{jid}", daemon=True).start()
        return job

    def start_demo_job(self) -> AsyncJob:
        jid = f"demo_{uuid.uuid4().hex[:10]}"
        job = AsyncJob(jid, "audit")
        with self.jobs_lock:
            self.jobs[jid] = job

        def _worker() -> None:
            try:
                report = run_demo_sandbox_audit(
                    baseline_store=self.baseline_store,
                    on_event=job.push,
                    cancel_check=job.cancel_flag.is_set,
                )
                job.finish_audit(report)
            except Exception as exc:
                job.fail(f"{type(exc).__name__}: {exc}")

        threading.Thread(target=_worker, name=f"demo-{jid}", daemon=True).start()
        return job

    def start_arena_job(self, cfg_a: AuditConfig, cfg_b: AuditConfig) -> AsyncJob:
        jid = f"arena_{uuid.uuid4().hex[:10]}"
        job = AsyncJob(jid, "arena")
        with self.jobs_lock:
            self.jobs[jid] = job

        def _worker() -> None:
            try:
                res = run_ab_arena(
                    cfg_a,
                    cfg_b,
                    baseline_store=self.baseline_store,
                    on_event=job.push,
                    cancel_check=job.cancel_flag.is_set,
                )
                try:
                    self.history_store.save_report(res["report_a"])
                    self.history_store.save_report(res["report_b"])
                except Exception:
                    pass
                job.finish_arena(res)
            except Exception as exc:
                job.fail(f"{type(exc).__name__}: {exc}")

        threading.Thread(target=_worker, name=f"arena-{jid}", daemon=True).start()
        return job

    def start_batch_job(
        self, targets: list[dict[str, Any]], *, mode: str, run_iq: bool, run_protocol: bool
    ) -> AsyncJob:
        jid = f"batch_{uuid.uuid4().hex[:10]}"
        job = AsyncJob(jid, "batch")
        with self.jobs_lock:
            self.jobs[jid] = job

        def _worker() -> None:
            try:
                res = run_batch_leaderboard(
                    targets,
                    mode=mode,
                    run_iq=run_iq,
                    run_protocol=run_protocol,
                    baseline_store=self.baseline_store,
                    on_event=job.push,
                    cancel_check=job.cancel_flag.is_set,
                )
                for row in res.get("leaderboard") or []:
                    try:
                        if row.get("report"):
                            self.history_store.save_report(row["report"])
                    except Exception:
                        pass
                job.finish_batch(res)
            except Exception as exc:
                job.fail(f"{type(exc).__name__}: {exc}")

        threading.Thread(target=_worker, name=f"batch-{jid}", daemon=True).start()
        return job

    def get_job(self, job_id: str) -> AsyncJob | None:
        with self.jobs_lock:
            return self.jobs.get(job_id)


def make_handler(state: AppState):
    class ForensicHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _check_token(self, query: dict[str, list[str]]) -> bool:
            if not state.app_token:
                return True
            hdr_tok = self.headers.get("X-App-Token", "")
            q_tok = (query.get("token") or [""])[0]
            return secrets.compare_digest(hdr_tok, state.app_token) or secrets.compare_digest(
                q_tok, state.app_token
            )

        def _read_raw_body(self) -> bytes:
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except Exception:
                length = 0
            if length <= 0:
                return b""
            if length > 15 * 1024 * 1024:
                self.close_connection = True
                raise ValueError("Payload too large")
            return self.rfile.read(length)

        def _read_json(self, raw: bytes | None = None) -> dict[str, Any]:
            buf = self._read_raw_body() if raw is None else raw
            if not buf.strip():
                return {}
            return json.loads(buf.decode("utf-8"))

        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            """Always emit JSON instead of HTML <!DOCTYPE> error pages and close broken sockets cleanly."""
            self.close_connection = True
            try:
                self._send_json(
                    int(code),
                    {"error": f"HTTP {code}: {message or 'Request error'}"},
                )
            except Exception:
                pass

        def do_OPTIONS(self) -> None:
            self._read_raw_body()
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Allow", "GET, POST, DELETE, OPTIONS")
            self.end_headers()

        def _send_bytes(
            self,
            status: int,
            body: bytes,
            content_type: str,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, obj: Any) -> None:
            data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self._send_bytes(status, data, "application/json; charset=utf-8")

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if path == "/" or path == "/index.html":
                self._send_bytes(200, state.index_html_bytes, "text/html; charset=utf-8")
                return

            if path == "/api/health":
                self._send_json(200, {"ok": True, "version": __version__})
                return

            if not self._check_token(query):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid session token"})
                return

            # Baselines
            if path == "/api/baselines":
                self._send_json(200, {"baselines": state.baseline_store.list_baselines()})
                return

            if path.startswith("/api/baselines/") and path.endswith("/export"):
                bid = path[len("/api/baselines/") : -len("/export")].strip("/")
                bl = state.baseline_store.get(bid)
                if not bl:
                    self._send_json(404, {"error": "Baseline not found"})
                    return
                body = json.dumps(bl, ensure_ascii=False, indent=2).encode("utf-8")
                self._send_bytes(
                    200,
                    body,
                    "application/json; charset=utf-8",
                    {"Content-Disposition": f'attachment; filename="baseline_{bid}.json"'},
                )
                return

            # History Vault
            if path == "/api/history":
                self._send_json(200, {"history": state.history_store.list_reports()})
                return

            if path.startswith("/api/history/") and path.endswith("/export"):
                aid = path[len("/api/history/") : -len("/export")].strip("/")
                fmt = (query.get("format") or ["html"])[0].lower()
                anon = (query.get("anonymize") or ["0"])[0] in ("1", "true", "yes")
                rep = state.history_store.get_report(aid)
                if not rep:
                    self._send_json(404, {"error": "History item not found"})
                    return
                if anon:
                    rep = anonymize_report_dict(rep)
                if fmt == "json":
                    body = json.dumps(rep, ensure_ascii=False, indent=2).encode("utf-8")
                    self._send_bytes(
                        200,
                        body,
                        "application/json; charset=utf-8",
                        {"Content-Disposition": f'attachment; filename="audit_{aid}.json"'},
                    )
                else:
                    html_str = render_html_report(rep, anonymize_domain=anon)
                    self._send_bytes(
                        200,
                        html_str.encode("utf-8"),
                        "text/html; charset=utf-8",
                        {"Content-Disposition": f'attachment; filename="audit_{aid}.html"'},
                    )
                return

            if path.startswith("/api/history/"):
                aid = path[len("/api/history/") :].strip("/")
                rep = state.history_store.get_report(aid)
                if not rep:
                    self._send_json(404, {"error": "History item not found"})
                    return
                self._send_json(200, {"report": rep})
                return

            # Backup ZIP export (all local baselines + history JSONs, already redacted!)
            if path == "/api/backup/export":
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for p in sorted(state.baseline_store.dir.glob("*.json")):
                        zf.write(p, arcname=f"baselines/{p.name}")
                    for p in sorted(state.history_store.dir.glob("*.json")):
                        zf.write(p, arcname=f"history/{p.name}")
                self._send_bytes(
                    200,
                    buf.getvalue(),
                    "application/zip",
                    {"Content-Disposition": 'attachment; filename="LLM-TruthLab-backup.zip"'},
                )
                return

            # Canary Monitor Status
            if path == "/api/monitor/status":
                self._send_json(200, state.monitor.status())
                return

            # Passive Transparent Proxy Status
            if path == "/api/proxy/status":
                self._send_json(200, state.passive_proxy.status())
                return

            # SSE Stream (works for both single audit & arena jobs)
            if path == "/api/audit/events":
                job_id = (query.get("job_id") or [""])[0]
                job = state.get_job(job_id)
                if not job:
                    self._send_json(404, {"error": "Job not found"})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()

                idx = 0
                try:
                    while True:
                        with job.cond:
                            while idx >= len(job.events) and not job.finished:
                                job.cond.wait(timeout=1.5)
                                if idx >= len(job.events) and not job.finished:
                                    self.wfile.write(b": ping\n\n")
                                    self.wfile.flush()
                            batch = job.events[idx:]
                            idx = len(job.events)
                            done_now = job.finished

                        for ev in batch:
                            payload = f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode("utf-8")
                            self.wfile.write(payload)
                            self.wfile.flush()

                        if done_now and idx >= len(job.events):
                            break
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass
                return

            # Export active audit or arena job
            if path == "/api/audit/export":
                job_id = (query.get("job_id") or [""])[0]
                fmt = (query.get("format") or ["html"])[0].lower()
                anon = (query.get("anonymize") or ["0"])[0] in ("1", "true", "yes")
                job = state.get_job(job_id)
                if not job or not job.report:
                    self._send_json(404, {"error": "Report not ready"})
                    return
                rep_dict = job.report.to_dict()
                if anon:
                    rep_dict = anonymize_report_dict(rep_dict)
                if fmt == "json":
                    body = json.dumps(rep_dict, ensure_ascii=False, indent=2).encode("utf-8")
                    self._send_bytes(
                        200,
                        body,
                        "application/json; charset=utf-8",
                        {"Content-Disposition": f'attachment; filename="audit_{job.report.audit_id}.json"'},
                    )
                else:
                    html_str = render_html_report(rep_dict, anonymize_domain=anon)
                    self._send_bytes(
                        200,
                        html_str.encode("utf-8"),
                        "text/html; charset=utf-8",
                        {"Content-Disposition": f'attachment; filename="audit_{job.report.audit_id}.html"'},
                    )
                return

            if path == "/api/arena/export":
                job_id = (query.get("job_id") or [""])[0]
                fmt = (query.get("format") or ["json"])[0].lower()
                job = state.get_job(job_id)
                if not job or not job.arena_result:
                    self._send_json(404, {"error": "Arena result not ready"})
                    return
                aid = job.arena_result["arena_id"]
                if fmt == "html":
                    body = render_arena_html(job.arena_result).encode("utf-8")
                    self._send_bytes(
                        200,
                        body,
                        "text/html; charset=utf-8",
                        {"Content-Disposition": f'attachment; filename="arena_{aid}.html"'},
                    )
                else:
                    body = json.dumps(job.arena_result, ensure_ascii=False, indent=2).encode("utf-8")
                    self._send_bytes(
                        200,
                        body,
                        "application/json; charset=utf-8",
                        {"Content-Disposition": f'attachment; filename="arena_{aid}.json"'},
                    )
                return

            if path == "/api/batch/export":
                job_id = (query.get("job_id") or [""])[0]
                fmt = (query.get("format") or ["json"])[0].lower()
                job = state.get_job(job_id)
                if not job or not job.batch_result:
                    self._send_json(404, {"error": "Batch result not ready"})
                    return
                bid = job.batch_result["batch_id"]
                if fmt == "html":
                    body = render_batch_html(job.batch_result).encode("utf-8")
                    self._send_bytes(
                        200,
                        body,
                        "text/html; charset=utf-8",
                        {"Content-Disposition": f'attachment; filename="batch_{bid}.html"'},
                    )
                else:
                    body = json.dumps(job.batch_result, ensure_ascii=False, indent=2).encode("utf-8")
                    self._send_bytes(
                        200,
                        body,
                        "application/json; charset=utf-8",
                        {"Content-Disposition": f'attachment; filename="batch_{bid}.json"'},
                    )
                return

            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            # Always drain HTTP/1.1 request body FIRST so keep-alive sockets NEVER desync!
            try:
                raw_body = self._read_raw_body()
            except Exception as exc:
                self._send_json(413, {"error": str(exc)})
                return

            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if not self._check_token(query):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid session token"})
                return

            if path == "/api/heartbeat":
                state.last_heartbeat = time.time()
                self._send_json(200, {"ok": True})
                return

            if path == "/api/window_closing":
                state.window_closed_signal.set()
                self._send_json(200, {"ok": True})
                return

            try:
                body = self._read_json(raw_body)
            except Exception as exc:
                self._send_json(400, {"error": f"Invalid JSON: {exc}"})
                return

            if path == "/api/models":
                cfg = AuditConfig(
                    base_url=str(body.get("base_url") or ""),
                    api_key=str(body.get("api_key") or ""),
                    model="",
                    protocol=str(body.get("protocol") or "openai_chat"),
                )
                client = RelayClient(cfg)
                try:
                    status, ids, meta = client.list_models()
                    self._send_json(200, {"status_code": status, "models": sorted(set(ids)), "meta": meta})
                finally:
                    client.close()
                return

            if path == "/api/audit/start":
                cfg = _parse_audit_config(body)
                if not cfg.base_url or not cfg.api_key or not cfg.model:
                    self._send_json(400, {"error": "请完整提供 base_url、api_key 与 model"})
                    return
                job = state.start_audit_job(cfg)
                self._send_json(200, {"job_id": job.job_id})
                return

            if path == "/api/audit/demo":
                job = state.start_demo_job()
                self._send_json(200, {"job_id": job.job_id})
                return

            if path == "/api/arena/start":
                a_raw = body.get("a") or {}
                b_raw = body.get("b") or {}
                shared = body.get("shared") or {}
                merged_a = {**shared, **a_raw}
                merged_b = {**shared, **b_raw}
                cfg_a = _parse_audit_config(merged_a)
                cfg_b = _parse_audit_config(merged_b)
                if not (cfg_a.base_url and cfg_a.api_key and cfg_a.model and cfg_b.base_url and cfg_b.api_key and cfg_b.model):
                    self._send_json(400, {"error": "请完整填写 A 端与 B 端的地址、Key 和模型名"})
                    return
                job = state.start_arena_job(cfg_a, cfg_b)
                self._send_json(200, {"job_id": job.job_id})
                return

            if path == "/api/batch/start":
                targets = body.get("targets") or []
                valid = [
                    t
                    for t in targets
                    if isinstance(t, dict)
                    and str(t.get("base_url") or "").strip()
                    and str(t.get("api_key") or "").strip()
                    and str(t.get("model") or "").strip()
                ]
                if len(valid) < 2:
                    self._send_json(400, {"error": "批量红黑榜至少需要填写 2 个有效目标"})
                    return
                if len(valid) > 12:
                    self._send_json(400, {"error": "单次批量横评最多支持 12 个目标"})
                    return
                job = state.start_batch_job(
                    valid,
                    mode=str(body.get("mode") or "quick"),
                    run_iq=bool(body.get("run_iq", True)),
                    run_protocol=bool(body.get("run_protocol", True)),
                )
                self._send_json(200, {"job_id": job.job_id})
                return

            if path == "/api/audit/cancel":
                jid = str(body.get("job_id") or "")
                job = state.get_job(jid)
                if job:
                    job.cancel_flag.set()
                self._send_json(200, {"ok": True})
                return

            if path == "/api/history/compare":
                id_old = str(body.get("old_id") or "").strip()
                id_new = str(body.get("new_id") or "").strip()
                rep_old = state.history_store.get_report(id_old)
                rep_new = state.history_store.get_report(id_new)
                if not rep_old or not rep_new:
                    self._send_json(404, {"error": "未找到选中的两条历史记录"})
                    return
                diff = compare_history_reports(rep_old, rep_new)
                self._send_json(200, {"diff": diff})
                return

            # Canary Monitor
            if path == "/api/monitor/start":
                cfg = _parse_audit_config(body)
                if not cfg.base_url or not cfg.api_key or not cfg.model:
                    self._send_json(400, {"error": "请完整填写巡检目标的地址、Key 和模型名"})
                    return
                interval = int(body.get("interval_sec") or 180)
                webhook_url = str(body.get("webhook_url") or "").strip()
                st = state.monitor.start(cfg, interval_sec=interval, webhook_url=webhook_url)
                self._send_json(200, st)
                return

            if path == "/api/monitor/stop":
                self._send_json(200, state.monitor.stop())
                return

            if path == "/api/monitor/tick_now":
                cfg = _parse_audit_config(body)
                if not cfg.base_url or not cfg.api_key or not cfg.model:
                    self._send_json(400, {"error": "请完整填写巡检目标的地址、Key 和模型名"})
                    return
                tick = state.monitor.run_single_tick(cfg)
                self._send_json(200, {"tick": tick, "status": state.monitor.status()})
                return

            if path == "/api/monitor/test_webhook":
                wh_url = str(body.get("webhook_url") or "").strip()
                ok, detail = send_webhook_alert(
                    wh_url,
                    "LLM-TruthLab v11.0 告警通道测试",
                    ["恭喜！金丝雀巡检 Webhook 告警链路已连通，发生高峰暗换/漂移时将自动推送。"],
                )
                self._send_json(200 if ok else 400, {"ok": ok, "detail": detail})
                return

            # Local Transparent Passive Audit Proxy
            if path == "/api/proxy/start":
                upstream = str(body.get("upstream_base_url") or "").strip()
                port_val = int(body.get("port") or 8899)
                proxy_url = str(body.get("proxy_url") or "").strip()
                verify_ssl = bool(body.get("verify_ssl", True))
                try:
                    st = state.passive_proxy.start(
                        upstream,
                        port=port_val,
                        proxy_url=proxy_url,
                        verify_ssl=verify_ssl,
                    )
                    self._send_json(200, st)
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/proxy/stop":
                self._send_json(200, state.passive_proxy.stop())
                return

            if path == "/api/proxy/clear":
                self._send_json(200, state.passive_proxy.clear())
                return

            # Backup ZIP Import & Merge
            if path == "/api/backup/import":
                zip_b64 = str(body.get("zip_b64") or "").strip()
                if not zip_b64:
                    self._send_json(400, {"error": "缺少 zip_b64 数据"})
                    return
                if "," in zip_b64 and zip_b64.startswith("data:"):
                    zip_b64 = zip_b64.split(",", 1)[1]
                try:
                    raw_zip = base64.b64decode(zip_b64)
                    imp_bl = 0
                    imp_hist = 0
                    with zipfile.ZipFile(io.BytesIO(raw_zip), "r") as zf:
                        for info in zf.infolist():
                            if info.is_dir() or info.file_size > 10 * 1024 * 1024:
                                continue
                            name = info.filename.replace("\\", "/")
                            if ".." in name or name.startswith("/") or not name.endswith(".json"):
                                continue
                            try:
                                parsed_obj = json.loads(zf.read(info).decode("utf-8"))
                            except Exception:
                                continue
                            if not isinstance(parsed_obj, dict):
                                continue
                            if name.startswith("baselines/") and parsed_obj.get("distributions") is not None:
                                state.baseline_store.import_json(parsed_obj)
                                imp_bl += 1
                            elif name.startswith("history/") and parsed_obj.get("audit_id") and parsed_obj.get("verdict"):
                                state.history_store.save_report(parsed_obj)
                                imp_hist += 1
                    self._send_json(
                        200,
                        {"ok": True, "imported_baselines": imp_bl, "imported_history": imp_hist},
                    )
                except Exception as exc:
                    self._send_json(400, {"error": f"导入备份 ZIP 失败: {exc}"})
                return

            # Baselines
            if path == "/api/baselines/save":
                jid = str(body.get("job_id") or "")
                aid = str(body.get("audit_id") or "")
                name = str(body.get("name") or "").strip()
                notes = str(body.get("notes") or "").strip()

                rep_dict: dict[str, Any] | None = None
                if jid:
                    job = state.get_job(jid)
                    if job and job.report:
                        rep_dict = job.report.to_dict()
                if rep_dict is None and aid:
                    rep_dict = state.history_store.get_report(aid)
                if rep_dict is None:
                    self._send_json(404, {"error": "未找到对应的已完成审计报告"})
                    return
                saved = state.baseline_store.save_from_report(rep_dict, name=name, notes=notes)
                self._send_json(200, {"baseline": saved})
                return

            if path == "/api/baselines/import":
                try:
                    saved = state.baseline_store.import_json(body)
                    self._send_json(200, {"baseline": saved})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            self._send_json(404, {"error": "Not found"})

        def do_DELETE(self) -> None:
            try:
                self._read_raw_body()
            except Exception:
                pass
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            if not self._check_token(query):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid session token"})
                return
            if path.startswith("/api/baselines/"):
                bid = path[len("/api/baselines/") :].strip("/")
                ok = state.baseline_store.delete(bid)
                self._send_json(200 if ok else 404, {"ok": ok})
                return
            if path.startswith("/api/history/"):
                aid = path[len("/api/history/") :].strip("/")
                ok = state.history_store.delete_report(aid)
                self._send_json(200 if ok else 404, {"ok": ok})
                return
            self._send_json(404, {"error": "Not found"})

    return ForensicHandler


def _find_chromium_app_browser() -> str | None:
    local_app = os.environ.get("LocalAppData", "")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    candidates = [
        Path(pf86) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(pf) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(pf) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(pf86) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(local_app) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(pf) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
        Path(local_app) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
    ]
    for p in candidates:
        if p.is_file():
            return str(p)
    return None


def run_cli(args: argparse.Namespace) -> int:
    def on_ev(ev: dict[str, Any]) -> None:
        if ev.get("type") == "progress":
            _safe_print(f"  [{ev.get('progress', 0):3d}%] {ev.get('message')}")

    if args.ab:
        url_b = args.url_b or args.url
        key_b = args.key_b or args.key
        model_b = args.model_b or args.model
        cfg_a = AuditConfig(
            base_url=args.url,
            api_key=args.key,
            model=args.model,
            protocol=args.protocol,
            mode=args.mode,
            run_vision=False,
            run_long_context=False,
            run_smart_routing=False,
            run_cutoff=False,
            run_iq=not args.no_iq,
            proxy_url=args.proxy,
            iq_seed=args.seed,
        )
        cfg_b = AuditConfig(
            base_url=url_b,
            api_key=key_b,
            model=model_b,
            protocol=args.protocol_b or args.protocol,
            mode=args.mode,
            run_vision=False,
            run_long_context=False,
            run_smart_routing=False,
            run_cutoff=False,
            run_iq=not args.no_iq,
            proxy_url=args.proxy,
            iq_seed=args.seed,
        )
        _safe_print(f"[LLM-TruthLab v{__version__} A/B CLI] A: {cfg_a.model} @ {cfg_a.base_url} vs B: {cfg_b.model} @ {cfg_b.base_url}")
        res = run_ab_arena(cfg_a, cfg_b, on_event=on_ev)
        c = res["comparison"]
        _safe_print("\n" + "=" * 76)
        _safe_print(f"A/B 对决结论: {c['relation_label']} ({c['relation_code']})")
        _safe_print(f"A <-> B JSD 散度: {c['mean_jsd']} | 词表 L1: {c['tokenizer_l1']} | 共享智商 Seed: {res['shared_iq_seed']}")
        _safe_print(f"摘要: {c['relation_summary']}")
        _safe_print("=" * 76)
        if args.out:
            Path(args.out).write_text(render_arena_html(res), encoding="utf-8")
            _safe_print(f"A/B HTML 报告已保存: {args.out}")
        if args.json:
            Path(args.json).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
            _safe_print(f"A/B JSON 已保存: {args.json}")
        return 0

    cfg = AuditConfig(
        base_url=args.url,
        api_key=args.key,
        model=args.model,
        protocol=args.protocol,
        mode=args.mode,
        run_vision=not args.no_vision,
        run_long_context=not args.no_long_context,
        run_iq=not args.no_iq,
        run_context_cliff=args.context_cliff,
        context_cliff_max_k=args.context_max_k,
        stealth_mode=args.stealth,
        budget_cap_cny=args.budget,
        anonymize_domain=args.anonymize,
        run_plain_summary=not args.no_plain_summary,
        proxy_url=args.proxy,
        iq_seed=args.seed,
    )
    _safe_print(f"[LLM-TruthLab v{__version__}] Target: {cfg.base_url} | Model: {cfg.model} | Mode: {cfg.mode}")

    report = run_full_audit(cfg, on_event=on_ev)
    v = report.verdict
    _safe_print("\n" + "=" * 76)
    _safe_print(f"零信任仲裁结论: {v.authenticity_label} ({v.authenticity_code})")
    _safe_print(f"可信度分: {v.trust_score}/100 | 协议: {v.detected_protocol} | 推断词表: {v.detected_tokenizer_family}")
    top_sus = (report.attribution or {}).get("top_suspect") or {}
    mlm = (report.attribution or {}).get("most_likely_model") or {}
    if mlm.get("model_name"):
        _safe_print(f"最可能真实模型: {mlm.get('model_name')} (置信度 {mlm.get('confidence_pct')}%) | {mlm.get('basis', '')}")
    elif top_sus:
        _safe_print(f"底层家族归因首推: {top_sus.get('family_label')} ({top_sus.get('confidence_pct')}%)")
    _safe_print(f"结论摘要: {v.headline}")
    if report.iq:
        _safe_print(f"动态智商 (10维): {report.iq.total_score}/100 | 智商指数 {report.iq.iq_index} | {report.iq.tier_label} (Seed={report.iq.seed})")
    if report.plain_summary and report.plain_summary.get("content"):
        _safe_print("-" * 76)
        _safe_print(report.plain_summary["content"])
    _safe_print("=" * 76)

    if args.out:
        Path(args.out).write_text(render_html_report(report), encoding="utf-8")
        _safe_print(f"HTML 报告已保存: {args.out}")
    if args.json:
        Path(args.json).write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        _safe_print(f"JSON 证据已保存: {args.json}")
    return 0


def run_desktop_app(port: int = 0, server_only: bool = False) -> int:
    token = secrets.token_urlsafe(18)
    state = AppState(app_token=token)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    server.daemon_threads = True
    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}/?token={token}"

    threading.Thread(target=server.serve_forever, daemon=True).start()

    if server_only:
        _safe_print(f"LLM-TruthLab v{__version__} server running at {url}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            state.monitor.stop()
            state.passive_proxy.stop()
            server.shutdown()
            return 0

    browser = _find_chromium_app_browser()
    temp_profile: str | None = None
    launched_app_proc: subprocess.Popen[Any] | None = None

    if browser:
        temp_profile = tempfile.mkdtemp(prefix="llm_truthlab_ui_")
        cmd = [
            browser,
            f"--app={url}",
            f"--user-data-dir={temp_profile}",
            "--window-size=1240,820",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--proxy-bypass-list=127.0.0.1;localhost",
        ]
        try:
            t_start = time.time()
            launched_app_proc = subprocess.Popen(cmd)
            launched_app_proc.wait()
            elapsed = time.time() - t_start
            if elapsed >= 3.0:
                state.monitor.stop()
                state.passive_proxy.stop()
                server.shutdown()
                shutil.rmtree(temp_profile, ignore_errors=True)
                return 0
        except Exception:
            launched_app_proc = None

    if launched_app_proc is None:
        webbrowser.open(url)

    state.last_heartbeat = time.time()
    launch_ts = time.time()
    try:
        while True:
            time.sleep(1.5)
            if state.window_closed_signal.is_set():
                time.sleep(2.5)
                if time.time() - state.last_heartbeat > 2.2:
                    break
                state.window_closed_signal.clear()
            # Give slower PCs / antivirus cold scans a 150s initial grace window before exiting
            grace = 150.0 if (time.time() - launch_ts) < 160.0 else 50.0
            if time.time() - state.last_heartbeat > grace:
                break
    except KeyboardInterrupt:
        pass
    finally:
        state.monitor.stop()
        state.passive_proxy.stop()
        server.shutdown()
        if temp_profile:
            shutil.rmtree(temp_profile, ignore_errors=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=f"LLM-TruthLab v{__version__}: Zero-Trust API Fingerprinting, Passive Proxy, Arena, Batch, Monitor & 10-Dim IQ")
    parser.add_argument("--cli", action="store_true", help="Run in headless CLI mode")
    parser.add_argument("--ab", action="store_true", help="Run A/B Dual-Endpoint duel in CLI mode")
    parser.add_argument("--server-only", action="store_true", help="Run local web server only")
    parser.add_argument("--port", type=int, default=0, help="Local HTTP port")
    parser.add_argument("--url", default="", help="API Base URL (Endpoint A in --ab mode)")
    parser.add_argument("--key", default="", help="API Key (Endpoint A in --ab mode)")
    parser.add_argument("--model", default="", help="Requested model name (Endpoint A in --ab mode)")
    parser.add_argument("--protocol", default="auto", choices=["auto", "openai_chat", "anthropic", "gemini", "openai_responses"])
    parser.add_argument("--url-b", default="", help="Endpoint B Base URL for --ab mode (defaults to --url)")
    parser.add_argument("--key-b", default="", help="Endpoint B API Key for --ab mode (defaults to --key)")
    parser.add_argument("--model-b", default="", help="Endpoint B model name for --ab mode")
    parser.add_argument("--protocol-b", default="", choices=["", "auto", "openai_chat", "anthropic", "gemini", "openai_responses"])
    parser.add_argument("--proxy", default="", help="Optional HTTP/SOCKS proxy URL")
    parser.add_argument("--mode", default="standard", choices=["quick", "standard", "deep"])
    parser.add_argument("--seed", type=int, default=None, help="Optional fixed random seed for IQ suite")
    parser.add_argument("--stealth", action="store_true", help="Enable anti-detector stealth mode")
    parser.add_argument("--budget", type=float, default=0.0, help="Budget cap in CNY (0 = unlimited)")
    parser.add_argument("--anonymize", action="store_true", help="Mask target domain in exported report")
    parser.add_argument("--no-iq", action="store_true", help="Skip dynamic IQ suite")
    parser.add_argument("--no-plain-summary", action="store_true", help="Skip AI plain-language summary call")
    parser.add_argument("--no-vision", action="store_true", help="Skip dynamic vision probe")
    parser.add_argument("--no-long-context", action="store_true", help="Skip multi-hop long context probe")
    parser.add_argument("--context-cliff", action="store_true", help="Enable stepped context cliff heatmap ladder")
    parser.add_argument("--context-max-k", type=int, default=16, help="Max K tokens for context cliff ladder (4..128)")
    parser.add_argument("--out", default="", help="Output path for standalone HTML report")
    parser.add_argument("--json", default="", help="Output path for raw JSON evidence")

    args = parser.parse_args()
    if args.cli:
        if not args.url or not args.key or not args.model:
            parser.error("--cli 模式必须同时指定 --url, --key 和 --model")
        if args.ab and not (args.model_b or args.url_b):
            parser.error("--cli --ab 模式至少需要指定 --model-b 或 --url-b")
        try:
            return run_cli(args)
        except Exception as exc:
            _safe_print(f"[ERROR] CLI execution failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
    return run_desktop_app(port=args.port, server_only=args.server_only)


if __name__ == "__main__":
    raise SystemExit(main())
