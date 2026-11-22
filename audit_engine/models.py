"""Data models for the zero-trust LLM API fingerprinting & IQ audit engine (v2/v3)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AuditConfig:
    base_url: str
    api_key: str
    model: str
    protocol: str = "auto"  # auto | openai_chat | anthropic | gemini | openai_responses
    mode: str = "standard"  # quick | standard | deep
    run_protocol: bool = True
    run_tokenizer: bool = True
    run_fingerprint: bool = True
    run_iq: bool = True
    run_vision: bool = True
    run_long_context: bool = True
    run_param_obedience: bool = True
    run_smart_routing: bool = True
    run_cutoff: bool = True
    run_regex_canary: bool = True
    run_agent_loop: bool = True
    run_concurrency: bool = True
    run_billing_mult: bool = True
    run_quant_precision: bool = True
    run_pdf_probe: bool = True
    run_output_cap: bool = False
    run_context_cliff: bool = False  # optional heavy context ladder (4K->32K+)
    context_cliff_max_k: int = 16
    run_v11_probes: bool = True  # anti-reverse-pool, logit_bias, cache physics, multi-turn, parallel tools
    run_vision_hires: bool = True  # 1024x1024 micro-corner downscaling trap
    stealth_mode: bool = False  # anti-detector evasion (official SDK UA + paraphrased prompts)
    budget_cap_cny: float = 0.0  # 0 = unlimited; >0 halts audit once estimated official cost reaches cap
    anonymize_domain: bool = False  # mask target domain in exported HTML/Markdown/PNG
    run_plain_summary: bool = True  # default ON: call audited key to generate a plain-Chinese summary
    iq_seed: int | None = None
    timeout_sec: float = 75.0
    max_concurrency: int = 4
    proxy_url: str = ""  # optional HTTP/SOCKS proxy (e.g. http://127.0.0.1:7890)
    verify_ssl: bool = True
    compare_baseline_id: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)

    def safe_dict(self) -> dict[str, Any]:
        d = asdict(self)
        k = self.api_key or ""
        if len(k) <= 8:
            d["api_key"] = "***" if k else ""
        else:
            d["api_key"] = f"{k[:4]}...{k[-4:]}"
        return d


@dataclass
class HttpTrace:
    method: str
    url: str
    status_code: int
    latency_ms: float
    ttft_ms: float | None = None
    headers: dict[str, str] = field(default_factory=dict)
    request_summary: dict[str, Any] = field(default_factory=dict)
    response_snippet: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    returned_model: str = ""
    response_id: str = ""
    system_fingerprint: str = ""
    error: str = ""


@dataclass
class EvidenceItem:
    id: str
    layer: str  # L1_CRYPTO | L1_PROTOCOL | L1_TOKENIZER | L2_FINGERPRINT | L3_CAPABILITY | L4_CONSISTENCY
    title: str
    status: str  # PASS | WARN | FAIL | INFO | SKIP
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    raw_evidence: Any = None
    score_impact: int = 0


@dataclass
class IQQuestionResult:
    id: str
    dimension: str
    dimension_label: str
    title: str
    difficulty: str  # medium | hard | extreme
    max_score: float
    score: float
    passed: bool
    latency_ms: float
    reasoning_tokens: int
    output_tokens: int
    prompt_preview: str
    expected: Any
    actual: str
    grading_notes: str


@dataclass
class IQSummary:
    total_score: float  # 0..100
    iq_index: int  # ~65..145
    tier: str  # S | A | B | C | D
    tier_label: str
    seed: int
    dimension_scores: dict[str, dict[str, Any]] = field(default_factory=dict)
    questions: list[IQQuestionResult] = field(default_factory=list)
    claimed_tier_mismatch: str | None = None


@dataclass
class FingerprintSummary:
    task_count: int = 0
    samples_per_task: int = 0
    total_samples: int = 0
    distributions: dict[str, dict[str, int]] = field(default_factory=dict)
    split_half_jsd: float | None = None
    short_vs_long_jsd: float | None = None
    t0_consistency_rate: float | None = None
    logprobs_supported: bool = False
    logprobs_signature: list[dict[str, Any]] = field(default_factory=list)
    baseline_matches: list[dict[str, Any]] = field(default_factory=list)
    family_clues: list[str] = field(default_factory=list)
    tokenizer_vector: dict[str, Any] = field(default_factory=dict)
    tokenizer_family_guess: str = "unknown"
    cutoff_estimate: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerdictSummary:
    authenticity_code: str  # VERIFIED_STRONG | CONSISTENT_UNPROVEN | SUSPICIOUS | LIKELY_FAKE_OR_WATERED | ERROR
    authenticity_label: str
    trust_score: int  # 0..100
    confidence: str  # HIGH | MEDIUM | LOW
    headline: str
    detected_protocol: str
    detected_engine_clues: list[str] = field(default_factory=list)
    detected_tokenizer_family: str = "unknown"
    suspected_anomalies: list[str] = field(default_factory=list)
    strong_proofs: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    audit_id: str
    started_at: str
    finished_at: str
    duration_sec: float
    config: dict[str, Any]
    verdict: VerdictSummary
    evidences: list[EvidenceItem] = field(default_factory=list)
    fingerprint: FingerprintSummary = field(default_factory=FingerprintSummary)
    iq: IQSummary | None = None
    attribution: dict[str, Any] = field(default_factory=dict)
    context_cliff: dict[str, Any] | None = None
    stream_metrics: dict[str, Any] = field(default_factory=dict)
    telemetry: dict[str, Any] = field(default_factory=dict)
    plain_summary: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
