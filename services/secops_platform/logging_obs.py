"""Structured JSON logging with PII redaction, OpenTelemetry-style spans, and Prometheus metrics."""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SECRET_PATTERN = re.compile(r"(secops-dev-[a-z-]+-key|Bearer\s+[A-Za-z0-9._-]+)")


def redact_sensitive_text(message: str) -> str:
    """Redact emails, raw IPv4s (preserving /24 CIDR subnets ending in .0/24), and API keys."""
    redacted = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", message)
    redacted = SECRET_PATTERN.sub("[REDACTED_SECRET]", redacted)

    def _mask_ip(match: re.Match[str]) -> str:
        ip_str = match.group(0)
        end_idx = match.end()
        if end_idx + 3 <= len(redacted) and redacted[end_idx : end_idx + 3] == "/24":
            return ip_str
        return "[REDACTED_IP]"

    return IPV4_PATTERN.sub(_mask_ip, redacted)


class RedactingJsonFormatter(logging.Formatter):
    """Structured JSON formatter with correlation/run/trace IDs and PII redaction."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp_ms": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_sensitive_text(record.getMessage()),
            "run_id": getattr(record, "run_id", None),
            "trace_id": getattr(record, "trace_id", None),
            "correlation_id": getattr(record, "correlation_id", None),
        }
        extra_fields = getattr(record, "extra_fields", None)
        if isinstance(extra_fields, dict):
            payload["fields"] = {
                k: redact_sensitive_text(str(v)) if isinstance(v, str) else v
                for k, v in extra_fields.items()
            }
        return json.dumps(payload, sort_keys=True)


def get_structured_logger(name: str = "secops_platform") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(RedactingJsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


class LocalSpanTracer:
    """OpenTelemetry-compatible lightweight span recorder writing JSONL spans for observability."""

    def __init__(self, trace_file: Path) -> None:
        self.trace_file = trace_file
        self.trace_file.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def start_span(
        self,
        operation: str,
        trace_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        tid = trace_id or uuid.uuid4().hex
        span_id = uuid.uuid4().hex[:16]
        start_ns = time.time_ns()
        span: dict[str, Any] = {
            "trace_id": tid,
            "span_id": span_id,
            "operation": operation,
            "start_time_ms": start_ns // 1_000_000,
            "status": "OK",
            "attributes": {
                k: redact_sensitive_text(str(v)) if isinstance(v, str) else v
                for k, v in (attributes or {}).items()
            },
        }
        try:
            yield span
        except Exception as exc:
            span["status"] = "ERROR"
            span["error"] = redact_sensitive_text(str(exc))
            raise
        finally:
            end_ns = time.time_ns()
            span["end_time_ms"] = end_ns // 1_000_000
            span["duration_ms"] = round((end_ns - start_ns) / 1_000_000.0, 3)
            with self.trace_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(span, sort_keys=True) + "\n")

    def read_recent_spans(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.trace_file.exists():
            return []
        lines = self.trace_file.read_text(encoding="utf-8").strip().splitlines()
        spans = [json.loads(line) for line in lines[-limit:] if line.strip()]
        spans.reverse()
        return spans


class PlatformMetrics:
    """Prometheus metrics registry for ingestion, CEP, privacy, ABAC, and API telemetry."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.events_ingested = Counter(
            "secops_events_ingested_total",
            "Total security events processed by stream and status",
            ["stream", "status"],
            registry=self.registry,
        )
        self.cep_incidents = Counter(
            "secops_cep_incidents_total",
            "Total CEP incidents emitted or retracted by rule and severity",
            ["rule_ref", "severity", "outcome"],
            registry=self.registry,
        )
        self.cep_detection_delay_ms = Histogram(
            "secops_cep_detection_delay_ms",
            "CEP detection delay in milliseconds from triggering event to alert",
            buckets=(5, 25, 100, 250, 500, 1000, 5000, 30000, 120000),
            registry=self.registry,
        )
        self.cep_state_entries = Gauge(
            "secops_cep_state_entries",
            "Active bounded CEP state entries currently resident in memory",
            registry=self.registry,
        )
        self.abac_decisions = Counter(
            "secops_abac_decisions_total",
            "ABAC/RBAC authorization decisions by role, resource, and outcome",
            ["role", "resource", "decision"],
            registry=self.registry,
        )
        self.privacy_erasures = Counter(
            "secops_privacy_erasures_total",
            "Total GDPR subject crypto-shredding and record purge operations completed",
            registry=self.registry,
        )
        self.retention_purged_rows = Counter(
            "secops_retention_purged_rows_total",
            "Total expired rows purged during retention TTL sweeps",
            ["table"],
            registry=self.registry,
        )
        self.dq_checks = Gauge(
            "secops_dq_checks_status",
            "Latest data quality check counts by status",
            ["status"],
            registry=self.registry,
        )
        self.api_request_duration = Histogram(
            "secops_api_request_duration_seconds",
            "FastAPI control-plane request latency in seconds",
            ["endpoint", "method", "status"],
            registry=self.registry,
        )

    def render_prometheus(self) -> bytes:
        return generate_latest(self.registry)


METRICS = PlatformMetrics()
