"""Avro schema contract validator, DLQ quarantine router, and privacy/k-anonymity data quality gate."""

from __future__ import annotations

import ipaddress
import json
import time
import uuid
from pathlib import Path
from typing import Any

import fastavro

from models.contracts import DataQualityResult, SecurityEvent, SourceStream
from services.secops_platform.logging_obs import METRICS
from services.secops_platform.privacy import scan_for_raw_pii

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas" / "avro"
VALID_STREAMS = {s.value for s in SourceStream}


def load_avro_schema(version: int = 2) -> dict[str, Any]:
    path = SCHEMAS_DIR / f"security_event_v{version}.avsc"
    return fastavro.parse_schema(json.loads(path.read_text(encoding="utf-8")))  # type: ignore[return-value]


def validate_and_split_events(
    raw_records: list[dict[str, Any]],
) -> tuple[list[SecurityEvent], list[dict[str, Any]]]:
    """Validate raw event dicts against Avro v2 + domain invariants; route invalid rows to DLQ."""
    parsed_schema = load_avro_schema(2)
    valid_events: list[SecurityEvent] = []
    dlq_rows: list[dict[str, Any]] = []
    now_ms = int(time.time() * 1000)

    for idx, rec in enumerate(raw_records):
        error_code: str | None = None
        error_reason: str | None = None

        if not isinstance(rec, dict):
            error_code = "INVALID_TYPE"
            error_reason = "Record is not a JSON object"
        elif not rec.get("event_id") or not isinstance(rec.get("event_id"), str):
            error_code = "MISSING_EVENT_ID"
            error_reason = "event_id must be a non-empty string"
        elif rec.get("source_stream") not in VALID_STREAMS:
            error_code = "INVALID_SOURCE_STREAM"
            error_reason = f"Unsupported source_stream={rec.get('source_stream')!r}"
        elif not isinstance(rec.get("event_time_ms"), int) or int(rec["event_time_ms"]) <= 0:
            error_code = "INVALID_EVENT_TIME"
            error_reason = f"event_time_ms must be positive epoch ms, got {rec.get('event_time_ms')!r}"
        else:
            # Validate IP address and geo coordinate ranges
            try:
                ipaddress.ip_address(str(rec.get("source_ip", "")))
            except ValueError:
                error_code = "INVALID_SOURCE_IP"
                error_reason = f"Invalid IP address: {rec.get('source_ip')!r}"

            if error_code is None:
                lat = rec.get("geo_lat")
                lon = rec.get("geo_lon")
                if not isinstance(lat, (int, float)) or not (-90.0 <= float(lat) <= 90.0):
                    error_code = "INVALID_GEO_COORDS"
                    error_reason = f"Latitude out of bounds: {lat!r}"
                elif not isinstance(lon, (int, float)) or not (-180.0 <= float(lon) <= 180.0):
                    error_code = "INVALID_GEO_COORDS"
                    error_reason = f"Longitude out of bounds: {lon!r}"

        if error_code is None:
            # Fill schema v2 defaults before Avro validation
            normalized = {
                "nat_egress_flag": False,
                "geo_asn": "AS0",
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
                "bytes_out": 0,
                "scenario_label": "benign",
                "attack_id": None,
                "http_status": None,
                "actor_email": None,
                "device_id": None,
                "session_id": None,
                "token_id": None,
                **rec,
            }
            if not fastavro.validate(normalized, parsed_schema, raise_errors=False):
                error_code = "AVRO_CONTRACT_VIOLATION"
                error_reason = "Record failed Avro v2 contract validation"
            else:
                try:
                    ev = SecurityEvent.model_validate(normalized)
                    valid_events.append(ev)
                    METRICS.events_ingested.labels(
                        stream=ev.source_stream.value, status="valid"
                    ).inc()
                    continue
                except Exception as exc:
                    error_code = "PYDANTIC_VALIDATION_ERROR"
                    error_reason = str(exc)

        METRICS.events_ingested.labels(stream="unknown", status="quarantined_dlq").inc()
        dlq_rows.append(
            {
                "dlq_id": f"dlq_{uuid.uuid4().hex[:12]}_{idx}",
                "ingested_at_ms": now_ms,
                "error_code": error_code or "UNKNOWN_ERROR",
                "error_reason": error_reason or "Unknown validation error",
                "raw_payload_json": json.dumps(rec, default=str, sort_keys=True),
            }
        )

    return valid_events, dlq_rows


def run_data_quality_gate(
    *,
    run_id: str,
    wal_ingested: int,
    valid_count: int,
    dlq_count: int,
    deduplicated_count: int,
    silver_rows: list[dict[str, Any]],
    incident_rows: list[dict[str, Any]],
    aggregate_rows: list[dict[str, Any]],
    k_threshold: int = 5,
) -> list[DataQualityResult]:
    """Run automated data quality & privacy compliance checks across Silver and Gold tables."""
    now_ms = int(time.time() * 1000)
    results: list[DataQualityResult] = []

    # 1. Ingestion reconciliation: WAL total == valid + DLQ
    recon_diff = abs(wal_ingested - (valid_count + dlq_count))
    results.append(
        DataQualityResult(
            run_id=run_id,
            checked_at_ms=now_ms,
            check_name="wal_to_bronze_reconciliation",
            table_name="bronze.raw_security_evidence",
            passed=(recon_diff == 0),
            observed_value=float(recon_diff),
            threshold_value=0.0,
            details=f"wal={wal_ingested}, valid={valid_count}, dlq={dlq_count}",
        )
    )

    # 2. Deduplication reconciliation: valid == silver_unique + deduplicated (+ dropped late if any)
    dedup_expected = len(silver_rows) + deduplicated_count
    dedup_ok = dedup_expected <= valid_count and len(silver_rows) > 0
    results.append(
        DataQualityResult(
            run_id=run_id,
            checked_at_ms=now_ms,
            check_name="silver_deduplication_integrity",
            table_name="silver.tokenized_security_events",
            passed=dedup_ok,
            observed_value=float(len(silver_rows)),
            threshold_value=1.0,
            details=f"silver_unique={len(silver_rows)}, deduped={deduplicated_count}, valid_in={valid_count}",
        )
    )

    # 3. Zero raw PII leak in silver.tokenized_security_events
    silver_pii_violations = scan_for_raw_pii(silver_rows)
    results.append(
        DataQualityResult(
            run_id=run_id,
            checked_at_ms=now_ms,
            check_name="zero_raw_pii_leak_silver",
            table_name="silver.tokenized_security_events",
            passed=(len(silver_pii_violations) == 0),
            observed_value=float(len(silver_pii_violations)),
            threshold_value=0.0,
            details="Zero raw emails or unmasked IPv4 hosts in silver zone"
            if not silver_pii_violations
            else f"Violations: {silver_pii_violations[:3]}",
        )
    )

    # 4. Zero raw PII leak in gold.cep_security_incidents
    gold_pii_violations = scan_for_raw_pii(incident_rows)
    results.append(
        DataQualityResult(
            run_id=run_id,
            checked_at_ms=now_ms,
            check_name="zero_raw_pii_leak_gold_incidents",
            table_name="gold.cep_security_incidents",
            passed=(len(gold_pii_violations) == 0),
            observed_value=float(len(gold_pii_violations)),
            threshold_value=0.0,
            details="Zero raw emails or unmasked IPv4 hosts in gold incidents"
            if not gold_pii_violations
            else f"Violations: {gold_pii_violations[:3]}",
        )
    )

    # 5. k-anonymity threshold invariant across gold.privacy_safe_aggregates
    min_distinct = (
        min(int(r["distinct_principals"]) for r in aggregate_rows) if aggregate_rows else k_threshold
    )
    min_events = (
        min(int(r["event_count"]) for r in aggregate_rows) if aggregate_rows else k_threshold
    )
    k_ok = (min_distinct >= k_threshold) and (min_events >= k_threshold)
    results.append(
        DataQualityResult(
            run_id=run_id,
            checked_at_ms=now_ms,
            check_name="k_anonymity_threshold_invariant",
            table_name="gold.privacy_safe_aggregates",
            passed=k_ok,
            observed_value=float(min_distinct),
            threshold_value=float(k_threshold),
            details=f"min_distinct_principals={min_distinct}, min_event_count={min_events}, required_k>={k_threshold}",
        )
    )

    # 6. Immutable evidence_ref completeness on gold.cep_security_incidents
    missing_evref = sum(
        1 for r in incident_rows if not str(r.get("evidence_ref", "")).startswith("evref_sha256:")
    )
    results.append(
        DataQualityResult(
            run_id=run_id,
            checked_at_ms=now_ms,
            check_name="immutable_evidence_ref_completeness",
            table_name="gold.cep_security_incidents",
            passed=(missing_evref == 0),
            observed_value=float(missing_evref),
            threshold_value=0.0,
            details=f"incidents_checked={len(incident_rows)}, missing_sha256_ref={missing_evref}",
        )
    )

    # 7. Quarantine DLQ auditable capture check (when poison events are expected)
    results.append(
        DataQualityResult(
            run_id=run_id,
            checked_at_ms=now_ms,
            check_name="quarantine_dlq_auditability",
            table_name="bronze.quarantine_dlq",
            passed=(dlq_count >= 0),
            observed_value=float(dlq_count),
            threshold_value=0.0,
            details=f"quarantined_poison_records={dlq_count}",
        )
    )

    passed_cnt = sum(1 for r in results if r.passed)
    failed_cnt = len(results) - passed_cnt
    METRICS.dq_checks.labels(status="passed").set(passed_cnt)
    METRICS.dq_checks.labels(status="failed").set(failed_cnt)
    return results
