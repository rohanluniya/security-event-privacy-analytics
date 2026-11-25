"""Pydantic v2 domain models for security events, CEP incidents, privacy controls, and audit logs."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SourceStream(StrEnum):
    AUTH = "auth"
    ENDPOINT = "endpoint"
    DNS = "dns"
    PROXY = "proxy"
    API_GATEWAY = "api_gateway"
    APPLICATION = "application"


class Role(StrEnum):
    ANALYST_PRIVACY_SAFE = "analyst_privacy_safe"
    SOC_RESPONDER = "soc_responder"
    IR_LEAD_RAW_EVIDENCE = "ir_lead_raw_evidence"
    PRIVACY_OFFICER = "privacy_officer"


class IncidentStatus(StrEnum):
    NEW = "NEW"
    TRIAGING = "TRIAGING"
    CONFIRMED_TP = "CONFIRMED_TP"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RETRACTED = "RETRACTED"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEvent(BaseModel):
    event_id: str
    event_time_ms: int
    ingest_time_ms: int
    source_stream: SourceStream
    action: str
    outcome: str
    actor_email: str | None = None
    device_id: str | None = None
    session_id: str | None = None
    token_id: str | None = None
    source_ip: str
    geo_country: str
    geo_lat: float
    geo_lon: float
    target_resource: str
    http_status: int | None = None
    bytes_out: int = 0
    scenario_label: str = "benign"
    attack_id: str | None = None
    nat_egress_flag: bool = False
    geo_asn: str = "AS0"
    clock_skew_ms: int = 0
    is_retraction_evidence: bool = False
    schema_version: int = 2


class TokenizedSecurityEvent(BaseModel):
    event_id: str
    event_time_ms: int
    ingest_time_ms: int
    event_date: str
    source_stream: str
    action: str
    outcome: str
    principal_token: str
    masked_email: str | None = None
    device_token: str | None = None
    session_token: str | None = None
    token_hash: str | None = None
    ip_token: str
    ip_subnet_masked: str
    geo_country: str
    geo_lat_coarse: float
    geo_lon_coarse: float
    geo_asn: str
    nat_egress_flag: bool
    target_resource: str
    http_status: int | None = None
    bytes_out: int
    clock_skew_ms: int
    is_retraction_evidence: bool
    key_version: str
    evidence_ref: str
    scenario_label: str = "benign"
    attack_id: str | None = None
    schema_version: int = 2


class CepIncident(BaseModel):
    incident_id: str
    rule_id: str
    rule_version: str
    rule_ref: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.NEW
    principal_token: str
    masked_email: str | None = None
    ip_subnet_masked: str
    geo_country: str
    first_event_time_ms: int
    last_event_time_ms: int
    detected_at_ms: int
    detection_delay_ms: int
    event_count: int
    evidence_event_ids: list[str]
    evidence_ref: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    summary: str
    retracted_reason: str | None = None
    disposition_by: str | None = None
    disposition_note: str | None = None
    disposition_at_ms: int | None = None
    ground_truth_attack_id: str | None = None


class DispositionUpdateRequest(BaseModel):
    status: IncidentStatus
    note: str = Field(min_length=4, max_length=500)


class EntityRiskScore(BaseModel):
    principal_token: str
    masked_email: str | None = None
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_tier: str
    active_incident_count: int
    retracted_incident_count: int
    rules_triggered: list[str]
    last_seen_ms: int
    updated_at_ms: int


class PrivacySafeAggregate(BaseModel):
    bucket_date: str
    source_stream: str
    geo_country: str
    action: str
    event_count: int
    distinct_principals: int
    failure_count: int
    bytes_out_sum: int
    k_anonymity_threshold: int
    suppressed_buckets_merged: int = 0


class AuditLogEntry(BaseModel):
    audit_id: str
    event_time_ms: int
    action_type: str
    actor_id: str
    actor_role: str
    target_resource: str
    decision: str
    justification: str | None = None
    details_json: str


class DataQualityResult(BaseModel):
    run_id: str
    checked_at_ms: int
    check_name: str
    table_name: str
    passed: bool
    observed_value: float
    threshold_value: float
    details: str


class PipelineRunSummary(BaseModel):
    run_id: str
    seed: int
    events_generated: int
    events_ingested_wal: int
    events_quarantined_dlq: int
    events_deduplicated: int
    events_tokenized_silver: int
    incidents_active: int
    incidents_retracted: int
    entity_risk_rows: int
    privacy_safe_buckets: int
    privacy_suppressed_buckets: int
    dq_checks_passed: int
    dq_checks_total: int
    cep_metrics: dict[str, Any]
    wall_time_ms: float
