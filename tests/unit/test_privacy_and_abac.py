"""Unit tests for cryptographic tokenization, masking, PII leak detection, k-anonymity, ABAC, and distributed job builders."""

from __future__ import annotations

from pathlib import Path

from models.contracts import Role, SecurityEvent, SourceStream
from processing.flink.security_cep_job import FlinkJobConfig, build_flink_sql_statements
from processing.spark.retention_and_compaction import build_maintenance_sql
from services.secops_platform.abac import AbacPolicyEngine
from services.secops_platform.config import PlatformConfig
from services.secops_platform.logging_obs import redact_sensitive_text
from services.secops_platform.privacy import (
    PrivacyVault,
    build_privacy_safe_aggregates,
    compute_evidence_ref,
    mask_email,
    mask_ip_subnet,
    scan_for_raw_pii,
)


def test_masking_and_log_redaction() -> None:
    assert mask_email("alice.smith@acme-secops.example") == "a***h@a***.example"
    assert mask_email("ab@corp.io") == "**@c***.io"
    assert mask_ip_subnet("198.51.100.42") == "198.51.100.0/24"
    assert mask_ip_subnet("10.20.30.99") == "10.20.30.0/24"

    redacted = redact_sensitive_text(
        "Login failed for alice@acme.example from 198.51.100.42 subnet 198.51.100.0/24 key secops-dev-ir-lead-key"
    )
    assert "alice@acme.example" not in redacted
    assert "198.51.100.42" not in redacted
    assert "198.51.100.0/24" in redacted
    assert "secops-dev-ir-lead-key" not in redacted


def test_vault_hmac_determinism_and_crypto_shredding(tmp_path: Path) -> None:
    vault = PrivacyVault("unit-test-key", "v1", tmp_path / "keys.json")
    t1 = vault.hmac_token("prn", "alice@acme.example")
    t2 = vault.hmac_token("prn", "ALICE@acme.example")
    assert t1 == t2
    assert t1.startswith("prn_v1_")

    key_id = vault.ensure_subject_key(t1)
    assert key_id.startswith("sbjk_")
    assert not vault.is_subject_shredded(t1)

    res = vault.crypto_shred_subject(t1)
    assert res["shredded"] is True
    assert vault.is_subject_shredded(t1) is True
    assert vault.ensure_subject_key(t1) == "SHREDDED"


def test_pii_leak_scanner_catches_raw_email_and_ip() -> None:
    clean_rows = [
        {
            "principal_token": "prn_v1_abcdef0123456789abcd",
            "masked_email": "a***e@a***.example",
            "ip_subnet_masked": "198.51.100.0/24",
            "summary": "Spray detected from subnet 198.51.100.0/24",
        }
    ]
    assert scan_for_raw_pii(clean_rows) == []

    leaked_rows = [
        {
            "principal_token": "prn_v1_abcdef0123456789abcd",
            "masked_email": "alice@acme.example",
            "ip_subnet_masked": "198.51.100.42",
            "summary": "Raw host 10.0.0.55 leaked",
        }
    ]
    violations = scan_for_raw_pii(leaked_rows)
    assert len(violations) >= 3


def test_k_anonymity_suppresses_small_buckets(tmp_path: Path) -> None:
    vault = PrivacyVault("unit-test-key", "v1", tmp_path / "keys.json")
    tokenized = []
    # 6 distinct users in US -> MUST appear
    for i in range(6):
        ev = SecurityEvent(
            event_id=f"evt_us_{i}",
            event_time_ms=1_795_500_000_000 + i * 1000,
            ingest_time_ms=1_795_500_000_100 + i * 1000,
            source_stream=SourceStream.AUTH,
            action="login_success",
            outcome="success",
            actor_email=f"u{i}@acme.example",
            source_ip="100.64.1.10",
            geo_country="US",
            geo_lat=37.77,
            geo_lon=-122.41,
            target_resource="idp/sso",
        )
        tokenized.append(vault.tokenize_event(ev, vault.hmac_token("prn", f"u{i}@acme.example")))
    # Only 2 distinct users in JP -> MUST be suppressed
    for i in range(2):
        ev = SecurityEvent(
            event_id=f"evt_jp_{i}",
            event_time_ms=1_795_500_000_000 + i * 1000,
            ingest_time_ms=1_795_500_000_100 + i * 1000,
            source_stream=SourceStream.AUTH,
            action="login_success",
            outcome="success",
            actor_email=f"jp{i}@acme.example",
            source_ip="100.64.2.10",
            geo_country="JP",
            geo_lat=35.67,
            geo_lon=139.65,
            target_resource="idp/sso",
        )
        tokenized.append(vault.tokenize_event(ev, vault.hmac_token("prn", f"jp{i}@acme.example")))

    aggs, suppressed = build_privacy_safe_aggregates(tokenized, k_threshold=5)
    assert suppressed == 1
    assert len(aggs) == 1
    assert aggs[0].geo_country == "US"
    assert aggs[0].distinct_principals == 6


def test_abac_policy_enforcement_and_separation_of_duties(test_config: PlatformConfig) -> None:
    engine = AbacPolicyEngine(test_config)

    # Unauthenticated always denied
    assert not engine.evaluate(authenticated=False, role=None, resource="overview").allow

    # analyst_privacy_safe allowed aggregates, denied incidents & raw evidence
    assert engine.evaluate(
        authenticated=True, role=Role.ANALYST_PRIVACY_SAFE.value, resource="privacy_safe_aggregates"
    ).allow
    assert not engine.evaluate(
        authenticated=True, role=Role.ANALYST_PRIVACY_SAFE.value, resource="incidents_read"
    ).allow
    assert not engine.evaluate(
        authenticated=True,
        role=Role.ANALYST_PRIVACY_SAFE.value,
        resource="raw_evidence_read",
        justification="long valid justification string",
    ).allow

    # soc_responder allowed incidents, denied raw evidence
    assert engine.evaluate(
        authenticated=True, role=Role.SOC_RESPONDER.value, resource="incidents_read"
    ).allow
    assert not engine.evaluate(
        authenticated=True,
        role=Role.SOC_RESPONDER.value,
        resource="raw_evidence_read",
        justification="long valid justification string",
    ).allow

    # ir_lead_raw_evidence requires justification >= 12 chars, denied GDPR erasure
    assert not engine.evaluate(
        authenticated=True,
        role=Role.IR_LEAD_RAW_EVIDENCE.value,
        resource="raw_evidence_read",
        justification="short",
    ).allow
    assert engine.evaluate(
        authenticated=True,
        role=Role.IR_LEAD_RAW_EVIDENCE.value,
        resource="raw_evidence_read",
        justification="INC-2026-0042 confirmed lateral movement forensics",
    ).allow
    assert not engine.evaluate(
        authenticated=True, role=Role.IR_LEAD_RAW_EVIDENCE.value, resource="privacy_erase"
    ).allow

    # privacy_officer allowed GDPR erasure & retention sweep, denied raw evidence
    assert engine.evaluate(
        authenticated=True, role=Role.PRIVACY_OFFICER.value, resource="privacy_erase"
    ).allow
    assert engine.evaluate(
        authenticated=True, role=Role.PRIVACY_OFFICER.value, resource="retention_sweep"
    ).allow
    assert not engine.evaluate(
        authenticated=True,
        role=Role.PRIVACY_OFFICER.value,
        resource="raw_evidence_read",
        justification="long justification string for audit",
    ).allow


def test_evidence_ref_and_distributed_sql_builders() -> None:
    ref1 = compute_evidence_ref(["evt_b", "evt_a"], "lateral_movement@v2")
    ref2 = compute_evidence_ref(["evt_a", "evt_b", "evt_a"], "lateral_movement@v2")
    assert ref1 == ref2
    assert ref1.startswith("evref_sha256:")

    flink_stmts = build_flink_sql_statements(FlinkJobConfig())
    assert len(flink_stmts) == 4
    assert "WATERMARK FOR event_ts" in flink_stmts[0]
    assert "nat_egress_flag = FALSE" in flink_stmts[2]

    spark_stmts = build_maintenance_sql(
        raw_cutoff_ms=1000,
        silver_cutoff_ms=500,
        erase_principal_token="prn_v1_abc",
    )
    assert len(spark_stmts) == 9
    assert any("rewrite_data_files" in s for s in spark_stmts)
    assert any("prn_v1_abc" in s for s in spark_stmts)
