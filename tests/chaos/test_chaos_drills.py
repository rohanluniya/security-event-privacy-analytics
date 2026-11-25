"""Eight automated chaos & fault-injection drills verifying security, privacy, and resilience invariants."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from ingestion.generator import generate_security_telemetry
from ingestion.wal_broker import DurableWalBroker
from models.contracts import IncidentStatus
from services.secops_platform.api import create_app
from services.secops_platform.config import PlatformConfig
from services.secops_platform.pipeline import CONSUMER_GROUP, RAW_TOPIC, run_end_to_end_pipeline
from services.secops_platform.privacy import PrivacyVault
from services.secops_platform.storage import PrivacyLakehouse

CHAOS_RESULTS_PATH = Path(__file__).resolve().parents[2] / "results" / "chaos" / "chaos_results.json"


def _record_drill(drill_id: str, title: str, passed: bool, metrics: dict[str, Any]) -> None:
    CHAOS_RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CHAOS_RESULTS_PATH.exists():
        data = json.loads(CHAOS_RESULTS_PATH.read_text(encoding="utf-8"))
    else:
        data = {"suite": "security-event-privacy-analytics-chaos-drills", "drills": {}}
    data["drills"][drill_id] = {
        "title": title,
        "passed": passed,
        "recorded_at_ms": int(time.time() * 1000),
        "metrics": metrics,
    }
    drills = data["drills"]
    data["summary"] = {
        "total_drills": len(drills),
        "passed_drills": sum(1 for d in drills.values() if d["passed"]),
        "failed_drills": sum(1 for d in drills.values() if not d["passed"]),
    }
    CHAOS_RESULTS_PATH.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def test_drill_01_credential_stuffing_plus_noisy_nat_storm(tmp_path: Path) -> None:
    cfg_v2 = PlatformConfig(data_dir=tmp_path / "nat_v2")
    cfg_v1 = PlatformConfig(data_dir=tmp_path / "nat_v1")

    s_v2 = run_end_to_end_pipeline(cfg_v2, seed=42, total_events=3000, nat_aware=True)
    s_v1 = run_end_to_end_pipeline(cfg_v1, seed=42, total_events=3000, nat_aware=False)

    fp_v2 = int(s_v2.cep_metrics["false_positives"])
    fp_v1 = int(s_v1.cep_metrics["false_positives"])
    passed = (
        fp_v2 == 0
        and fp_v1 > 0
        and float(s_v2.cep_metrics["recall"]) == 1.0
        and float(s_v2.cep_metrics["precision"]) == 1.0
    )
    _record_drill(
        "drill_01_credential_stuffing_plus_noisy_nat_storm",
        "Credential stuffing amid shared corporate NAT login storm (NAT-aware v2 vs NAT-naive v1)",
        passed,
        {
            "nat_naive_v1_false_positives": fp_v1,
            "nat_naive_v1_precision": s_v1.cep_metrics["precision"],
            "nat_aware_v2_false_positives": fp_v2,
            "nat_aware_v2_precision": s_v2.cep_metrics["precision"],
            "nat_aware_v2_recall": s_v2.cep_metrics["recall"],
        },
    )
    assert passed


def test_drill_02_clock_skewed_impossible_travel_retraction(tmp_path: Path) -> None:
    cfg = PlatformConfig(data_dir=tmp_path / "skew")
    summary = run_end_to_end_pipeline(cfg, seed=42, total_events=3000)
    lh = PrivacyLakehouse(cfg)
    incidents = lh.read_rows("gold.cep_security_incidents")
    retracted = [i for i in incidents if i["status"] == IncidentStatus.RETRACTED.value]
    risk_by_tok = {r["principal_token"]: r for r in lh.read_rows("gold.entity_risk_scores")}

    retracted_zero_risk = all(
        risk_by_tok[r["principal_token"]]["risk_score"] == 0.0
        for r in retracted
        if risk_by_tok[r["principal_token"]]["active_incident_count"] == 0
    )
    passed = len(retracted) >= 2 and all(bool(r["retracted_reason"]) for r in retracted) and retracted_zero_risk
    _record_drill(
        "drill_02_clock_skewed_impossible_travel_retraction",
        "Clock-skewed false impossible-travel alert retracted by late NTP/MFA event",
        passed,
        {
            "retracted_incidents": len(retracted),
            "active_incidents": summary.incidents_active,
            "retracted_entities_zero_risk": retracted_zero_risk,
        },
    )
    assert passed


def test_drill_03_unauthorized_raw_evidence_abac_rejection(tmp_path: Path) -> None:
    cfg = PlatformConfig(data_dir=tmp_path / "abac")
    run_end_to_end_pipeline(cfg, seed=42, total_events=1500)
    client = TestClient(create_app(cfg))

    ov = client.get("/v1/overview", headers={"X-API-Key": cfg.role_api_keys["ir_lead_raw_evidence"]})
    ev_id = ov.json()["sample_evidence_event_ids"][0]

    statuses = {
        "unauthenticated": client.get(f"/v1/evidence/raw/{ev_id}").status_code,
        "analyst_privacy_safe": client.get(
            f"/v1/evidence/raw/{ev_id}",
            headers={"X-API-Key": cfg.role_api_keys["analyst_privacy_safe"]},
        ).status_code,
        "soc_responder": client.get(
            f"/v1/evidence/raw/{ev_id}",
            headers={"X-API-Key": cfg.role_api_keys["soc_responder"]},
        ).status_code,
        "privacy_officer": client.get(
            f"/v1/evidence/raw/{ev_id}",
            headers={"X-API-Key": cfg.role_api_keys["privacy_officer"]},
        ).status_code,
        "ir_lead_missing_justification": client.get(
            f"/v1/evidence/raw/{ev_id}",
            headers={"X-API-Key": cfg.role_api_keys["ir_lead_raw_evidence"]},
        ).status_code,
        "ir_lead_with_justification": client.get(
            f"/v1/evidence/raw/{ev_id}",
            headers={
                "X-API-Key": cfg.role_api_keys["ir_lead_raw_evidence"],
                "X-Justification": "INC-2026-CH03 authorized forensic inspection",
            },
        ).status_code,
    }
    lh = PrivacyLakehouse(cfg)
    denial_audits = [
        a for a in lh.read_rows("gold.retention_and_erasure_audit") if a["action_type"] == "ABAC_ACCESS_DENIED"
    ]
    passed = (
        statuses["unauthenticated"] == 401
        and statuses["analyst_privacy_safe"] == 403
        and statuses["soc_responder"] == 403
        and statuses["privacy_officer"] == 403
        and statuses["ir_lead_missing_justification"] == 403
        and statuses["ir_lead_with_justification"] == 200
        and len(denial_audits) >= 5
    )
    _record_drill(
        "drill_03_unauthorized_raw_evidence_abac_rejection",
        "Unauthorized raw-evidence & unjustified break-glass requests rejected with 401/403 and audited",
        passed,
        {"http_status_matrix": statuses, "logged_denial_audits": len(denial_audits)},
    )
    assert passed


def test_drill_04_gdpr_subject_erasure_and_crypto_shredding(tmp_path: Path) -> None:
    cfg = PlatformConfig(data_dir=tmp_path / "gdpr")
    run_end_to_end_pipeline(cfg, seed=42, total_events=1800)
    meta = json.loads(cfg.metadata_file_path.read_text(encoding="utf-8"))
    target_token = meta["gdpr_candidate_tokens"][0]

    lh = PrivacyLakehouse(cfg)
    vault = PrivacyVault(cfg.hmac_master_key, cfg.key_version, cfg.vault_file_path)
    raw_before = sum(1 for r in lh.read_rows("bronze.raw_security_evidence") if r["principal_token"] == target_token)
    silver_before = sum(1 for r in lh.read_rows("silver.tokenized_security_events") if r["principal_token"] == target_token)
    aggs_before = lh.table_row_count("gold.privacy_safe_aggregates")

    erasure = lh.erase_subject_gdpr(
        principal_token=target_token,
        vault=vault,
        actor_id="chaos-privacy-officer",
        actor_role="privacy_officer",
        justification="GDPR Article 17 Chaos Drill Erasure",
    )

    raw_after = sum(1 for r in lh.read_rows("bronze.raw_security_evidence") if r["principal_token"] == target_token)
    silver_after = sum(1 for r in lh.read_rows("silver.tokenized_security_events") if r["principal_token"] == target_token)
    idmap_after = sum(1 for r in lh.read_rows("silver.identity_resolution_map") if r["principal_token"] == target_token)
    aggs_after = lh.table_row_count("gold.privacy_safe_aggregates")

    passed = (
        raw_before > 0
        and silver_before > 0
        and raw_after == 0
        and silver_after == 0
        and idmap_after == 0
        and vault.is_subject_shredded(target_token)
        and aggs_after == aggs_before
    )
    _record_drill(
        "drill_04_gdpr_subject_erasure_and_crypto_shredding",
        "GDPR Article 17 crypto-shredding & subject purge leaves 0 subject rows while preserving k-anon aggregates",
        passed,
        {
            "raw_before": raw_before,
            "silver_before": silver_before,
            "raw_after": raw_after,
            "silver_after": silver_after,
            "identity_map_after": idmap_after,
            "vault_key_shredded": vault.is_subject_shredded(target_token),
            "aggregates_preserved": aggs_after,
            "audit_id": erasure["audit_id"],
        },
    )
    assert passed


def test_drill_05_retention_window_ttl_purge(tmp_path: Path) -> None:
    cfg = PlatformConfig(data_dir=tmp_path / "retention", raw_retention_days=7)
    base_ms = 1_795_500_000_000
    run_end_to_end_pipeline(cfg, seed=42, total_events=1600, base_time_ms=base_ms)
    lh = PrivacyLakehouse(cfg)
    raw_before = lh.table_row_count("bronze.raw_security_evidence")

    res = lh.run_retention_sweep(
        reference_time_ms=base_ms + 3_600_000,
        actor_id="chaos-privacy-officer",
        actor_role="privacy_officer",
    )
    purged_raw = int(res["purged_rows"]["bronze.raw_security_evidence"])
    remaining_raw = int(res["remaining_rows"]["bronze.raw_security_evidence"])
    cutoff_ms = (base_ms + 3_600_000) - 7 * 86_400 * 1000
    still_expired = sum(
        1 for r in lh.read_rows("bronze.raw_security_evidence") if int(r["event_time_ms"]) < cutoff_ms
    )

    passed = purged_raw >= 15 and still_expired == 0 and remaining_raw == (raw_before - purged_raw)
    _record_drill(
        "drill_05_retention_window_ttl_purge",
        "7-day raw evidence retention TTL sweep purges expired historical records and preserves fresh evidence",
        passed,
        {
            "raw_before": raw_before,
            "purged_expired_rows": purged_raw,
            "remaining_fresh_rows": remaining_raw,
            "expired_rows_remaining": still_expired,
            "audit_id": res["audit_id"],
        },
    )
    assert passed


def test_drill_06_broker_outage_wal_crash_recovery(tmp_path: Path) -> None:
    cfg = PlatformConfig(data_dir=tmp_path / "wal_crash")
    s_initial = run_end_to_end_pipeline(cfg, seed=99, total_events=1800)
    lh = PrivacyLakehouse(cfg)
    initial_inc_ids = sorted(r["incident_id"] for r in lh.read_rows("gold.cep_security_incidents"))

    # Simulate consumer crash mid-processing: rewind offset to partial mid-point & wipe derived Silver/Gold tables
    broker = DurableWalBroker(cfg.wal_dir)
    wal_total = broker.topic_count(RAW_TOPIC)
    broker.commit_offset(CONSUMER_GROUP, RAW_TOPIC, wal_total // 2)
    lh.overwrite_rows("silver.tokenized_security_events", [])
    lh.overwrite_rows("gold.cep_security_incidents", [])
    assert lh.table_row_count("silver.tokenized_security_events") == 0

    # Recover by replaying durable WAL from offset 0
    s_recovered = run_end_to_end_pipeline(cfg, seed=99, replay_only=True, reset_wal=False)
    recovered_inc_ids = sorted(r["incident_id"] for r in lh.read_rows("gold.cep_security_incidents"))

    passed = (
        s_recovered.events_tokenized_silver == s_initial.events_tokenized_silver
        and recovered_inc_ids == initial_inc_ids
        and broker.get_committed_offset(CONSUMER_GROUP, RAW_TOPIC) == wal_total
    )
    _record_drill(
        "drill_06_broker_outage_wal_crash_recovery",
        "Mid-stream consumer crash & derived state wipe recovered bit-identically via durable WAL replay",
        passed,
        {
            "wal_total_records": wal_total,
            "initial_silver_rows": s_initial.events_tokenized_silver,
            "recovered_silver_rows": s_recovered.events_tokenized_silver,
            "incident_ids_identical": recovered_inc_ids == initial_inc_ids,
        },
    )
    assert passed


def test_drill_07_schema_invalid_poison_dlq_quarantine(tmp_path: Path) -> None:
    cfg = PlatformConfig(data_dir=tmp_path / "poison")
    batch = generate_security_telemetry(seed=55, total_events=1500, include_poison_events=True)
    # Inject 25 additional severe poison payloads of varied corruption types
    extra_poison = [
        {"event_id": "", "source_stream": "auth"},
        {"event_id": "bad_ip", "event_time_ms": 1_795_500_000_000, "ingest_time_ms": 1_795_500_000_100, "source_stream": "dns", "action": "dns_query", "outcome": "success", "source_ip": "300.1.2.3", "geo_country": "US", "geo_lat": 10.0, "geo_lon": 10.0, "target_resource": "x"},
        {"event_id": "bad_lat", "event_time_ms": 1_795_500_000_000, "ingest_time_ms": 1_795_500_000_100, "source_stream": "proxy", "action": "http_request", "outcome": "success", "source_ip": "10.0.0.1", "geo_country": "US", "geo_lat": 145.0, "geo_lon": 10.0, "target_resource": "x"},
    ] * 8
    batch.raw_records.extend(extra_poison)
    expected_dlq = batch.poison_count + len(extra_poison)

    summary = run_end_to_end_pipeline(cfg, seed=55, batch_override=batch)
    lh = PrivacyLakehouse(cfg)
    dlq_rows = lh.read_rows("bronze.quarantine_dlq")
    passed = (
        len(dlq_rows) == expected_dlq
        and summary.dq_checks_passed == summary.dq_checks_total == 7
        and summary.events_tokenized_silver > 900
    )
    _record_drill(
        "drill_07_schema_invalid_poison_dlq_quarantine",
        "Malformed poison telemetry flood quarantined in bronze.quarantine_dlq with zero pipeline failures",
        passed,
        {
            "injected_poison_records": expected_dlq,
            "quarantined_dlq_rows": len(dlq_rows),
            "valid_silver_processed": summary.events_tokenized_silver,
            "dq_checks_passed": f"{summary.dq_checks_passed}/{summary.dq_checks_total}",
        },
    )
    assert passed


def test_drill_08_duplicate_replay_idempotency_storm(tmp_path: Path) -> None:
    cfg_base = PlatformConfig(data_dir=tmp_path / "dup_base")
    cfg_storm = PlatformConfig(data_dir=tmp_path / "dup_storm")

    base_batch = generate_security_telemetry(seed=88, total_events=1500)
    s_base = run_end_to_end_pipeline(cfg_base, seed=88, batch_override=base_batch)

    # Triple-duplicate 200 valid events to create an aggressive at-least-once delivery storm
    storm_batch = generate_security_telemetry(seed=88, total_events=1500)
    valid_streams = {"auth", "endpoint", "dns", "proxy", "api_gateway", "application"}
    valid_slice = [
        r
        for r in storm_batch.raw_records
        if isinstance(r.get("event_time_ms"), int)
        and r["event_time_ms"] > 0
        and r.get("event_id")
        and r.get("source_stream") in valid_streams
    ][:200]
    for _ in range(3):
        for r in valid_slice:
            dup = dict(r)
            dup["ingest_time_ms"] = int(dup["ingest_time_ms"]) + 1500
            storm_batch.raw_records.append(dup)

    s_storm = run_end_to_end_pipeline(cfg_storm, seed=88, batch_override=storm_batch)
    passed = (
        s_storm.events_tokenized_silver == s_base.events_tokenized_silver
        and s_storm.incidents_active == s_base.incidents_active
        and s_storm.events_deduplicated >= s_base.events_deduplicated + 600
    )
    _record_drill(
        "drill_08_duplicate_replay_idempotency_storm",
        "3x at-least-once duplicate storm absorbed idempotently with zero row or incident inflation",
        passed,
        {
            "extra_duplicates_injected": 600,
            "base_silver_rows": s_base.events_tokenized_silver,
            "storm_silver_rows": s_storm.events_tokenized_silver,
            "base_incidents": s_base.incidents_active,
            "storm_incidents": s_storm.incidents_active,
            "total_deduplicated": s_storm.events_deduplicated,
        },
    )
    assert passed
