"""End-to-end vertical slice test proving deterministic generation, durable WAL replay, and reconciliation."""

from __future__ import annotations

from services.secops_platform.config import PlatformConfig
from services.secops_platform.pipeline import run_end_to_end_pipeline
from services.secops_platform.storage import PrivacyLakehouse


def test_e2e_vertical_slice_and_deterministic_wal_replay(test_config: PlatformConfig) -> None:
    # Run 1: Fresh generation -> WAL -> Avro/DLQ -> Tokenization -> CEP -> Iceberg V2 -> DQ
    s1 = run_end_to_end_pipeline(test_config, seed=101, total_events=2200)
    assert s1.dq_checks_passed == s1.dq_checks_total == 7
    assert s1.events_quarantined_dlq > 0
    assert s1.events_deduplicated > 0
    assert s1.incidents_active > 0
    assert s1.incidents_retracted >= 1
    assert s1.cep_metrics["precision"] == 1.0
    assert s1.cep_metrics["recall"] == 1.0

    lh = PrivacyLakehouse(test_config)
    inc_ids_run1 = sorted(r["incident_id"] for r in lh.read_rows("gold.cep_security_incidents"))
    evrefs_run1 = sorted(r["evidence_ref"] for r in lh.read_rows("gold.cep_security_incidents"))
    silver_count_run1 = lh.table_row_count("silver.tokenized_security_events")

    # Run 2: Replay directly from durable WAL offset 0 without regenerating source data
    s2 = run_end_to_end_pipeline(test_config, seed=101, replay_only=True, reset_wal=False)
    assert s2.dq_checks_passed == s2.dq_checks_total == 7
    assert s2.events_tokenized_silver == s1.events_tokenized_silver
    assert s2.incidents_active == s1.incidents_active
    assert s2.incidents_retracted == s1.incidents_retracted

    inc_ids_run2 = sorted(r["incident_id"] for r in lh.read_rows("gold.cep_security_incidents"))
    evrefs_run2 = sorted(r["evidence_ref"] for r in lh.read_rows("gold.cep_security_incidents"))
    silver_count_run2 = lh.table_row_count("silver.tokenized_security_events")

    assert inc_ids_run1 == inc_ids_run2
    assert evrefs_run1 == evrefs_run2
    assert silver_count_run1 == silver_count_run2
