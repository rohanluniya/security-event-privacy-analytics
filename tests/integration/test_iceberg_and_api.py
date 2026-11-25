"""Integration tests for Apache Iceberg V2, DuckDB queries, snapshot time-travel, compaction, and FastAPI RBAC/ABAC."""

from __future__ import annotations

from fastapi.testclient import TestClient

from services.secops_platform.api import create_app
from services.secops_platform.config import PlatformConfig
from services.secops_platform.pipeline import run_end_to_end_pipeline
from services.secops_platform.storage import PrivacyLakehouse


def test_iceberg_time_travel_duckdb_and_compaction(test_config: PlatformConfig) -> None:
    run_end_to_end_pipeline(test_config, seed=42, total_events=1200)
    lh = PrivacyLakehouse(test_config)

    # Append 5 small micro-batches to simulate small-file fragmentation in Silver
    sample_rows = lh.read_rows("silver.tokenized_security_events")[:20]
    for idx in range(5):
        batch = []
        for r in sample_rows:
            clone = dict(r)
            clone["event_id"] = f"{r['event_id']}_micro_{idx}"
            batch.append(clone)
        lh.append_rows("silver.tokenized_security_events", batch)

    snaps = lh.table_snapshots("silver.tokenized_security_events")
    assert len(snaps) >= 6

    # Time-travel to initial snapshot vs latest snapshot
    first_snap_rows = lh.read_arrow(
        "silver.tokenized_security_events", snapshot_id=snaps[0]["snapshot_id"]
    ).num_rows
    latest_rows = lh.table_row_count("silver.tokenized_security_events")
    assert latest_rows == first_snap_rows + 100

    # Compact fragmented Parquet files and verify file count decreases with zero row loss
    compaction = lh.compact_table("silver.tokenized_security_events")
    assert compaction["data_files_before"] > compaction["data_files_after"]
    assert compaction["row_count"] == latest_rows

    # DuckDB analytical query against gold.privacy_safe_aggregates proves k-anonymity >= 5
    violations = lh.run_duckdb_query(
        "gold.privacy_safe_aggregates",
        "SELECT COUNT(*) AS bad FROM gold_privacy_safe_aggregates WHERE distinct_principals < 5 OR event_count < 5",
    )
    assert violations[0]["bad"] == 0


def test_fastapi_rbac_abac_disposition_erasure_and_retention(test_config: PlatformConfig) -> None:
    run_end_to_end_pipeline(test_config, seed=42, total_events=1800)
    app = create_app(test_config)
    client = TestClient(app)

    k_analyst = {"X-API-Key": test_config.role_api_keys["analyst_privacy_safe"]}
    k_soc = {"X-API-Key": test_config.role_api_keys["soc_responder"]}
    k_ir = {"X-API-Key": test_config.role_api_keys["ir_lead_raw_evidence"]}
    k_priv = {"X-API-Key": test_config.role_api_keys["privacy_officer"]}

    # 1. Public health and Prometheus metrics
    h = client.get("/health")
    assert h.status_code == 200
    assert h.json()["status"] == "healthy"
    assert h.json()["tables"]["silver_tokenized_security_events"] > 0

    m = client.get("/metrics")
    assert m.status_code == 200
    assert "secops_events_ingested_total" in m.text

    # 2. Unauthenticated request -> HTTP 401
    assert client.get("/v1/overview").status_code == 401
    assert client.get("/v1/overview", headers={"X-API-Key": "invalid-key"}).status_code == 401

    # 3. analyst_privacy_safe: allowed overview & privacy-safe aggregates, DENIED incidents & raw evidence
    ov = client.get("/v1/overview", headers=k_analyst)
    assert ov.status_code == 200
    sample_event_id = ov.json()["sample_evidence_event_ids"][0]
    gdpr_token = ov.json()["gdpr_candidate_tokens"][0]

    agg = client.get("/v1/aggregates/privacy-safe", headers=k_analyst)
    assert agg.status_code == 200
    assert agg.json()["total"] > 0
    assert all(row["distinct_principals"] >= 5 for row in agg.json()["items"])

    assert client.get("/v1/incidents", headers=k_analyst).status_code == 403
    assert client.get("/v1/entities/risk", headers=k_analyst).status_code == 403
    assert client.get(f"/v1/evidence/raw/{sample_event_id}", headers=k_analyst).status_code == 403
    assert client.post(f"/v1/privacy/erase/{gdpr_token}", headers=k_analyst).status_code == 403

    # 4. soc_responder: allowed incidents & disposition, DENIED raw evidence & GDPR erasure
    incs = client.get("/v1/incidents", headers=k_soc)
    assert incs.status_code == 200
    first_inc_id = incs.json()["items"][0]["incident_id"]

    disp = client.post(
        f"/v1/incidents/{first_inc_id}/disposition",
        headers=k_soc,
        json={"status": "CONFIRMED_TP", "note": "Verified malicious IP spray in SOC triage"},
    )
    assert disp.status_code == 200
    assert disp.json()["incident"]["status"] == "CONFIRMED_TP"

    assert client.get(f"/v1/evidence/raw/{sample_event_id}", headers=k_soc).status_code == 403
    assert client.post(f"/v1/privacy/erase/{gdpr_token}", headers=k_soc).status_code == 403

    # 5. ir_lead_raw_evidence: DENIED without justification, ALLOWED with justification + audited, DENIED erasure
    assert client.get(f"/v1/evidence/raw/{sample_event_id}", headers=k_ir).status_code == 403
    assert (
        client.get(
            f"/v1/evidence/raw/{sample_event_id}",
            headers={**k_ir, "X-Justification": "too short"},
        ).status_code
        == 403
    )
    raw_ok = client.get(
        f"/v1/evidence/raw/{sample_event_id}",
        headers={**k_ir, "X-Justification": "INC-2026-0091 confirmed credential stuffing forensics"},
    )
    assert raw_ok.status_code == 200
    assert raw_ok.json()["evidence"]["event_id"] == sample_event_id
    assert raw_ok.json()["audit_id"].startswith("aud_")

    # Separation of duties: IR Lead cannot perform GDPR erasure or retention sweep
    assert client.post(f"/v1/privacy/erase/{gdpr_token}", headers=k_ir).status_code == 403
    assert client.post("/v1/privacy/retention-sweep", headers=k_ir).status_code == 403

    # 6. privacy_officer: DENIED raw evidence, ALLOWED GDPR erasure & retention sweep
    assert (
        client.get(
            f"/v1/evidence/raw/{sample_event_id}",
            headers={**k_priv, "X-Justification": "INC-2026-0091 attempting raw evidence read"},
        ).status_code
        == 403
    )

    agg_count_before = len(client.get("/v1/aggregates/privacy-safe", headers=k_priv).json()["items"])
    erase_resp = client.post(
        f"/v1/privacy/erase/{gdpr_token}",
        headers={**k_priv, "X-Justification": "GDPR Article 17 verified erasure request #401"},
    )
    assert erase_resp.status_code == 200
    body = erase_resp.json()
    assert body["crypto_shredded"] is True
    assert body["remaining_raw_rows"] == 0
    assert body["remaining_tokenized_rows"] == 0
    assert body["privacy_safe_aggregates_preserved"] == agg_count_before

    # Verify erased subject truly has 0 rows in bronze/silver/identity map
    lh = PrivacyLakehouse(test_config)
    for tbl in (
        "bronze.raw_security_evidence",
        "silver.tokenized_security_events",
        "silver.identity_resolution_map",
    ):
        rem = [r for r in lh.read_rows(tbl) if r["principal_token"] == gdpr_token]
        assert len(rem) == 0

    # 7. Retention TTL sweep purges aged 10-day raw records while keeping fresh events
    ret_resp = client.post("/v1/privacy/retention-sweep", headers=k_priv)
    assert ret_resp.status_code == 200
    assert ret_resp.json()["purged_rows"]["bronze.raw_security_evidence"] >= 10
    assert ret_resp.json()["remaining_rows"]["bronze.raw_security_evidence"] > 500

    # 8. Audit log records denials, break-glass reads, GDPR erasure, and retention sweeps
    audit = client.get("/v1/audit", headers=k_priv)
    assert audit.status_code == 200
    action_types = {a["action_type"] for a in audit.json()["items"]}
    assert "ABAC_ACCESS_DENIED" in action_types
    assert "BREAK_GLASS_RAW_EVIDENCE_READ" in action_types
    assert "GDPR_SUBJECT_ERASURE" in action_types
    assert "RETENTION_TTL_SWEEP" in action_types
