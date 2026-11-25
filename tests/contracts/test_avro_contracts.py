"""Avro v1 & v2 schema contract tests verifying backward/forward compatibility and poison DLQ rejection."""

from __future__ import annotations

import io
from typing import Any

import fastavro

from services.secops_platform.dq import load_avro_schema, validate_and_split_events


def _sample_v1_record() -> dict[str, Any]:
    return {
        "event_id": "evt_contract_001",
        "event_time_ms": 1_795_500_000_000,
        "ingest_time_ms": 1_795_500_000_250,
        "source_stream": "auth",
        "action": "login_success",
        "outcome": "success",
        "actor_email": "alice@acme-secops.example",
        "device_id": "dev-0001",
        "session_id": "ses-0001",
        "token_id": "tok-0001",
        "source_ip": "198.51.100.10",
        "geo_country": "US",
        "geo_lat": 37.7749,
        "geo_lon": -122.4194,
        "target_resource": "idp/sso-login",
        "http_status": 200,
        "bytes_out": 1024,
        "scenario_label": "benign",
        "attack_id": None,
    }


def test_avro_v1_to_v2_backward_compatibility() -> None:
    v1_schema = load_avro_schema(1)
    v2_schema = load_avro_schema(2)
    rec_v1 = _sample_v1_record()

    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, v1_schema, rec_v1)
    buf.seek(0)

    # Read v1-encoded binary payload using v2 reader schema (defaults auto-populated)
    decoded_v2 = fastavro.schemaless_reader(buf, v1_schema, v2_schema)
    assert isinstance(decoded_v2, dict)
    assert decoded_v2["event_id"] == "evt_contract_001"
    assert decoded_v2["nat_egress_flag"] is False
    assert decoded_v2["geo_asn"] == "AS0"
    assert decoded_v2["clock_skew_ms"] == 0
    assert decoded_v2["is_retraction_evidence"] is False
    assert decoded_v2["schema_version"] == 2


def test_avro_v2_to_v1_forward_compatibility() -> None:
    v1_schema = load_avro_schema(1)
    v2_schema = load_avro_schema(2)
    rec_v2 = {
        **_sample_v1_record(),
        "nat_egress_flag": True,
        "geo_asn": "AS15169",
        "clock_skew_ms": -4000,
        "is_retraction_evidence": False,
        "schema_version": 2,
    }

    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, v2_schema, rec_v2)
    buf.seek(0)

    # Read v2-encoded binary payload with older v1 consumer reader schema
    decoded_v1 = fastavro.schemaless_reader(buf, v2_schema, v1_schema)
    assert isinstance(decoded_v1, dict)
    assert decoded_v1["event_id"] == "evt_contract_001"
    assert "nat_egress_flag" not in decoded_v1


def test_poison_records_routed_to_dlq_with_specific_error_codes() -> None:
    records = [
        _sample_v1_record(),
        {"event_id": "", "source_stream": "auth", "event_time_ms": 1000, "source_ip": "1.1.1.1"},
        {"event_id": "e2", "source_stream": "invalid_bus", "event_time_ms": 1000, "source_ip": "1.1.1.1"},
        {"event_id": "e3", "source_stream": "auth", "event_time_ms": -5, "source_ip": "1.1.1.1"},
        {
            "event_id": "e4",
            "source_stream": "auth",
            "event_time_ms": 1_795_500_000_000,
            "ingest_time_ms": 1_795_500_000_100,
            "source_ip": "999.999.999.999",
            "geo_lat": 10.0,
            "geo_lon": 10.0,
        },
    ]
    valid, dlq = validate_and_split_events(records)
    assert len(valid) == 1
    assert len(dlq) == 4
    codes = {row["error_code"] for row in dlq}
    assert codes == {
        "MISSING_EVENT_ID",
        "INVALID_SOURCE_STREAM",
        "INVALID_EVENT_TIME",
        "INVALID_SOURCE_IP",
    }
