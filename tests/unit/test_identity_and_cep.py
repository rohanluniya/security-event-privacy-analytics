"""Unit tests for deterministic generation, NAT-safe identity resolution, and Streaming CEP rules."""

from __future__ import annotations

from pathlib import Path

from ingestion.generator import generate_security_telemetry
from models.contracts import IncidentStatus, SecurityEvent, SourceStream
from processing.cep_engine import CepConfig, StreamingCepEngine
from processing.identity_resolver import IdentityResolver
from services.secops_platform.dq import validate_and_split_events
from services.secops_platform.privacy import PrivacyVault


def test_deterministic_generator_reproducibility() -> None:
    b1 = generate_security_telemetry(seed=77, total_events=1200)
    b2 = generate_security_telemetry(seed=77, total_events=1200)
    assert len(b1.raw_records) == len(b2.raw_records)
    assert [r.get("event_id") for r in b1.raw_records] == [r.get("event_id") for r in b2.raw_records]
    assert b1.ground_truth_attacks == b2.ground_truth_attacks


def test_identity_resolver_never_conflates_shared_nat_ip(tmp_path: Path) -> None:
    vault = PrivacyVault("test-key", "v1", tmp_path / "vault.json")
    resolver = IdentityResolver(vault)
    shared_nat_ip = "198.51.100.10"

    tokens = set()
    for i in range(25):
        ev = SecurityEvent(
            event_id=f"evt_nat_{i}",
            event_time_ms=1_795_500_000_000 + i * 1000,
            ingest_time_ms=1_795_500_000_100 + i * 1000,
            source_stream=SourceStream.AUTH,
            action="login_success",
            outcome="success",
            actor_email=f"employee{i}@acme.example",
            device_id=f"dev-{i}",
            source_ip=shared_nat_ip,
            geo_country="US",
            geo_lat=37.77,
            geo_lon=-122.41,
            target_resource="idp/sso",
            nat_egress_flag=True,
        )
        tokens.add(resolver.resolve(ev))

    assert len(tokens) == 25

    # Endpoint event omitting email still resolves to employee0 via device_id
    ep_ev = SecurityEvent(
        event_id="evt_ep_0",
        event_time_ms=1_795_500_060_000,
        ingest_time_ms=1_795_500_060_200,
        source_stream=SourceStream.ENDPOINT,
        action="process_exec",
        outcome="success",
        actor_email=None,
        device_id="dev-0",
        source_ip=shared_nat_ip,
        geo_country="US",
        geo_lat=37.77,
        geo_lon=-122.41,
        target_resource="workstation/chrome",
        nat_egress_flag=True,
    )
    resolved_ep = resolver.resolve(ep_ev)
    assert resolved_ep == vault.hmac_token("prn", "employee0@acme.example")


def test_cep_nat_aware_reduces_false_positives_and_retracts_clock_skew(tmp_path: Path) -> None:
    batch = generate_security_telemetry(seed=42, total_events=2500)
    valid, dlq = validate_and_split_events(batch.raw_records)
    assert len(dlq) == batch.poison_count

    def run_mode(nat_aware: bool, retract: bool) -> tuple[StreamingCepEngine, dict[str, object]]:
        vault = PrivacyVault("test-key", "v1", tmp_path / f"v_{nat_aware}_{retract}.json")
        resolver = IdentityResolver(vault)
        cep = StreamingCepEngine(
            CepConfig(nat_aware=nat_aware, clock_skew_retraction_enabled=retract)
        )
        for ev in valid:
            prn = resolver.resolve(ev)
            tok = vault.tokenize_event(ev, prn)
            cep.process_event(ev, tok)
        return cep, cep.evaluate_precision_recall(batch.ground_truth_attacks)

    cep_v2, metrics_v2 = run_mode(nat_aware=True, retract=True)
    _, metrics_v1 = run_mode(nat_aware=False, retract=False)

    # NAT-aware + clock-skew retraction achieves zero false positives and 100% recall
    assert metrics_v2["false_positives"] == 0
    assert metrics_v2["recall"] == 1.0
    assert metrics_v2["precision"] == 1.0
    assert int(metrics_v2["retracted_incidents"]) >= 1  # type: ignore[arg-type]

    # NAT-naive v1 suffers false positives from shared corporate NAT & unretracted clock skew
    assert int(metrics_v1["false_positives"]) > int(metrics_v2["false_positives"])  # type: ignore[arg-type]
    assert float(metrics_v1["precision"]) < float(metrics_v2["precision"])  # type: ignore[arg-type]

    # Verify retracted incidents have explicit reason and zero weight in entity risk
    retracted = [i for i in cep_v2.get_incidents() if i.status == IncidentStatus.RETRACTED]
    assert len(retracted) >= 1
    assert all(i.retracted_reason for i in retracted)
    risks = {r.principal_token: r for r in cep_v2.compute_entity_risk_scores()}
    for inc in retracted:
        if risks[inc.principal_token].active_incident_count == 0:
            assert risks[inc.principal_token].risk_score == 0.0
