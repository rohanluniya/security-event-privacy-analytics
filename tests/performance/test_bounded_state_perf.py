"""Performance regression test confirming bounded CEP state under high-cardinality traffic."""

from __future__ import annotations

import time
from pathlib import Path

from models.contracts import SecurityEvent, SourceStream
from processing.cep_engine import CepConfig, StreamingCepEngine
from services.secops_platform.privacy import PrivacyVault


def test_bounded_state_eviction_and_throughput(tmp_path: Path) -> None:
    vault = PrivacyVault("perf-test-key", "v1", tmp_path / "vault.json")
    cfg = CepConfig(
        max_dedup_ids=500,
        max_ip_keys=200,
        max_principal_keys=200,
        max_token_keys=200,
    )
    cep = StreamingCepEngine(cfg)

    t0 = time.perf_counter()
    total = 2500
    for i in range(total):
        ev = SecurityEvent(
            event_id=f"evt_hc_{i}",
            event_time_ms=1_795_500_000_000 + i * 50,
            ingest_time_ms=1_795_500_000_050 + i * 50,
            source_stream=SourceStream.AUTH,
            action="login_failed",
            outcome="failure",
            actor_email=f"carduser{i}@acme.example",
            device_id=f"dev-{i}",
            token_id=f"tok-{i}",
            source_ip=f"192.0.{(i // 250) % 255}.{(i % 250) + 1}",
            geo_country="US",
            geo_lat=37.77,
            geo_lon=-122.41,
            target_resource="idp/sso",
        )
        prn = vault.hmac_token("prn", ev.actor_email or "anon")
        tok = vault.tokenize_event(ev, prn)
        cep.process_event(ev, tok)
    elapsed = time.perf_counter() - t0

    # Strict bounded state cap: sum of max caps = 500 + 200 + 200 + 200 + 200 + 200 = 1500
    assert cep.metrics.peak_state_entries <= 1500
    assert cep.current_state_entries <= 1500
    assert total / max(elapsed, 0.001) > 1000.0
