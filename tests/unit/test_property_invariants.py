"""Hypothesis property-based tests proving privacy, k-anonymity, ABAC, and NAT non-conflation invariants."""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from models.contracts import Role, SecurityEvent, SourceStream
from processing.identity_resolver import IdentityResolver
from services.secops_platform.abac import AbacPolicyEngine
from services.secops_platform.config import PlatformConfig
from services.secops_platform.privacy import (
    PrivacyVault,
    build_privacy_safe_aggregates,
    scan_for_raw_pii,
)

EMAIL_STRAT = st.builds(
    lambda user, dom: f"{user}@{dom}.example",
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=3, max_size=12),
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=8),
)

IPV4_STRAT = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    st.integers(min_value=1, max_value=223),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=1, max_value=254),
)


@settings(max_examples=40, deadline=None)
@given(email=EMAIL_STRAT, ip=IPV4_STRAT, dev=st.text(alphabet="abcdef0123456789", min_size=4, max_size=12))
def test_property_hmac_determinism_and_zero_raw_pii_leak(email: str, ip: str, dev: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        vault = PrivacyVault("prop-test-master-key", "v1", Path(td) / "vault.json")
        p1 = vault.hmac_token("prn", email)
        p2 = vault.hmac_token("prn", email.upper())
        assert p1 == p2

        ev = SecurityEvent(
            event_id="evt_prop_1",
            event_time_ms=1_795_500_000_000,
            ingest_time_ms=1_795_500_000_100,
            source_stream=SourceStream.AUTH,
            action="login_success",
            outcome="success",
            actor_email=email,
            device_id=dev,
            source_ip=ip,
            geo_country="US",
            geo_lat=37.7749,
            geo_lon=-122.4194,
            target_resource="idp/sso-login",
        )
        tokenized = vault.tokenize_event(ev, p1)
        row = tokenized.model_dump()

        # Invariant: ZERO raw PII leaked into silver tokenized record
        assert email not in str(row.values())
        assert ip not in str(row.values()) or ip.endswith(".0")
        assert scan_for_raw_pii([row]) == []


@settings(max_examples=35, deadline=None)
@given(
    k_threshold=st.integers(min_value=3, max_value=8),
    events_spec=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=14),  # principal idx
            st.sampled_from(["US", "GB", "DE", "JP"]),
            st.sampled_from(["auth", "dns", "proxy"]),
            st.sampled_from(["login_success", "dns_query", "http_request"]),
        ),
        min_size=1,
        max_size=60,
    ),
)
def test_property_k_anonymity_invariant_always_holds(
    k_threshold: int, events_spec: list[tuple[int, str, str, str]]
) -> None:
    with tempfile.TemporaryDirectory() as td:
        vault = PrivacyVault("prop-k-key", "v1", Path(td) / "vault.json")
        tokenized = []
        for idx, (pid, country, stream, action) in enumerate(events_spec):
            ev = SecurityEvent(
                event_id=f"evt_k_{idx}",
                event_time_ms=1_795_500_000_000 + idx * 1000,
                ingest_time_ms=1_795_500_000_100 + idx * 1000,
                source_stream=SourceStream(stream),
                action=action,
                outcome="success",
                actor_email=f"user{pid}@acme.example",
                source_ip="100.64.1.20",
                geo_country=country,
                geo_lat=37.77,
                geo_lon=-122.41,
                target_resource="res/x",
            )
            tokenized.append(vault.tokenize_event(ev, vault.hmac_token("prn", f"user{pid}@acme.example")))

        aggs, _ = build_privacy_safe_aggregates(tokenized, k_threshold=k_threshold)
        # Invariant: EVERY emitted aggregate row strictly satisfies distinct_principals >= k AND event_count >= k
        for agg in aggs:
            assert agg.distinct_principals >= k_threshold
            assert agg.event_count >= k_threshold


@settings(max_examples=40, deadline=None)
@given(
    role=st.sampled_from(
        [
            Role.ANALYST_PRIVACY_SAFE.value,
            Role.SOC_RESPONDER.value,
            Role.PRIVACY_OFFICER.value,
            "unknown_role",
        ]
    ),
    justification=st.text(min_size=0, max_size=80),
)
def test_property_non_ir_roles_never_read_raw_evidence(role: str, justification: str) -> None:
    cfg = PlatformConfig()
    engine = AbacPolicyEngine(cfg)
    decision = engine.evaluate(
        authenticated=True,
        role=role,
        resource="raw_evidence_read",
        justification=justification,
    )
    assert decision.allow is False


@settings(max_examples=30, deadline=None)
@given(
    emails=st.lists(EMAIL_STRAT, min_size=2, max_size=15, unique=True),
    shared_ip=IPV4_STRAT,
)
def test_property_nat_shared_ip_never_conflates_distinct_emails(
    emails: list[str], shared_ip: str
) -> None:
    with tempfile.TemporaryDirectory() as td:
        vault = PrivacyVault("prop-nat-key", "v1", Path(td) / "vault.json")
        resolver = IdentityResolver(vault)
        resolved_tokens = set()
        for idx, em in enumerate(emails):
            ev = SecurityEvent(
                event_id=f"evt_nat_{idx}",
                event_time_ms=1_795_500_000_000 + idx * 1000,
                ingest_time_ms=1_795_500_000_100 + idx * 1000,
                source_stream=SourceStream.AUTH,
                action="login_success",
                outcome="success",
                actor_email=em,
                device_id=f"dev-{idx}",
                source_ip=shared_ip,
                geo_country="US",
                geo_lat=37.77,
                geo_lon=-122.41,
                target_resource="idp/sso",
                nat_egress_flag=True,
            )
            resolved_tokens.add(resolver.resolve(ev))
        assert len(resolved_tokens) == len(emails)
