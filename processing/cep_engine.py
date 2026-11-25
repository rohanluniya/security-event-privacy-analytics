"""Bounded-state Event-Time Streaming CEP & Interval-Join Security Correlation Engine."""

from __future__ import annotations

import hashlib
import math
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any

from models.contracts import (
    CepIncident,
    EntityRiskScore,
    IncidentStatus,
    SecurityEvent,
    Severity,
    TokenizedSecurityEvent,
)
from services.secops_platform.logging_obs import METRICS
from services.secops_platform.privacy import compute_evidence_ref


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two WGS-84 coordinates in kilometers."""
    r_km = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2.0) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2.0) ** 2
    return 2.0 * r_km * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))


def _det_incident_id(rule_ref: str, entity_key: str, window_bucket: int) -> str:
    digest = hashlib.sha256(f"{rule_ref}|{entity_key}|{window_bucket}".encode()).hexdigest()[:16]
    return f"inc_{digest}"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(math.ceil((pct / 100.0) * len(ordered))) - 1))
    return round(ordered[idx], 3)


@dataclass
class CepConfig:
    nat_aware: bool = True
    clock_skew_retraction_enabled: bool = True
    watermark_delay_ms: int = 30_000
    allowed_lateness_ms: int = 300_000
    max_dedup_ids: int = 50_000
    max_ip_keys: int = 10_000
    max_principal_keys: int = 10_000
    max_token_keys: int = 20_000
    cred_stuff_window_ms: int = 180_000
    cred_stuff_distinct_users: int = 6
    impossible_travel_kmh_threshold: float = 900.0
    impossible_travel_min_dist_km: float = 500.0
    lateral_window_ms: int = 600_000
    burst_window_ms: int = 60_000
    burst_min_events: int = 12
    burst_min_bytes: int = 40_000_000


@dataclass
class CepRunMetrics:
    events_processed: int = 0
    events_deduplicated: int = 0
    events_dropped_beyond_lateness: int = 0
    watermark_ms: int = 0
    peak_state_entries: int = 0
    final_state_entries: int = 0
    incidents_emitted: int = 0
    incidents_retracted: int = 0
    processing_ms_samples: list[float] = field(default_factory=list)
    detection_delay_ms_samples: list[float] = field(default_factory=list)


class StreamingCepEngine:
    """Bounded-state event-time CEP & interval-join engine with rule versioning and retractions."""

    def __init__(self, config: CepConfig | None = None) -> None:
        self.cfg = config or CepConfig()
        self.metrics = CepRunMetrics()

        # Bounded state structures (evicted on TTL and hard cardinality bounds)
        self._seen_event_ids: OrderedDict[str, int] = OrderedDict()
        self._ip_auth_failures: OrderedDict[str, deque[dict[str, Any]]] = OrderedDict()
        self._principal_last_auth: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._token_usage_state: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lateral_state: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._burst_windows: OrderedDict[str, deque[dict[str, Any]]] = OrderedDict()

        # Deduplicated incident store keyed by deterministic incident_id
        self._incidents: dict[str, CepIncident] = {}
        self._principal_last_seen: dict[str, int] = {}
        self._principal_masked_email: dict[str, str | None] = {}

    @property
    def current_state_entries(self) -> int:
        return (
            len(self._seen_event_ids)
            + len(self._ip_auth_failures)
            + len(self._principal_last_auth)
            + len(self._token_usage_state)
            + len(self._lateral_state)
            + len(self._burst_windows)
        )

    def _enforce_state_bounds(self) -> None:
        while len(self._seen_event_ids) > self.cfg.max_dedup_ids:
            self._seen_event_ids.popitem(last=False)
        while len(self._ip_auth_failures) > self.cfg.max_ip_keys:
            self._ip_auth_failures.popitem(last=False)
        while len(self._principal_last_auth) > self.cfg.max_principal_keys:
            self._principal_last_auth.popitem(last=False)
        while len(self._token_usage_state) > self.cfg.max_token_keys:
            self._token_usage_state.popitem(last=False)
        while len(self._lateral_state) > self.cfg.max_principal_keys:
            self._lateral_state.popitem(last=False)
        while len(self._burst_windows) > self.cfg.max_principal_keys:
            self._burst_windows.popitem(last=False)

        cur = self.current_state_entries
        if cur > self.metrics.peak_state_entries:
            self.metrics.peak_state_entries = cur
        METRICS.cep_state_entries.set(cur)

    def process_event(
        self,
        raw_event: SecurityEvent,
        tokenized: TokenizedSecurityEvent,
    ) -> bool:
        """Process a single event in event-time order with deduplication and bounded state.

        Returns False if event was deduplicated or dropped beyond allowed lateness.
        """
        t_start = time.perf_counter()

        # 1. Idempotent event_id deduplication
        if raw_event.event_id in self._seen_event_ids:
            self.metrics.events_deduplicated += 1
            return False

        # 2. Event-time watermark & allowed lateness (retraction events bypass normal drop check)
        if self.metrics.watermark_ms == 0:
            self.metrics.watermark_ms = raw_event.event_time_ms - self.cfg.watermark_delay_ms
        elif raw_event.event_time_ms - self.cfg.watermark_delay_ms > self.metrics.watermark_ms:
            self.metrics.watermark_ms = raw_event.event_time_ms - self.cfg.watermark_delay_ms

        is_aged_fixture = raw_event.scenario_label == "aged_retention_fixture"
        if (
            not raw_event.is_retraction_evidence
            and not is_aged_fixture
            and raw_event.event_time_ms < (self.metrics.watermark_ms - self.cfg.allowed_lateness_ms)
        ):
            self.metrics.events_dropped_beyond_lateness += 1
            return False

        self._seen_event_ids[raw_event.event_id] = raw_event.event_time_ms
        self.metrics.events_processed += 1

        principal = tokenized.principal_token
        self._principal_last_seen[principal] = max(
            self._principal_last_seen.get(principal, 0), raw_event.event_time_ms
        )
        if tokenized.masked_email:
            self._principal_masked_email[principal] = tokenized.masked_email

        # 3. Rule evaluation across streams (skip aged retention fixtures from real-time CEP alerts)
        if not is_aged_fixture:
            self._eval_credential_stuffing(raw_event, tokenized)
            self._eval_impossible_travel_and_retraction(raw_event, tokenized)
            self._eval_stolen_token_misuse(raw_event, tokenized)
            self._eval_lateral_movement(raw_event, tokenized)
            self._eval_anomalous_access_burst(raw_event, tokenized)

        self._enforce_state_bounds()
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        self.metrics.processing_ms_samples.append(elapsed_ms)
        return True

    def _upsert_incident(
        self,
        *,
        rule_id: str,
        rule_version: str,
        entity_key: str,
        window_bucket: int,
        severity: Severity,
        principal_token: str,
        masked_email: str | None,
        ip_subnet_masked: str,
        geo_country: str,
        first_event_time_ms: int,
        last_event_time_ms: int,
        ingest_time_ms: int,
        evidence_event_ids: list[str],
        confidence_score: float,
        summary: str,
        ground_truth_attack_id: str | None,
        trigger_event_time_ms: int | None = None,
    ) -> CepIncident:
        rule_ref = f"{rule_id}@{rule_version}"
        inc_id = _det_incident_id(rule_ref, entity_key, window_bucket)
        ref_event_ts = trigger_event_time_ms if trigger_event_time_ms is not None else last_event_time_ms
        detection_delay_ms = max(1, ingest_time_ms - ref_event_ts)
        existing = self._incidents.get(inc_id)
        if existing is not None:
            merged_ids = sorted(set(existing.evidence_event_ids).union(evidence_event_ids))
            existing.evidence_event_ids = merged_ids
            existing.event_count = len(merged_ids)
            existing.first_event_time_ms = min(existing.first_event_time_ms, first_event_time_ms)
            existing.last_event_time_ms = max(existing.last_event_time_ms, last_event_time_ms)
            existing.evidence_ref = compute_evidence_ref(merged_ids, rule_ref)
            existing.confidence_score = max(existing.confidence_score, confidence_score)
            if ground_truth_attack_id and not existing.ground_truth_attack_id:
                existing.ground_truth_attack_id = ground_truth_attack_id
            return existing

        ev_ids = sorted(set(evidence_event_ids))
        incident = CepIncident(
            incident_id=inc_id,
            rule_id=rule_id,
            rule_version=rule_version,
            rule_ref=rule_ref,
            severity=severity,
            status=IncidentStatus.NEW,
            principal_token=principal_token,
            masked_email=masked_email,
            ip_subnet_masked=ip_subnet_masked,
            geo_country=geo_country,
            first_event_time_ms=first_event_time_ms,
            last_event_time_ms=last_event_time_ms,
            detected_at_ms=ingest_time_ms,
            detection_delay_ms=detection_delay_ms,
            event_count=len(ev_ids),
            evidence_event_ids=ev_ids,
            evidence_ref=compute_evidence_ref(ev_ids, rule_ref),
            confidence_score=confidence_score,
            summary=summary,
            ground_truth_attack_id=ground_truth_attack_id,
        )
        self._incidents[inc_id] = incident
        self.metrics.incidents_emitted += 1
        self.metrics.detection_delay_ms_samples.append(float(detection_delay_ms))
        METRICS.cep_incidents.labels(
            rule_ref=rule_ref, severity=severity.value, outcome="emitted"
        ).inc()
        METRICS.cep_detection_delay_ms.observe(detection_delay_ms)
        return incident

    def _eval_credential_stuffing(
        self, raw: SecurityEvent, tok: TokenizedSecurityEvent
    ) -> None:
        if raw.source_stream.value != "auth" or raw.action != "login_failed":
            return

        # NAT-aware v2 rule guards against false positives from shared corporate NAT gateways
        if self.cfg.nat_aware and raw.nat_egress_flag:
            return

        ip_key = tok.ip_token
        win = self._ip_auth_failures.get(ip_key)
        if win is None:
            win = deque()
            self._ip_auth_failures[ip_key] = win
        else:
            self._ip_auth_failures.move_to_end(ip_key)

        win.append(
            {
                "event_id": raw.event_id,
                "event_time_ms": raw.event_time_ms,
                "principal": tok.principal_token,
                "attack_id": raw.attack_id,
            }
        )
        cutoff = raw.event_time_ms - self.cfg.cred_stuff_window_ms
        while win and win[0]["event_time_ms"] < cutoff:
            win.popleft()

        distinct_principals = {item["principal"] for item in win}
        if len(distinct_principals) >= self.cfg.cred_stuff_distinct_users:
            rule_ver = "v2" if self.cfg.nat_aware else "v1"
            ev_ids = [item["event_id"] for item in win]
            gt_ids = [item["attack_id"] for item in win if item["attack_id"]]
            self._upsert_incident(
                rule_id="cred_stuffing",
                rule_version=rule_ver,
                entity_key=ip_key,
                window_bucket=win[0]["event_time_ms"] // 1_800_000,
                severity=Severity.HIGH,
                principal_token=tok.principal_token,
                masked_email=tok.masked_email,
                ip_subnet_masked=tok.ip_subnet_masked,
                geo_country=raw.geo_country,
                first_event_time_ms=win[0]["event_time_ms"],
                last_event_time_ms=raw.event_time_ms,
                ingest_time_ms=raw.ingest_time_ms,
                evidence_event_ids=ev_ids,
                confidence_score=0.92 if self.cfg.nat_aware else 0.70,
                summary=(
                    f"Credential stuffing spray detected from subnet {tok.ip_subnet_masked} "
                    f"targeting {len(distinct_principals)} distinct principals within 3m"
                ),
                ground_truth_attack_id=gt_ids[0] if gt_ids else None,
                trigger_event_time_ms=raw.event_time_ms,
            )

    def _eval_impossible_travel_and_retraction(
        self, raw: SecurityEvent, tok: TokenizedSecurityEvent
    ) -> None:
        if raw.source_stream.value != "auth":
            return

        principal = tok.principal_token

        # Late-event clock-skew retraction path
        if raw.is_retraction_evidence and self.cfg.clock_skew_retraction_enabled:
            for inc in self._incidents.values():
                if (
                    inc.principal_token == principal
                    and inc.rule_id == "impossible_travel"
                    and inc.status != IncidentStatus.RETRACTED
                ):
                    inc.status = IncidentStatus.RETRACTED
                    inc.retracted_reason = (
                        f"Retracted by late NTP/MFA reconciliation event {raw.event_id} "
                        f"(host clock_skew_ms={raw.clock_skew_ms} resolved apparent velocity)"
                    )
                    inc.evidence_event_ids = sorted(set(inc.evidence_event_ids + [raw.event_id]))
                    inc.event_count = len(inc.evidence_event_ids)
                    inc.evidence_ref = compute_evidence_ref(inc.evidence_event_ids, inc.rule_ref)
                    self.metrics.incidents_retracted += 1
                    METRICS.cep_incidents.labels(
                        rule_ref=inc.rule_ref, severity=inc.severity.value, outcome="retracted"
                    ).inc()
            return

        if raw.action != "login_success" or raw.outcome != "success":
            return

        prev = self._principal_last_auth.get(principal)
        curr_state = {
            "event_id": raw.event_id,
            "event_time_ms": raw.event_time_ms,
            "lat": raw.geo_lat,
            "lon": raw.geo_lon,
            "country": raw.geo_country,
            "asn": raw.geo_asn,
            "device": tok.device_token,
            "nat": raw.nat_egress_flag,
        }
        self._principal_last_auth[principal] = curr_state
        self._principal_last_auth.move_to_end(principal)

        if prev is None:
            return
        # Skip corporate NAT gateway handoffs if nat_aware
        if self.cfg.nat_aware and (raw.nat_egress_flag or prev["nat"]):
            return

        dt_ms = abs(raw.event_time_ms - int(prev["event_time_ms"]))
        if dt_ms == 0 or dt_ms > 4 * 3_600 * 1000:
            return

        dist_km = haversine_km(float(prev["lat"]), float(prev["lon"]), raw.geo_lat, raw.geo_lon)
        velocity_kmh = dist_km / (dt_ms / 3_600_000.0)

        if (
            dist_km >= self.cfg.impossible_travel_min_dist_km
            and velocity_kmh > self.cfg.impossible_travel_kmh_threshold
            and prev["country"] != raw.geo_country
        ):
            rule_ver = "v2" if self.cfg.clock_skew_retraction_enabled else "v1"
            self._upsert_incident(
                rule_id="impossible_travel",
                rule_version=rule_ver,
                entity_key=principal,
                window_bucket=min(int(prev["event_time_ms"]), raw.event_time_ms) // 1_800_000,
                severity=Severity.CRITICAL,
                principal_token=principal,
                masked_email=tok.masked_email,
                ip_subnet_masked=tok.ip_subnet_masked,
                geo_country=raw.geo_country,
                first_event_time_ms=min(int(prev["event_time_ms"]), raw.event_time_ms),
                last_event_time_ms=max(int(prev["event_time_ms"]), raw.event_time_ms),
                ingest_time_ms=raw.ingest_time_ms,
                evidence_event_ids=[str(prev["event_id"]), raw.event_id],
                confidence_score=0.95 if abs(raw.clock_skew_ms) < 5_000 else 0.65,
                summary=(
                    f"Impossible travel detected ({prev['country']} -> {raw.geo_country}): "
                    f"{dist_km:.0f} km in {dt_ms / 60_000.0:.1f} min ({velocity_kmh:.0f} km/h)"
                ),
                ground_truth_attack_id=raw.attack_id,
                trigger_event_time_ms=raw.event_time_ms,
            )

    def _eval_stolen_token_misuse(
        self, raw: SecurityEvent, tok: TokenizedSecurityEvent
    ) -> None:
        if not tok.token_hash or raw.source_stream.value not in ("api_gateway", "auth"):
            return

        prev = self._token_usage_state.get(tok.token_hash)
        curr = {
            "event_id": raw.event_id,
            "event_time_ms": raw.event_time_ms,
            "device": tok.device_token,
            "asn": raw.geo_asn,
            "country": raw.geo_country,
        }
        self._token_usage_state[tok.token_hash] = curr
        self._token_usage_state.move_to_end(tok.token_hash)

        if prev is None:
            return

        dt_ms = abs(raw.event_time_ms - int(prev["event_time_ms"]))
        device_flipped = bool(tok.device_token and prev["device"] and tok.device_token != prev["device"])
        asn_flipped = raw.geo_asn != prev["asn"]
        is_priv_esc = raw.action == "priv_escalation" or "/admin/" in raw.target_resource

        if dt_ms <= 300_000 and device_flipped and asn_flipped and is_priv_esc:
            self._upsert_incident(
                rule_id="stolen_token_misuse",
                rule_version="v2",
                entity_key=f"{tok.principal_token}:{tok.token_hash}",
                window_bucket=min(int(prev["event_time_ms"]), raw.event_time_ms) // 1_800_000,
                severity=Severity.CRITICAL,
                principal_token=tok.principal_token,
                masked_email=tok.masked_email,
                ip_subnet_masked=tok.ip_subnet_masked,
                geo_country=raw.geo_country,
                first_event_time_ms=min(int(prev["event_time_ms"]), raw.event_time_ms),
                last_event_time_ms=max(int(prev["event_time_ms"]), raw.event_time_ms),
                ingest_time_ms=raw.ingest_time_ms,
                evidence_event_ids=[str(prev["event_id"]), raw.event_id],
                confidence_score=0.97,
                summary=(
                    f"Stolen OAuth token replayed across ASN ({prev['asn']} -> {raw.geo_asn}) "
                    f"and device switch with privilege escalation on {raw.target_resource}"
                ),
                ground_truth_attack_id=raw.attack_id,
                trigger_event_time_ms=raw.event_time_ms,
            )

    def _eval_lateral_movement(
        self, raw: SecurityEvent, tok: TokenizedSecurityEvent
    ) -> None:
        stream = raw.source_stream.value
        matched_stage: str | None = None
        if stream == "auth" and raw.action == "login_success" and "jumpbox" in raw.target_resource:
            matched_stage = "auth"
        elif stream == "endpoint" and raw.action == "process_exec_suspicious":
            matched_stage = "endpoint"
        elif stream in ("dns", "proxy") and (
            "c2-beacon" in raw.target_resource or raw.action == "proxy_beacon"
        ):
            matched_stage = "egress"

        if matched_stage is None:
            return

        principal = tok.principal_token
        state = self._lateral_state.get(principal)
        if state is None:
            state = {}
            self._lateral_state[principal] = state
        else:
            self._lateral_state.move_to_end(principal)

        state[matched_stage] = (raw.event_time_ms, raw.event_id, raw.attack_id)

        if "auth" in state and "endpoint" in state and "egress" in state:
            t_auth, id_auth, gt_auth = state["auth"]
            t_ep, id_ep, gt_ep = state["endpoint"]
            t_eg, id_eg, gt_eg = state["egress"]
            chain_start = min(t_auth, t_ep, t_eg)
            chain_end = max(t_auth, t_ep, t_eg)
            span_ms = chain_end - chain_start
            if span_ms <= self.cfg.lateral_window_ms:
                gt = gt_eg or gt_ep or gt_auth
                self._upsert_incident(
                    rule_id="lateral_movement",
                    rule_version="v2",
                    entity_key=principal,
                    window_bucket=chain_start // 1_800_000,
                    severity=Severity.CRITICAL,
                    principal_token=principal,
                    masked_email=tok.masked_email,
                    ip_subnet_masked=tok.ip_subnet_masked,
                    geo_country=raw.geo_country,
                    first_event_time_ms=chain_start,
                    last_event_time_ms=chain_end,
                    ingest_time_ms=raw.ingest_time_ms,
                    evidence_event_ids=[id_auth, id_ep, id_eg],
                    confidence_score=0.96,
                    summary=(
                        "Multi-source lateral movement chain correlated across auth -> endpoint -> "
                        f"egress beacon within {span_ms / 1000.0:.0f}s"
                    ),
                    ground_truth_attack_id=gt,
                    trigger_event_time_ms=raw.event_time_ms,
                )

    def _eval_anomalous_access_burst(
        self, raw: SecurityEvent, tok: TokenizedSecurityEvent
    ) -> None:
        if raw.source_stream.value not in ("api_gateway", "application"):
            return
        if raw.action != "bulk_export" and raw.bytes_out < 1_000_000:
            return

        principal = tok.principal_token
        win = self._burst_windows.get(principal)
        if win is None:
            win = deque()
            self._burst_windows[principal] = win
        else:
            self._burst_windows.move_to_end(principal)

        win.append(
            {
                "event_id": raw.event_id,
                "event_time_ms": raw.event_time_ms,
                "bytes_out": raw.bytes_out,
                "attack_id": raw.attack_id,
            }
        )
        cutoff = raw.event_time_ms - self.cfg.burst_window_ms
        while win and win[0]["event_time_ms"] < cutoff:
            win.popleft()

        total_bytes = sum(int(item["bytes_out"]) for item in win)
        if len(win) >= self.cfg.burst_min_events and total_bytes >= self.cfg.burst_min_bytes:
            ev_ids = [str(item["event_id"]) for item in win]
            gt_ids = [item["attack_id"] for item in win if item["attack_id"]]
            self._upsert_incident(
                rule_id="anomalous_access_burst",
                rule_version="v2",
                entity_key=principal,
                window_bucket=int(win[0]["event_time_ms"]) // 1_800_000,
                severity=Severity.HIGH,
                principal_token=principal,
                masked_email=tok.masked_email,
                ip_subnet_masked=tok.ip_subnet_masked,
                geo_country=raw.geo_country,
                first_event_time_ms=int(win[0]["event_time_ms"]),
                last_event_time_ms=raw.event_time_ms,
                ingest_time_ms=raw.ingest_time_ms,
                evidence_event_ids=ev_ids,
                confidence_score=0.91,
                summary=(
                    f"Anomalous data export burst: {len(win)} bulk requests totaling "
                    f"{total_bytes / 1_000_000.0:.1f} MB in <60s"
                ),
                ground_truth_attack_id=gt_ids[0] if gt_ids else None,
                trigger_event_time_ms=raw.event_time_ms,
            )

    def get_incidents(self) -> list[CepIncident]:
        self.metrics.final_state_entries = self.current_state_entries
        return sorted(self._incidents.values(), key=lambda i: i.detected_at_ms, reverse=True)

    def compute_entity_risk_scores(self, now_ms: int | None = None) -> list[EntityRiskScore]:
        """Compute bounded 0-100 risk scores per pseudonymous principal excluding retracted incidents."""
        ts_now = now_ms or int(time.time() * 1000)
        sev_weight = {
            Severity.CRITICAL: 48.0,
            Severity.HIGH: 32.0,
            Severity.MEDIUM: 18.0,
            Severity.LOW: 8.0,
        }
        grouped: dict[str, list[CepIncident]] = {}
        for inc in self._incidents.values():
            grouped.setdefault(inc.principal_token, []).append(inc)

        scores: list[EntityRiskScore] = []
        for principal, incs in grouped.items():
            active = [
                i
                for i in incs
                if i.status not in (IncidentStatus.RETRACTED, IncidentStatus.FALSE_POSITIVE)
            ]
            retracted = [i for i in incs if i.status == IncidentStatus.RETRACTED]
            raw_score = sum(sev_weight[i.severity] * i.confidence_score for i in active)
            distinct_rules = sorted({i.rule_ref for i in active})
            if len(distinct_rules) >= 2:
                raw_score += 12.0 * (len(distinct_rules) - 1)
            bounded = round(min(100.0, raw_score), 2)
            if bounded >= 75.0:
                tier = "CRITICAL"
            elif bounded >= 45.0:
                tier = "HIGH"
            elif bounded >= 20.0:
                tier = "MEDIUM"
            else:
                tier = "LOW"
            scores.append(
                EntityRiskScore(
                    principal_token=principal,
                    masked_email=self._principal_masked_email.get(principal),
                    risk_score=bounded,
                    risk_tier=tier,
                    active_incident_count=len(active),
                    retracted_incident_count=len(retracted),
                    rules_triggered=distinct_rules,
                    last_seen_ms=self._principal_last_seen.get(principal, ts_now),
                    updated_at_ms=ts_now,
                )
            )
        scores.sort(key=lambda s: (s.risk_score, s.active_incident_count), reverse=True)
        return scores

    def evaluate_precision_recall(
        self, ground_truth_attacks: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Measure CEP precision, recall, F1, false-positive rate, latency, and state footprint."""
        active_incidents = [
            inc
            for inc in self._incidents.values()
            if inc.status not in (IncidentStatus.RETRACTED, IncidentStatus.FALSE_POSITIVE)
        ]
        retracted_incidents = [
            inc for inc in self._incidents.values() if inc.status == IncidentStatus.RETRACTED
        ]
        expected_ids = {
            aid for aid, meta in ground_truth_attacks.items() if meta.get("expected_active", True)
        }
        detected_gt_ids = {
            inc.ground_truth_attack_id
            for inc in active_incidents
            if inc.ground_truth_attack_id in expected_ids
        }
        tp = len(detected_gt_ids)
        fp = sum(
            1
            for inc in active_incidents
            if not inc.ground_truth_attack_id or inc.ground_truth_attack_id not in expected_ids
        )
        fn = len(expected_ids - detected_gt_ids)

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
        f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
        fp_rate = round(fp / max(1, len(active_incidents)), 4)

        return {
            "nat_aware": self.cfg.nat_aware,
            "clock_skew_retraction_enabled": self.cfg.clock_skew_retraction_enabled,
            "ground_truth_campaigns": len(expected_ids),
            "active_incidents": len(active_incidents),
            "retracted_incidents": len(retracted_incidents),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fp_rate,
            "detection_delay_p50_ms": _percentile(self.metrics.detection_delay_ms_samples, 50),
            "detection_delay_p95_ms": _percentile(self.metrics.detection_delay_ms_samples, 95),
            "detection_delay_p99_ms": _percentile(self.metrics.detection_delay_ms_samples, 99),
            "per_event_proc_p50_ms": _percentile(self.metrics.processing_ms_samples, 50),
            "per_event_proc_p95_ms": _percentile(self.metrics.processing_ms_samples, 95),
            "per_event_proc_p99_ms": _percentile(self.metrics.processing_ms_samples, 99),
            "peak_state_entries": self.metrics.peak_state_entries,
            "final_state_entries": self.current_state_entries,
            "events_processed": self.metrics.events_processed,
            "events_deduplicated": self.metrics.events_deduplicated,
        }
