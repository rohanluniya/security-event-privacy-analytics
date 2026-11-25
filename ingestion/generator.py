"""Deterministic seeded multi-source security telemetry generator with realistic attacks and noise."""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Any

# Global enterprise offices: (country, city, lat, lon, corp_asn)
OFFICES: list[tuple[str, str, float, float, str]] = [
    ("US", "San Francisco", 37.7749, -122.4194, "AS15169"),
    ("US", "New York", 40.7128, -74.0060, "AS15169"),
    ("GB", "London", 51.5074, -0.1278, "AS5089"),
    ("DE", "Frankfurt", 50.1109, 8.6821, "AS3320"),
    ("JP", "Tokyo", 35.6762, 139.6503, "AS2516"),
    ("AU", "Sydney", -33.8688, 151.2093, "AS1221"),
]

# Shared corporate NAT egress gateways (dozens of benign employees share each IP)
CORPORATE_NAT_IPS: list[tuple[str, str, float, float, str]] = [
    ("198.51.100.10", "US", 37.7749, -122.4194, "AS15169"),
    ("203.0.113.25", "GB", 51.5074, -0.1278, "AS5089"),
]

ATTACKER_IPS: list[tuple[str, str, float, float, str]] = [
    ("185.220.101.44", "NL", 52.3676, 4.9041, "AS49505"),
    ("91.134.202.18", "FR", 48.8566, 2.3522, "AS16276"),
    ("45.155.205.77", "RU", 55.7558, 37.6173, "AS49505"),
    ("103.149.86.21", "SG", 1.3521, 103.8198, "AS138915"),
    ("194.26.135.91", "DE", 52.5200, 13.4050, "AS209854"),
]

BENIGN_RESOURCES: dict[str, list[str]] = {
    "auth": ["idp/sso-login", "idp/mfa-verify", "idp/token-refresh"],
    "endpoint": ["workstation/chrome", "workstation/vscode", "workstation/slack"],
    "dns": ["api.internal.corp", "git.internal.corp", "docs.internal.corp"],
    "proxy": ["github.com", "pypi.org", "cloud.internal.corp"],
    "api_gateway": ["/v1/profile", "/v1/projects", "/v1/reports"],
    "application": ["billing-ui/view", "hr-portal/home", "analytics/dashboard"],
}


@dataclass(frozen=True)
class SyntheticEmployee:
    employee_idx: int
    email: str
    device_id: str
    home_country: str
    home_lat: float
    home_lon: float
    home_asn: str
    home_ip: str
    uses_corp_nat: bool
    nat_tuple: tuple[str, str, float, float, str]


@dataclass
class GeneratedBatch:
    seed: int
    raw_records: list[dict[str, Any]]
    ground_truth_attacks: dict[str, dict[str, Any]]
    gdpr_deletion_emails: list[str]
    poison_count: int
    duplicate_count: int
    aged_count: int


def _det_event_id(seed: int, seq: int, tag: str) -> str:
    digest = hashlib.sha256(f"secops:{seed}:{seq}:{tag}".encode()).hexdigest()[:16]
    return f"evt_{digest}"


def _build_employees(rng: random.Random, count: int) -> list[SyntheticEmployee]:
    employees: list[SyntheticEmployee] = []
    for idx in range(count):
        office = OFFICES[idx % len(OFFICES)]
        nat = CORPORATE_NAT_IPS[idx % len(CORPORATE_NAT_IPS)]
        uses_nat = idx < int(count * 0.45)  # 45% of workforce sits behind shared corporate NAT
        home_ip = f"100.64.{(idx // 200) + 1}.{(idx % 200) + 10}"
        employees.append(
            SyntheticEmployee(
                employee_idx=idx,
                email=f"emp{idx:04d}@acme-secops.example",
                device_id=f"dev-corp-{idx:04d}",
                home_country=office[0],
                home_lat=office[2] + rng.uniform(-0.08, 0.08),
                home_lon=office[3] + rng.uniform(-0.08, 0.08),
                home_asn=office[4],
                home_ip=home_ip,
                uses_corp_nat=uses_nat,
                nat_tuple=nat,
            )
        )
    return employees


def generate_security_telemetry(
    *,
    seed: int = 42,
    total_events: int = 3000,
    base_time_ms: int = 1_795_500_000_000,
    include_aged_events: bool = True,
    include_poison_events: bool = True,
) -> GeneratedBatch:
    """Generate deterministic multi-source security telemetry with labeled attacks & realistic noise.

    All IDs, timestamps, attack campaigns, NAT storms, clock skews, duplicates, and poison events
    are 100% deterministic for a given `(seed, total_events, base_time_ms)`.
    """
    rng = random.Random(seed)
    num_employees = max(60, min(240, total_events // 20))
    employees = _build_employees(rng, num_employees)
    records: list[dict[str, Any]] = []
    ground_truth: dict[str, dict[str, Any]] = {}
    seq = 0

    def next_id(tag: str) -> str:
        nonlocal seq
        seq += 1
        return _det_event_id(seed, seq, tag)

    # Reserve non-NAT employees for clean impossible_travel & clock_skew cohorts so baseline auth
    # does not create accidental extra travel pairs outside labeled campaigns
    non_nat_emps = [e for e in employees if not e.uses_corp_nat]
    campaign_scale = max(1, min(4, total_events // 1500))
    travel_victims = non_nat_emps[: 2 * campaign_scale]
    skew_victims = [e for e in non_nat_emps[2 * campaign_scale :] if e.home_country == "GB"][: max(1, campaign_scale)]
    if len(skew_victims) < max(1, campaign_scale):
        skew_victims = non_nat_emps[2 * campaign_scale : 2 * campaign_scale + max(1, campaign_scale)]
    reserved_auth_emails = {e.email for e in travel_victims} | {e.email for e in skew_victims}

    # 1. Baseline multi-source benign traffic across 6 streams (~68% of target)
    benign_target = max(400, int(total_events * 0.68))
    streams = ["auth", "endpoint", "dns", "proxy", "api_gateway", "application"]
    for i in range(benign_target):
        emp = employees[i % len(employees)]
        stream = streams[i % len(streams)]
        if stream == "auth" and emp.email in reserved_auth_emails:
            stream = "application"
        event_ts = base_time_ms + int((i / max(1, benign_target)) * 3_600_000) + rng.randint(-1500, 1500)
        # 8% out-of-order late ingestion delay (5s-60s)
        lag_ms = rng.randint(5_000, 60_000) if (i % 13 == 0) else rng.randint(50, 900)
        if emp.uses_corp_nat:
            ip, country, lat, lon, asn = emp.nat_tuple
            nat_flag = True
            label = "nat_benign"
        else:
            ip, country, lat, lon, asn = (
                emp.home_ip,
                emp.home_country,
                emp.home_lat,
                emp.home_lon,
                emp.home_asn,
            )
            nat_flag = False
            label = "benign"

        action_map = {
            "auth": "login_success",
            "endpoint": "process_exec",
            "dns": "dns_query",
            "proxy": "http_request",
            "api_gateway": "api_call",
            "application": "app_read",
        }
        action = action_map[stream]
        outcome = "success"
        # Occasional normal mistyped password on non-NAT hosts
        if stream == "auth" and (i % 37 == 0) and not emp.uses_corp_nat:
            action = "login_failed"
            outcome = "failure"

        # Endpoint & DNS sometimes omit email and only carry device_id (tests identity resolution!)
        actor_email: str | None = emp.email if stream not in ("endpoint", "dns") or (i % 3 == 0) else None
        session_id = f"ses-{emp.employee_idx:04d}-{(event_ts // 1_800_000) % 10}"
        token_id = f"tok-{emp.employee_idx:04d}-{(event_ts // 3_600_000) % 10}"

        records.append(
            {
                "event_id": next_id(f"benign-{stream}"),
                "event_time_ms": event_ts,
                "ingest_time_ms": event_ts + lag_ms,
                "source_stream": stream,
                "action": action,
                "outcome": outcome,
                "actor_email": actor_email,
                "device_id": emp.device_id,
                "session_id": session_id,
                "token_id": token_id,
                "source_ip": ip,
                "geo_country": country,
                "geo_lat": round(lat, 4),
                "geo_lon": round(lon, 4),
                "target_resource": BENIGN_RESOURCES[stream][i % len(BENIGN_RESOURCES[stream])],
                "http_status": 200 if outcome == "success" else 401,
                "bytes_out": rng.randint(512, 65_536),
                "scenario_label": label,
                "attack_id": None,
                "nat_egress_flag": nat_flag,
                "geo_asn": asn,
                "clock_skew_ms": rng.randint(-1500, 1500),
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )

    # 2. Corporate NAT Shared-Egress Storm (BENIGN noise designed to trip NAT-naive rules!)
    # 30+ distinct corporate employees behind 198.51.100.10 & 203.0.113.25 mistyping password after SSO rotation
    nat_employees = [e for e in employees if e.uses_corp_nat]
    for burst_idx, nat_tuple in enumerate(CORPORATE_NAT_IPS):
        ip, country, lat, lon, asn = nat_tuple
        burst_start = base_time_ms + 600_000 + burst_idx * 900_000
        cohort = [e for e in nat_employees if e.nat_tuple[0] == ip][:14]
        for j, emp in enumerate(cohort):
            # 1 failed login (expired SSO cache) followed by 1 successful login 20s later
            fail_ts = burst_start + j * 4_500
            records.append(
                {
                    "event_id": next_id(f"nat-noise-fail-{burst_idx}-{j}"),
                    "event_time_ms": fail_ts,
                    "ingest_time_ms": fail_ts + 250,
                    "source_stream": "auth",
                    "action": "login_failed",
                    "outcome": "failure",
                    "actor_email": emp.email,
                    "device_id": emp.device_id,
                    "session_id": f"ses-nat-{emp.employee_idx}-{burst_idx}",
                    "token_id": f"tok-nat-{emp.employee_idx}-{burst_idx}",
                    "source_ip": ip,
                    "geo_country": country,
                    "geo_lat": lat,
                    "geo_lon": lon,
                    "target_resource": "idp/sso-login",
                    "http_status": 401,
                    "bytes_out": 420,
                    "scenario_label": "nat_benign",
                    "attack_id": None,
                    "nat_egress_flag": True,
                    "geo_asn": asn,
                    "clock_skew_ms": rng.randint(-500, 500),
                    "is_retraction_evidence": False,
                    "schema_version": 2,
                }
            )
            ok_ts = fail_ts + 20_000
            records.append(
                {
                    "event_id": next_id(f"nat-noise-ok-{burst_idx}-{j}"),
                    "event_time_ms": ok_ts,
                    "ingest_time_ms": ok_ts + 200,
                    "source_stream": "auth",
                    "action": "login_success",
                    "outcome": "success",
                    "actor_email": emp.email,
                    "device_id": emp.device_id,
                    "session_id": f"ses-nat-{emp.employee_idx}-{burst_idx}",
                    "token_id": f"tok-nat-{emp.employee_idx}-{burst_idx}",
                    "source_ip": ip,
                    "geo_country": country,
                    "geo_lat": lat,
                    "geo_lon": lon,
                    "target_resource": "idp/sso-login",
                    "http_status": 200,
                    "bytes_out": 890,
                    "scenario_label": "nat_benign",
                    "attack_id": None,
                    "nat_egress_flag": True,
                    "geo_asn": asn,
                    "clock_skew_ms": 0,
                    "is_retraction_evidence": False,
                    "schema_version": 2,
                }
            )

    # 3. Credential Stuffing Attacks (TRUE POSITIVES from external non-NAT IPs)
    for c_idx in range(2 * campaign_scale):
        attack_id = f"atk_cred_stuff_{seed}_{c_idx:02d}"
        atk_ip, atk_country, atk_lat, atk_lon, atk_asn = ATTACKER_IPS[c_idx % len(ATTACKER_IPS)]
        octets = atk_ip.split(".")
        unique_atk_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{50 + c_idx}"
        # Keep entire 36s spray strictly within a single 30-minute bucket
        start_ts = base_time_ms + 300_000 + c_idx * 300_000
        targeted = employees[(c_idx * 9) % (len(employees) - 10) : (c_idx * 9) % (len(employees) - 10) + 9]
        ground_truth[attack_id] = {
            "rule_id": "cred_stuffing",
            "expected_active": True,
            "scenario": "credential_stuffing",
            "target_count": len(targeted),
        }
        for k, emp in enumerate(targeted):
            ev_ts = start_ts + k * 4_000
            records.append(
                {
                    "event_id": next_id(f"cred-fail-{c_idx}-{k}"),
                    "event_time_ms": ev_ts,
                    "ingest_time_ms": ev_ts + 300,
                    "source_stream": "auth",
                    "action": "login_failed",
                    "outcome": "failure",
                    "actor_email": emp.email,
                    "device_id": f"dev-bot-{c_idx:02d}",
                    "session_id": f"ses-bot-{c_idx:02d}-{k}",
                    "token_id": None,
                    "source_ip": unique_atk_ip,
                    "geo_country": atk_country,
                    "geo_lat": atk_lat,
                    "geo_lon": atk_lon,
                    "target_resource": "idp/sso-login",
                    "http_status": 401,
                    "bytes_out": 380,
                    "scenario_label": "credential_stuffing",
                    "attack_id": attack_id,
                    "nat_egress_flag": False,
                    "geo_asn": atk_asn,
                    "clock_skew_ms": 0,
                    "is_retraction_evidence": False,
                    "schema_version": 2,
                }
            )
        # Final compromised account login_success (use non-reserved victim so impossible_travel doesn't double-fire)
        victim = targeted[-1]
        if victim.email in reserved_auth_emails:
            victim = employees[-3]
        ok_ts = start_ts + len(targeted) * 4_000 + 2_000
        records.append(
            {
                "event_id": next_id(f"cred-hit-{c_idx}"),
                "event_time_ms": ok_ts,
                "ingest_time_ms": ok_ts + 250,
                "source_stream": "auth",
                "action": "login_success",
                "outcome": "success",
                "actor_email": victim.email,
                "device_id": f"dev-bot-{c_idx:02d}",
                "session_id": f"ses-bot-hit-{c_idx:02d}",
                "token_id": f"tok-bot-hit-{c_idx:02d}",
                "source_ip": unique_atk_ip,
                "geo_country": victim.home_country,
                "geo_lat": victim.home_lat,
                "geo_lon": victim.home_lon,
                "target_resource": "idp/sso-login",
                "http_status": 200,
                "bytes_out": 1240,
                "scenario_label": "credential_stuffing",
                "attack_id": attack_id,
                "nat_egress_flag": False,
                "geo_asn": atk_asn,
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )

    # 4. Impossible Travel Attacks (TRUE POSITIVES: home office -> far hemisphere in 18 mins)
    for it_idx, victim in enumerate(travel_victims):
        attack_id = f"atk_impos_travel_{seed}_{it_idx:02d}"
        t0 = base_time_ms + 700_000 + it_idx * 410_000
        dest_country, dest_lat, dest_lon, dest_asn = (
            ("US", 37.7749, -122.4194, "AS15169")
            if victim.home_country == "JP"
            else ("JP", 35.6762, 139.6503, "AS138915")
        )
        ground_truth[attack_id] = {
            "rule_id": "impossible_travel",
            "expected_active": True,
            "scenario": "impossible_travel",
            "victim_email": victim.email,
        }
        records.append(
            {
                "event_id": next_id(f"travel-a-{it_idx}"),
                "event_time_ms": t0,
                "ingest_time_ms": t0 + 180,
                "source_stream": "auth",
                "action": "login_success",
                "outcome": "success",
                "actor_email": victim.email,
                "device_id": victim.device_id,
                "session_id": f"ses-trv-a-{it_idx}",
                "token_id": f"tok-trv-a-{it_idx}",
                "source_ip": victim.home_ip,
                "geo_country": victim.home_country,
                "geo_lat": round(victim.home_lat, 4),
                "geo_lon": round(victim.home_lon, 4),
                "target_resource": "idp/sso-login",
                "http_status": 200,
                "bytes_out": 940,
                "scenario_label": "impossible_travel",
                "attack_id": attack_id,
                "nat_egress_flag": False,
                "geo_asn": victim.home_asn,
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )
        t1 = t0 + 18 * 60 * 1000
        records.append(
            {
                "event_id": next_id(f"travel-b-{it_idx}"),
                "event_time_ms": t1,
                "ingest_time_ms": t1 + 210,
                "source_stream": "auth",
                "action": "login_success",
                "outcome": "success",
                "actor_email": victim.email,
                "device_id": f"dev-rogue-{it_idx:02d}",
                "session_id": f"ses-trv-b-{it_idx}",
                "token_id": f"tok-trv-b-{it_idx}",
                "source_ip": f"103.149.86.{120 + it_idx}",
                "geo_country": dest_country,
                "geo_lat": dest_lat,
                "geo_lon": dest_lon,
                "target_resource": "idp/sso-login",
                "http_status": 200,
                "bytes_out": 1120,
                "scenario_label": "impossible_travel",
                "attack_id": attack_id,
                "nat_egress_flag": False,
                "geo_asn": dest_asn,
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )

    # 5. Clock-Skewed False Impossible Travel + Late-Event Retraction (MUST BE RETRACTED!)
    for sk_idx, emp in enumerate(skew_victims):
        t0 = base_time_ms + 900_000 + sk_idx * 450_000
        records.append(
            {
                "event_id": next_id(f"skew-a-{sk_idx}"),
                "event_time_ms": t0,
                "ingest_time_ms": t0 + 200,
                "source_stream": "auth",
                "action": "login_success",
                "outcome": "success",
                "actor_email": emp.email,
                "device_id": emp.device_id,
                "session_id": f"ses-skew-a-{sk_idx}",
                "token_id": f"tok-skew-a-{sk_idx}",
                "source_ip": f"100.64.90.{10 + sk_idx}",
                "geo_country": "GB",
                "geo_lat": 51.5074,
                "geo_lon": -0.1278,
                "target_resource": "idp/sso-login",
                "http_status": 200,
                "bytes_out": 850,
                "scenario_label": "clock_skew_false_travel",
                "attack_id": None,
                "nat_egress_flag": False,
                "geo_asn": "AS5089",
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )
        t1 = t0 + 20 * 60 * 1000
        records.append(
            {
                "event_id": next_id(f"skew-b-{sk_idx}"),
                "event_time_ms": t1,
                "ingest_time_ms": t1 + 300,
                "source_stream": "auth",
                "action": "login_success",
                "outcome": "success",
                "actor_email": emp.email,
                "device_id": emp.device_id,
                "session_id": f"ses-skew-b-{sk_idx}",
                "token_id": f"tok-skew-b-{sk_idx}",
                "source_ip": f"100.64.91.{10 + sk_idx}",
                "geo_country": "DE",
                "geo_lat": 50.1109,
                "geo_lon": 8.6821,
                "target_resource": "idp/sso-login",
                "http_status": 200,
                "bytes_out": 860,
                "scenario_label": "clock_skew_false_travel",
                "attack_id": None,
                "nat_egress_flag": False,
                "geo_asn": "AS3320",
                "clock_skew_ms": -10_800_000,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )
        t_retract = t1 + 45_000
        records.append(
            {
                "event_id": next_id(f"skew-retract-{sk_idx}"),
                "event_time_ms": t_retract,
                "ingest_time_ms": t_retract + 150,
                "source_stream": "auth",
                "action": "clock_sync_retraction",
                "outcome": "success",
                "actor_email": emp.email,
                "device_id": emp.device_id,
                "session_id": f"ses-skew-b-{sk_idx}",
                "token_id": f"tok-skew-b-{sk_idx}",
                "source_ip": f"100.64.91.{10 + sk_idx}",
                "geo_country": "DE",
                "geo_lat": 50.1109,
                "geo_lon": 8.6821,
                "target_resource": "idp/ntp-mfa-reconcile",
                "http_status": 200,
                "bytes_out": 512,
                "scenario_label": "clock_skew_false_travel",
                "attack_id": None,
                "nat_egress_flag": False,
                "geo_asn": "AS3320",
                "clock_skew_ms": -10_800_000,
                "is_retraction_evidence": True,
                "schema_version": 2,
            }
        )

    # 6. Stolen Token Misuse (TRUE POSITIVES: concurrent ASN/device flip + API privilege escalation)
    for st_idx in range(2 * campaign_scale):
        attack_id = f"atk_stolen_token_{seed}_{st_idx:02d}"
        victim = non_nat_emps[(16 + st_idx) % len(non_nat_emps)]
        shared_tok = f"tok-stolen-{seed}-{st_idx:02d}"
        t0 = base_time_ms + 1_100_000 + st_idx * 350_000
        ground_truth[attack_id] = {
            "rule_id": "stolen_token_misuse",
            "expected_active": True,
            "scenario": "stolen_token_misuse",
            "victim_email": victim.email,
        }
        # Legitimate token use on corporate device
        records.append(
            {
                "event_id": next_id(f"tok-legit-{st_idx}"),
                "event_time_ms": t0,
                "ingest_time_ms": t0 + 140,
                "source_stream": "api_gateway",
                "action": "token_use",
                "outcome": "success",
                "actor_email": victim.email,
                "device_id": victim.device_id,
                "session_id": f"ses-tok-{st_idx}",
                "token_id": shared_tok,
                "source_ip": victim.home_ip,
                "geo_country": victim.home_country,
                "geo_lat": victim.home_lat,
                "geo_lon": victim.home_lon,
                "target_resource": "/v1/projects",
                "http_status": 200,
                "bytes_out": 4096,
                "scenario_label": "stolen_token_misuse",
                "attack_id": attack_id,
                "nat_egress_flag": False,
                "geo_asn": victim.home_asn,
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )
        # Attacker replays exact token from different device & foreign ASN + priv escalation 35s later
        t1 = t0 + 35_000
        records.append(
            {
                "event_id": next_id(f"tok-replay-{st_idx}"),
                "event_time_ms": t1,
                "ingest_time_ms": t1 + 190,
                "source_stream": "api_gateway",
                "action": "priv_escalation",
                "outcome": "success",
                "actor_email": victim.email,
                "device_id": f"dev-exfil-{st_idx:02d}",
                "session_id": f"ses-tok-rogue-{st_idx}",
                "token_id": shared_tok,
                "source_ip": f"45.155.205.{90 + st_idx}",
                "geo_country": "RU",
                "geo_lat": 55.7558,
                "geo_lon": 37.6173,
                "target_resource": "/admin/iam-policy-export",
                "http_status": 200,
                "bytes_out": 1_850_000,
                "scenario_label": "stolen_token_misuse",
                "attack_id": attack_id,
                "nat_egress_flag": False,
                "geo_asn": "AS49505",
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )

    # 7. Lateral Movement Multi-Source Interval Join (auth -> endpoint -> dns/proxy beacon)
    for lm_idx in range(2 * campaign_scale):
        attack_id = f"atk_lateral_move_{seed}_{lm_idx:02d}"
        victim = non_nat_emps[(22 + lm_idx) % len(non_nat_emps)]
        t0 = base_time_ms + 1_450_000 + lm_idx * 380_000
        ground_truth[attack_id] = {
            "rule_id": "lateral_movement",
            "expected_active": True,
            "scenario": "lateral_movement",
            "victim_email": victim.email,
        }
        # Step 1: Auth jumpbox login
        records.append(
            {
                "event_id": next_id(f"lat-auth-{lm_idx}"),
                "event_time_ms": t0,
                "ingest_time_ms": t0 + 160,
                "source_stream": "auth",
                "action": "login_success",
                "outcome": "success",
                "actor_email": victim.email,
                "device_id": victim.device_id,
                "session_id": f"ses-lat-{lm_idx}",
                "token_id": f"tok-lat-{lm_idx}",
                "source_ip": victim.home_ip,
                "geo_country": victim.home_country,
                "geo_lat": victim.home_lat,
                "geo_lon": victim.home_lon,
                "target_resource": "bastion/prod-jumpbox-01",
                "http_status": 200,
                "bytes_out": 900,
                "scenario_label": "lateral_movement",
                "attack_id": attack_id,
                "nat_egress_flag": False,
                "geo_asn": victim.home_asn,
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )
        # Step 2: Endpoint suspicious process execution (email omitted — resolved via device_id!)
        t1 = t0 + 95_000
        records.append(
            {
                "event_id": next_id(f"lat-ep-{lm_idx}"),
                "event_time_ms": t1,
                "ingest_time_ms": t1 + 220,
                "source_stream": "endpoint",
                "action": "process_exec_suspicious",
                "outcome": "alert",
                "actor_email": None,
                "device_id": victim.device_id,
                "session_id": f"ses-lat-{lm_idx}",
                "token_id": None,
                "source_ip": victim.home_ip,
                "geo_country": victim.home_country,
                "geo_lat": victim.home_lat,
                "geo_lon": victim.home_lon,
                "target_resource": "proc/ssh-agent-hijack",
                "http_status": None,
                "bytes_out": 12_288,
                "scenario_label": "lateral_movement",
                "attack_id": attack_id,
                "nat_egress_flag": False,
                "geo_asn": victim.home_asn,
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )
        # Step 3: DNS C2 resolution + Proxy beacon exfiltration
        t2 = t1 + 70_000
        records.append(
            {
                "event_id": next_id(f"lat-dns-{lm_idx}"),
                "event_time_ms": t2,
                "ingest_time_ms": t2 + 170,
                "source_stream": "dns",
                "action": "dns_query",
                "outcome": "success",
                "actor_email": None,
                "device_id": victim.device_id,
                "session_id": None,
                "token_id": None,
                "source_ip": victim.home_ip,
                "geo_country": victim.home_country,
                "geo_lat": victim.home_lat,
                "geo_lon": victim.home_lon,
                "target_resource": f"stage-{lm_idx}.c2-beacon.bad-tld",
                "http_status": None,
                "bytes_out": 2048,
                "scenario_label": "lateral_movement",
                "attack_id": attack_id,
                "nat_egress_flag": False,
                "geo_asn": victim.home_asn,
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )
        t3 = t2 + 25_000
        records.append(
            {
                "event_id": next_id(f"lat-proxy-{lm_idx}"),
                "event_time_ms": t3,
                "ingest_time_ms": t3 + 210,
                "source_stream": "proxy",
                "action": "proxy_beacon",
                "outcome": "success",
                "actor_email": victim.email,
                "device_id": victim.device_id,
                "session_id": f"ses-lat-{lm_idx}",
                "token_id": None,
                "source_ip": victim.home_ip,
                "geo_country": victim.home_country,
                "geo_lat": victim.home_lat,
                "geo_lon": victim.home_lon,
                "target_resource": f"https://stage-{lm_idx}.c2-beacon.bad-tld/upload",
                "http_status": 200,
                "bytes_out": 8_500_000,
                "scenario_label": "lateral_movement",
                "attack_id": attack_id,
                "nat_egress_flag": False,
                "geo_asn": victim.home_asn,
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )

    # 8. Anomalous Access Burst (TRUE POSITIVES: high-volume data scraping in <60s)
    for ab_idx in range(2 * campaign_scale):
        attack_id = f"atk_access_burst_{seed}_{ab_idx:02d}"
        victim = non_nat_emps[(28 + ab_idx) % len(non_nat_emps)]
        t0 = base_time_ms + 1_900_000 + ab_idx * 300_000
        ground_truth[attack_id] = {
            "rule_id": "anomalous_access_burst",
            "expected_active": True,
            "scenario": "anomalous_access_burst",
            "victim_email": victim.email,
        }
        for b in range(14):
            ev_ts = t0 + b * 2_500
            records.append(
                {
                    "event_id": next_id(f"burst-{ab_idx}-{b}"),
                    "event_time_ms": ev_ts,
                    "ingest_time_ms": ev_ts + 120,
                    "source_stream": "application" if b % 2 == 0 else "api_gateway",
                    "action": "bulk_export",
                    "outcome": "success",
                    "actor_email": victim.email,
                    "device_id": victim.device_id,
                    "session_id": f"ses-burst-{ab_idx}",
                    "token_id": f"tok-burst-{ab_idx}",
                    "source_ip": victim.home_ip,
                    "geo_country": victim.home_country,
                    "geo_lat": victim.home_lat,
                    "geo_lon": victim.home_lon,
                    "target_resource": f"/v1/customers/export?page={b}",
                    "http_status": 200,
                    "bytes_out": 4_500_000,
                    "scenario_label": "anomalous_access_burst",
                    "attack_id": attack_id,
                    "nat_egress_flag": False,
                    "geo_asn": victim.home_asn,
                    "clock_skew_ms": 0,
                    "is_retraction_evidence": False,
                    "schema_version": 2,
                }
            )

    # 9. GDPR Subject Deletion Requests (for right-to-erasure workflow)
    gdpr_emails: list[str] = []
    for g_idx in range(2):
        emp = employees[len(employees) - 1 - g_idx]
        gdpr_emails.append(emp.email)
        t_gdpr = base_time_ms + 2_600_000 + g_idx * 10_000
        records.append(
            {
                "event_id": next_id(f"gdpr-req-{g_idx}"),
                "event_time_ms": t_gdpr,
                "ingest_time_ms": t_gdpr + 100,
                "source_stream": "application",
                "action": "gdpr_delete_request",
                "outcome": "info",
                "actor_email": emp.email,
                "device_id": emp.device_id,
                "session_id": f"ses-gdpr-{g_idx}",
                "token_id": None,
                "source_ip": emp.home_ip,
                "geo_country": emp.home_country,
                "geo_lat": emp.home_lat,
                "geo_lon": emp.home_lon,
                "target_resource": "privacy-portal/article-17-erasure",
                "http_status": 202,
                "bytes_out": 512,
                "scenario_label": "gdpr_deletion",
                "attack_id": None,
                "nat_egress_flag": False,
                "geo_asn": emp.home_asn,
                "clock_skew_ms": 0,
                "is_retraction_evidence": False,
                "schema_version": 2,
            }
        )

    # 10. Historical Aged Records (10 days old -> tests retention TTL sweep for 7-day raw window)
    aged_count = 0
    if include_aged_events:
        ten_days_ms = 10 * 86_400 * 1000
        for a_idx in range(15):
            emp = employees[a_idx % len(employees)]
            ev_ts = base_time_ms - ten_days_ms + a_idx * 1000
            records.append(
                {
                    "event_id": next_id(f"aged-{a_idx}"),
                    "event_time_ms": ev_ts,
                    "ingest_time_ms": ev_ts + 200,
                    "source_stream": "auth",
                    "action": "login_success",
                    "outcome": "success",
                    "actor_email": emp.email,
                    "device_id": emp.device_id,
                    "session_id": f"ses-aged-{a_idx}",
                    "token_id": f"tok-aged-{a_idx}",
                    "source_ip": emp.home_ip,
                    "geo_country": emp.home_country,
                    "geo_lat": emp.home_lat,
                    "geo_lon": emp.home_lon,
                    "target_resource": "idp/sso-login",
                    "http_status": 200,
                    "bytes_out": 740,
                    "scenario_label": "aged_retention_fixture",
                    "attack_id": None,
                    "nat_egress_flag": False,
                    "geo_asn": emp.home_asn,
                    "clock_skew_ms": 0,
                    "is_retraction_evidence": False,
                    "schema_version": 2,
                }
            )
            aged_count += 1

    # 11. Duplicate logs (~3% of valid records simulating at-least-once broker retries)
    valid_snapshot = list(records)
    dup_target = max(10, int(len(valid_snapshot) * 0.03))
    dup_indices = rng.sample(range(len(valid_snapshot)), k=min(dup_target, len(valid_snapshot)))
    duplicate_count = 0
    for idx in dup_indices:
        dup_copy = dict(valid_snapshot[idx])
        dup_copy["ingest_time_ms"] = int(dup_copy["ingest_time_ms"]) + rng.randint(500, 4_000)
        records.append(dup_copy)
        duplicate_count += 1

    # 12. Malformed poison records (must be caught by schema/DQ gate & routed to DLQ!)
    poison_count = 0
    if include_poison_events:
        poison_target = max(6, int(total_events * 0.01))
        for p_idx in range(poison_target):
            kind = p_idx % 4
            if kind == 0:
                bad: dict[str, Any] = {
                    "event_id": "",
                    "event_time_ms": base_time_ms + p_idx * 1000,
                    "ingest_time_ms": base_time_ms + p_idx * 1000 + 50,
                    "source_stream": "auth",
                    "action": "login_failed",
                    "outcome": "failure",
                    "source_ip": "198.51.100.99",
                    "geo_country": "US",
                    "geo_lat": 37.7,
                    "geo_lon": -122.4,
                    "target_resource": "idp/sso-login",
                }
            elif kind == 1:
                bad = {
                    "event_id": next_id(f"poison-stream-{p_idx}"),
                    "event_time_ms": base_time_ms + p_idx * 1000,
                    "ingest_time_ms": base_time_ms + p_idx * 1000 + 50,
                    "source_stream": "unknown_telemetry_bus",
                    "action": "corrupt_op",
                    "outcome": "failure",
                    "source_ip": "198.51.100.99",
                    "geo_country": "US",
                    "geo_lat": 37.7,
                    "geo_lon": -122.4,
                    "target_resource": "bad/route",
                }
            elif kind == 2:
                bad = {
                    "event_id": next_id(f"poison-negts-{p_idx}"),
                    "event_time_ms": -999999,
                    "ingest_time_ms": base_time_ms,
                    "source_stream": "proxy",
                    "action": "http_request",
                    "outcome": "success",
                    "source_ip": "not-an-ip-address",
                    "geo_country": "US",
                    "geo_lat": 999.0,
                    "geo_lon": -999.0,
                    "target_resource": "broken",
                }
            else:
                bad = {
                    "event_id": next_id(f"poison-missing-{p_idx}"),
                    "event_time_ms": "not_a_timestamp",
                    "source_stream": "dns",
                }
            records.append(bad)
            poison_count += 1

    # Sort primarily by ingest_time_ms (preserving realistic out-of-order event_time_ms arrivals)
    records.sort(
        key=lambda r: (
            int(r.get("ingest_time_ms", base_time_ms))
            if isinstance(r.get("ingest_time_ms"), int)
            else base_time_ms + 9_999_999,
            str(r.get("event_id", "")),
        )
    )

    return GeneratedBatch(
        seed=seed,
        raw_records=records,
        ground_truth_attacks=ground_truth,
        gdpr_deletion_emails=gdpr_emails,
        poison_count=poison_count,
        duplicate_count=duplicate_count,
        aged_count=aged_count,
    )
