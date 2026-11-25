"""Cryptographic tokenization, field masking, crypto-shredding vault, PII scanner, and k-anonymity."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from models.contracts import PrivacySafeAggregate, SecurityEvent, TokenizedSecurityEvent

RAW_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RAW_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def mask_email(email: str | None) -> str | None:
    """Field-level email redaction preserving only first/last char of local part and domain TLD."""
    if not email or "@" not in email:
        return None
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = f"{local[0]}***{local[-1]}"
    domain_parts = domain.split(".")
    if len(domain_parts) >= 2:
        root = domain_parts[0]
        masked_root = f"{root[0]}***" if root else "***"
        masked_domain = ".".join([masked_root, *domain_parts[1:]])
    else:
        masked_domain = "***"
    return f"{masked_local}@{masked_domain}"


def mask_ip_subnet(ip_str: str) -> str:
    """Mask IPv4 host bits to /24 CIDR subnet (or /48 for IPv6) so raw host IP never leaves raw zone."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4:
            net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            return str(net)
        net6 = ipaddress.ip_network(f"{ip_str}/48", strict=False)
        return str(net6)
    except ValueError:
        return "0.0.0.0/24"


def coarsen_geo(lat: float, lon: float) -> tuple[float, float]:
    """Coarsen coordinates to 0.1 degree (~11 km) for privacy-safe analytical storage."""
    return round(lat, 1), round(lon, 1)


def compute_evidence_ref(event_ids: list[str], rule_ref: str) -> str:
    """Compute immutable SHA-256 evidence pointer linking gold incidents to restricted bronze evidence."""
    canonical = f"{rule_ref}|" + "|".join(sorted(set(event_ids)))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"evref_sha256:{digest}"


class PrivacyVault:
    """HMAC-SHA256 tokenization engine with per-subject crypto-shredding keys (OpenBao local parity)."""

    def __init__(self, master_key: str, key_version: str, vault_file: Path) -> None:
        self.master_key = master_key.encode("utf-8")
        self.key_version = key_version
        self.vault_file = vault_file
        self.vault_file.parent.mkdir(parents=True, exist_ok=True)
        self._subject_keys: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if self.vault_file.exists():
            data = json.loads(self.vault_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._subject_keys = data

    def save(self) -> None:
        self.vault_file.parent.mkdir(parents=True, exist_ok=True)
        self.vault_file.write_text(
            json.dumps(self._subject_keys, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def hmac_token(self, namespace: str, raw_value: str) -> str:
        """Deterministic keyed HMAC-SHA256 pseudonym token."""
        msg = f"{self.key_version}:{namespace}:{raw_value.strip().lower()}".encode()
        digest = hmac.new(self.master_key, msg, hashlib.sha256).hexdigest()[:20]
        return f"{namespace}_{self.key_version}_{digest}"

    def ensure_subject_key(self, principal_token: str) -> str:
        """Return per-subject crypto-shredding key ID; creates if missing and not shredded."""
        existing = self._subject_keys.get(principal_token)
        if existing is not None:
            if existing.get("shredded"):
                return "SHREDDED"
            return str(existing["subject_key_id"])
        subject_salt = secrets.token_hex(16)
        key_id = f"sbjk_{hashlib.sha256(subject_salt.encode()).hexdigest()[:12]}"
        self._subject_keys[principal_token] = {
            "subject_key_id": key_id,
            "subject_salt": subject_salt,
            "key_version": self.key_version,
            "created_at_ms": int(time.time() * 1000),
            "shredded": False,
            "shredded_at_ms": None,
        }
        return key_id

    def is_subject_shredded(self, principal_token: str) -> bool:
        entry = self._subject_keys.get(principal_token)
        return bool(entry and entry.get("shredded"))

    def crypto_shred_subject(self, principal_token: str) -> dict[str, Any]:
        """Destroy per-subject salt/key material permanently (GDPR Article 17 crypto-shredding)."""
        now_ms = int(time.time() * 1000)
        existed = principal_token in self._subject_keys
        self._subject_keys[principal_token] = {
            "subject_key_id": "SHREDDED",
            "subject_salt": None,
            "key_version": self.key_version,
            "created_at_ms": self._subject_keys.get(principal_token, {}).get("created_at_ms"),
            "shredded": True,
            "shredded_at_ms": now_ms,
        }
        self.save()
        return {
            "principal_token": principal_token,
            "key_existed": existed,
            "shredded": True,
            "shredded_at_ms": now_ms,
        }

    def tokenize_event(
        self,
        event: SecurityEvent,
        principal_token: str,
    ) -> TokenizedSecurityEvent:
        """Convert raw SecurityEvent into a zero-raw-PII TokenizedSecurityEvent."""
        self.ensure_subject_key(principal_token)
        event_date = time.strftime("%Y-%m-%d", time.gmtime(event.event_time_ms / 1000.0))
        lat_c, lon_c = coarsen_geo(event.geo_lat, event.geo_lon)
        return TokenizedSecurityEvent(
            event_id=event.event_id,
            event_time_ms=event.event_time_ms,
            ingest_time_ms=event.ingest_time_ms,
            event_date=event_date,
            source_stream=event.source_stream.value,
            action=event.action,
            outcome=event.outcome,
            principal_token=principal_token,
            masked_email=mask_email(event.actor_email),
            device_token=self.hmac_token("dev", event.device_id) if event.device_id else None,
            session_token=self.hmac_token("ses", event.session_id) if event.session_id else None,
            token_hash=self.hmac_token("tok", event.token_id) if event.token_id else None,
            ip_token=self.hmac_token("ip", event.source_ip),
            ip_subnet_masked=mask_ip_subnet(event.source_ip),
            geo_country=event.geo_country,
            geo_lat_coarse=lat_c,
            geo_lon_coarse=lon_c,
            geo_asn=event.geo_asn,
            nat_egress_flag=event.nat_egress_flag,
            target_resource=event.target_resource,
            http_status=event.http_status,
            bytes_out=event.bytes_out,
            clock_skew_ms=event.clock_skew_ms,
            is_retraction_evidence=event.is_retraction_evidence,
            key_version=self.key_version,
            evidence_ref=compute_evidence_ref([event.event_id], "raw_event_pointer"),
            scenario_label=event.scenario_label,
            attack_id=event.attack_id,
            schema_version=event.schema_version,
        )


def scan_for_raw_pii(records: list[dict[str, Any]]) -> list[str]:
    """Scan silver/gold records for accidental leakage of raw emails or unmasked IPv4 addresses."""
    violations: list[str] = []
    for idx, rec in enumerate(records):
        for field_name, value in rec.items():
            if not isinstance(value, str):
                continue
            if field_name == "masked_email":
                # Masked email must always include "***" before "@"
                if "@" in value and "***" not in value.split("@", 1)[0]:
                    violations.append(f"row={idx} field={field_name} unmasked_email")
                continue
            if field_name == "ip_subnet_masked":
                # Masked subnet must end in .0/24 (or IPv6 /48)
                if not (value.endswith(".0/24") or value.endswith("/48")):
                    violations.append(f"row={idx} field={field_name} unmasked_ip={value}")
                continue
            if RAW_EMAIL_RE.search(value) and "***" not in value:
                violations.append(f"row={idx} field={field_name} leaked_email")
            for ip_match in RAW_IPV4_RE.finditer(value):
                end_pos = ip_match.end()
                if not (
                    value[ip_match.start() : end_pos].endswith(".0")
                    and value[end_pos : end_pos + 3] == "/24"
                ):
                    violations.append(f"row={idx} field={field_name} leaked_ipv4")
                    break
    return violations


def build_privacy_safe_aggregates(
    tokenized_events: list[TokenizedSecurityEvent],
    k_threshold: int = 5,
) -> tuple[list[PrivacySafeAggregate], int]:
    """Build k-anonymous aggregates guaranteeing distinct_principals >= k AND event_count >= k."""
    if k_threshold < 2:
        raise ValueError("k_threshold must be >= 2")

    buckets: dict[tuple[str, str, str, str], dict[str, Any]] = defaultdict(
        lambda: {"events": 0, "principals": set(), "failures": 0, "bytes_out": 0}
    )
    for ev in tokenized_events:
        key = (ev.event_date, ev.source_stream, ev.geo_country, ev.action)
        b = buckets[key]
        b["events"] += 1
        b["principals"].add(ev.principal_token)
        if ev.outcome in ("failure", "blocked"):
            b["failures"] += 1
        b["bytes_out"] += ev.bytes_out

    results: list[PrivacySafeAggregate] = []
    suppressed_count = 0
    overflow_by_date_stream: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"events": 0, "principals": set(), "failures": 0, "bytes_out": 0, "merged": 0}
    )

    for (bucket_date, stream, country, action), stats in sorted(buckets.items()):
        distinct_p = len(stats["principals"])
        if distinct_p >= k_threshold and stats["events"] >= k_threshold:
            results.append(
                PrivacySafeAggregate(
                    bucket_date=bucket_date,
                    source_stream=stream,
                    geo_country=country,
                    action=action,
                    event_count=stats["events"],
                    distinct_principals=distinct_p,
                    failure_count=stats["failures"],
                    bytes_out_sum=stats["bytes_out"],
                    k_anonymity_threshold=k_threshold,
                    suppressed_buckets_merged=0,
                )
            )
        else:
            suppressed_count += 1
            ov = overflow_by_date_stream[(bucket_date, stream)]
            ov["events"] += stats["events"]
            ov["principals"].update(stats["principals"])
            ov["failures"] += stats["failures"]
            ov["bytes_out"] += stats["bytes_out"]
            ov["merged"] += 1

    # Only emit merged suppressed bucket if the combined bucket itself meets k-anonymity!
    for (bucket_date, stream), ov in sorted(overflow_by_date_stream.items()):
        distinct_p = len(ov["principals"])
        if distinct_p >= k_threshold and ov["events"] >= k_threshold:
            results.append(
                PrivacySafeAggregate(
                    bucket_date=bucket_date,
                    source_stream=stream,
                    geo_country="SUPPRESSED_OTHER",
                    action="SUPPRESSED_OTHER",
                    event_count=ov["events"],
                    distinct_principals=distinct_p,
                    failure_count=ov["failures"],
                    bytes_out_sum=ov["bytes_out"],
                    k_anonymity_threshold=k_threshold,
                    suppressed_buckets_merged=ov["merged"],
                )
            )

    return results, suppressed_count
