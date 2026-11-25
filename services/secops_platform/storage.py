"""Apache Iceberg V2 lakehouse with privacy zone isolation, DuckDB analytics, compaction, retention, and GDPR erasure."""

from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any

import duckdb
import pyarrow as pa
from pyiceberg.catalog import Catalog, load_catalog
from pyiceberg.exceptions import NamespaceAlreadyExistsError, NoSuchTableError
from pyiceberg.partitioning import PartitionField, PartitionSpec
from pyiceberg.table import Table
from pyiceberg.transforms import IdentityTransform

from models.contracts import (
    AuditLogEntry,
    CepIncident,
    DataQualityResult,
    EntityRiskScore,
    IncidentStatus,
    PrivacySafeAggregate,
    SecurityEvent,
    TokenizedSecurityEvent,
)
from services.secops_platform.config import PlatformConfig
from services.secops_platform.logging_obs import METRICS
from services.secops_platform.privacy import PrivacyVault, compute_evidence_ref

# Explicit PyArrow schemas for all 9 Iceberg V2 tables
RAW_EVIDENCE_SCHEMA = pa.schema(
    [
        pa.field("event_id", pa.string(), nullable=False),
        pa.field("principal_token", pa.string(), nullable=False),
        pa.field("event_time_ms", pa.int64(), nullable=False),
        pa.field("ingest_time_ms", pa.int64(), nullable=False),
        pa.field("event_date", pa.string(), nullable=False),
        pa.field("source_stream", pa.string(), nullable=False),
        pa.field("action", pa.string(), nullable=False),
        pa.field("outcome", pa.string(), nullable=False),
        pa.field("actor_email", pa.string(), nullable=True),
        pa.field("device_id", pa.string(), nullable=True),
        pa.field("session_id", pa.string(), nullable=True),
        pa.field("token_id", pa.string(), nullable=True),
        pa.field("source_ip", pa.string(), nullable=False),
        pa.field("geo_country", pa.string(), nullable=False),
        pa.field("geo_lat", pa.float64(), nullable=False),
        pa.field("geo_lon", pa.float64(), nullable=False),
        pa.field("geo_asn", pa.string(), nullable=False),
        pa.field("nat_egress_flag", pa.bool_(), nullable=False),
        pa.field("target_resource", pa.string(), nullable=False),
        pa.field("bytes_out", pa.int64(), nullable=False),
        pa.field("evidence_ref", pa.string(), nullable=False),
        pa.field("raw_payload_json", pa.string(), nullable=False),
    ]
)

QUARANTINE_DLQ_SCHEMA = pa.schema(
    [
        pa.field("dlq_id", pa.string(), nullable=False),
        pa.field("ingested_at_ms", pa.int64(), nullable=False),
        pa.field("error_code", pa.string(), nullable=False),
        pa.field("error_reason", pa.string(), nullable=False),
        pa.field("raw_payload_json", pa.string(), nullable=False),
    ]
)

TOKENIZED_EVENTS_SCHEMA = pa.schema(
    [
        pa.field("event_id", pa.string(), nullable=False),
        pa.field("event_time_ms", pa.int64(), nullable=False),
        pa.field("ingest_time_ms", pa.int64(), nullable=False),
        pa.field("event_date", pa.string(), nullable=False),
        pa.field("source_stream", pa.string(), nullable=False),
        pa.field("action", pa.string(), nullable=False),
        pa.field("outcome", pa.string(), nullable=False),
        pa.field("principal_token", pa.string(), nullable=False),
        pa.field("masked_email", pa.string(), nullable=True),
        pa.field("device_token", pa.string(), nullable=True),
        pa.field("session_token", pa.string(), nullable=True),
        pa.field("token_hash", pa.string(), nullable=True),
        pa.field("ip_token", pa.string(), nullable=False),
        pa.field("ip_subnet_masked", pa.string(), nullable=False),
        pa.field("geo_country", pa.string(), nullable=False),
        pa.field("geo_lat_coarse", pa.float64(), nullable=False),
        pa.field("geo_lon_coarse", pa.float64(), nullable=False),
        pa.field("geo_asn", pa.string(), nullable=False),
        pa.field("nat_egress_flag", pa.bool_(), nullable=False),
        pa.field("target_resource", pa.string(), nullable=False),
        pa.field("http_status", pa.int32(), nullable=True),
        pa.field("bytes_out", pa.int64(), nullable=False),
        pa.field("clock_skew_ms", pa.int64(), nullable=False),
        pa.field("is_retraction_evidence", pa.bool_(), nullable=False),
        pa.field("key_version", pa.string(), nullable=False),
        pa.field("evidence_ref", pa.string(), nullable=False),
        pa.field("scenario_label", pa.string(), nullable=False),
        pa.field("attack_id", pa.string(), nullable=True),
        pa.field("schema_version", pa.int32(), nullable=False),
    ]
)

IDENTITY_MAP_SCHEMA = pa.schema(
    [
        pa.field("principal_token", pa.string(), nullable=False),
        pa.field("alias_type", pa.string(), nullable=False),
        pa.field("alias_token", pa.string(), nullable=False),
        pa.field("subject_key_id", pa.string(), nullable=False),
        pa.field("first_seen_ms", pa.int64(), nullable=False),
        pa.field("last_seen_ms", pa.int64(), nullable=False),
        pa.field("key_version", pa.string(), nullable=False),
    ]
)

CEP_INCIDENTS_SCHEMA = pa.schema(
    [
        pa.field("incident_id", pa.string(), nullable=False),
        pa.field("rule_id", pa.string(), nullable=False),
        pa.field("rule_version", pa.string(), nullable=False),
        pa.field("rule_ref", pa.string(), nullable=False),
        pa.field("severity", pa.string(), nullable=False),
        pa.field("status", pa.string(), nullable=False),
        pa.field("principal_token", pa.string(), nullable=False),
        pa.field("masked_email", pa.string(), nullable=True),
        pa.field("ip_subnet_masked", pa.string(), nullable=False),
        pa.field("geo_country", pa.string(), nullable=False),
        pa.field("first_event_time_ms", pa.int64(), nullable=False),
        pa.field("last_event_time_ms", pa.int64(), nullable=False),
        pa.field("detected_at_ms", pa.int64(), nullable=False),
        pa.field("detection_delay_ms", pa.int64(), nullable=False),
        pa.field("event_count", pa.int32(), nullable=False),
        pa.field("evidence_event_ids_json", pa.string(), nullable=False),
        pa.field("evidence_ref", pa.string(), nullable=False),
        pa.field("confidence_score", pa.float64(), nullable=False),
        pa.field("summary", pa.string(), nullable=False),
        pa.field("retracted_reason", pa.string(), nullable=True),
        pa.field("disposition_by", pa.string(), nullable=True),
        pa.field("disposition_note", pa.string(), nullable=True),
        pa.field("disposition_at_ms", pa.int64(), nullable=True),
        pa.field("ground_truth_attack_id", pa.string(), nullable=True),
    ]
)

ENTITY_RISK_SCHEMA = pa.schema(
    [
        pa.field("principal_token", pa.string(), nullable=False),
        pa.field("masked_email", pa.string(), nullable=True),
        pa.field("risk_score", pa.float64(), nullable=False),
        pa.field("risk_tier", pa.string(), nullable=False),
        pa.field("active_incident_count", pa.int32(), nullable=False),
        pa.field("retracted_incident_count", pa.int32(), nullable=False),
        pa.field("rules_triggered_json", pa.string(), nullable=False),
        pa.field("last_seen_ms", pa.int64(), nullable=False),
        pa.field("updated_at_ms", pa.int64(), nullable=False),
    ]
)

PRIVACY_AGGREGATES_SCHEMA = pa.schema(
    [
        pa.field("bucket_date", pa.string(), nullable=False),
        pa.field("source_stream", pa.string(), nullable=False),
        pa.field("geo_country", pa.string(), nullable=False),
        pa.field("action", pa.string(), nullable=False),
        pa.field("event_count", pa.int64(), nullable=False),
        pa.field("distinct_principals", pa.int64(), nullable=False),
        pa.field("failure_count", pa.int64(), nullable=False),
        pa.field("bytes_out_sum", pa.int64(), nullable=False),
        pa.field("k_anonymity_threshold", pa.int32(), nullable=False),
        pa.field("suppressed_buckets_merged", pa.int32(), nullable=False),
    ]
)

AUDIT_LOG_SCHEMA = pa.schema(
    [
        pa.field("audit_id", pa.string(), nullable=False),
        pa.field("event_time_ms", pa.int64(), nullable=False),
        pa.field("action_type", pa.string(), nullable=False),
        pa.field("actor_id", pa.string(), nullable=False),
        pa.field("actor_role", pa.string(), nullable=False),
        pa.field("target_resource", pa.string(), nullable=False),
        pa.field("decision", pa.string(), nullable=False),
        pa.field("justification", pa.string(), nullable=True),
        pa.field("details_json", pa.string(), nullable=False),
    ]
)

DQ_RESULTS_SCHEMA = pa.schema(
    [
        pa.field("run_id", pa.string(), nullable=False),
        pa.field("checked_at_ms", pa.int64(), nullable=False),
        pa.field("check_name", pa.string(), nullable=False),
        pa.field("table_name", pa.string(), nullable=False),
        pa.field("passed", pa.bool_(), nullable=False),
        pa.field("observed_value", pa.float64(), nullable=False),
        pa.field("threshold_value", pa.float64(), nullable=False),
        pa.field("details", pa.string(), nullable=False),
    ]
)

TABLE_SPECS: dict[str, tuple[pa.Schema, str, str | None]] = {
    "bronze.raw_security_evidence": (RAW_EVIDENCE_SCHEMA, "restricted_raw_pii", "event_date"),
    "bronze.quarantine_dlq": (QUARANTINE_DLQ_SCHEMA, "restricted_quarantine", None),
    "silver.tokenized_security_events": (TOKENIZED_EVENTS_SCHEMA, "tokenized_analytics", "event_date"),
    "silver.identity_resolution_map": (IDENTITY_MAP_SCHEMA, "vault_managed_linkage", None),
    "gold.cep_security_incidents": (CEP_INCIDENTS_SCHEMA, "tokenized_soc_incidents", None),
    "gold.entity_risk_scores": (ENTITY_RISK_SCHEMA, "tokenized_soc_risk", None),
    "gold.privacy_safe_aggregates": (PRIVACY_AGGREGATES_SCHEMA, "privacy_safe_k_anon", None),
    "gold.retention_and_erasure_audit": (AUDIT_LOG_SCHEMA, "immutable_governance_audit", None),
    "quality.dq_results": (DQ_RESULTS_SCHEMA, "governance_quality", None),
}


class PrivacyLakehouse:
    """Manages Apache Iceberg V2 privacy-zone tables, DuckDB queries, compaction, retention, and erasure."""

    def __init__(self, config: PlatformConfig) -> None:
        self.config = config
        self.config.ensure_directories()
        self._lock = threading.RLock()
        self.catalog: Catalog = load_catalog(
            "secops",
            **{
                "type": "sql",
                "uri": f"sqlite:///{self.config.catalog_db_path}",
                "warehouse": f"file://{self.config.warehouse_dir}",
            },
        )
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        with self._lock:
            for ns in ("bronze", "silver", "gold", "quality"):
                try:
                    self.catalog.create_namespace(ns)
                except NamespaceAlreadyExistsError:
                    pass

            for full_name, (arrow_schema, zone, part_col) in TABLE_SPECS.items():
                try:
                    self.catalog.load_table(full_name)
                except NoSuchTableError:
                    props = {
                        "format-version": "2",
                        "secops.privacy_zone": zone,
                        "write.parquet.compression-codec": "zstd",
                    }
                    tbl = self.catalog.create_table(
                        identifier=full_name,
                        schema=arrow_schema,
                        properties=props,
                    )
                    if part_col is not None:
                        ice_field = tbl.schema().find_field(part_col)
                        spec = PartitionSpec(
                            PartitionField(
                                source_id=ice_field.field_id,
                                field_id=1000,
                                transform=IdentityTransform(),
                                name=part_col,
                            )
                        )
                        with tbl.update_spec() as upd:
                            upd.add_identity(part_col)
                        _ = spec

    def load_table(self, table_name: str) -> Table:
        with self._lock:
            return self.catalog.load_table(table_name)

    def _to_arrow(self, table_name: str, rows: list[dict[str, Any]]) -> pa.Table:
        schema = TABLE_SPECS[table_name][0]
        if not rows:
            return pa.Table.from_pylist([], schema=schema)
        return pa.Table.from_pylist(rows, schema=schema)

    def overwrite_rows(self, table_name: str, rows: list[dict[str, Any]]) -> int:
        with self._lock:
            tbl = self.catalog.load_table(table_name)
            arrow_tbl = self._to_arrow(table_name, rows)
            if tbl.current_snapshot() is None:
                if rows:
                    tbl.append(arrow_tbl)
            else:
                tbl.overwrite(arrow_tbl)
            return len(rows)

    def append_rows(self, table_name: str, rows: list[dict[str, Any]]) -> int:
        if not rows:
            return 0
        with self._lock:
            tbl = self.catalog.load_table(table_name)
            arrow_tbl = self._to_arrow(table_name, rows)
            tbl.append(arrow_tbl)
            return len(rows)

    def read_arrow(self, table_name: str, snapshot_id: int | None = None) -> pa.Table:
        with self._lock:
            tbl = self.catalog.load_table(table_name)
            if snapshot_id is not None:
                return tbl.scan(snapshot_id=snapshot_id).to_arrow()
            return tbl.scan().to_arrow()

    def read_rows(self, table_name: str, snapshot_id: int | None = None) -> list[dict[str, Any]]:
        return self.read_arrow(table_name, snapshot_id=snapshot_id).to_pylist()

    def table_row_count(self, table_name: str) -> int:
        return int(self.read_arrow(table_name).num_rows)

    def table_data_file_count(self, table_name: str) -> int:
        with self._lock:
            tbl = self.catalog.load_table(table_name)
            return len(list(tbl.scan().plan_files()))

    def table_snapshots(self, table_name: str) -> list[dict[str, Any]]:
        with self._lock:
            tbl = self.catalog.load_table(table_name)
            return [
                {
                    "snapshot_id": int(s.snapshot_id),
                    "timestamp_ms": int(s.timestamp_ms),
                    "summary": dict(s.summary.additional_properties) if s.summary else {},
                }
                for s in tbl.snapshots()
            ]

    def write_raw_evidence(
        self,
        events: list[tuple[SecurityEvent, str]],
        *,
        mode: str = "overwrite",
    ) -> int:
        rows: list[dict[str, Any]] = []
        for ev, principal_token in events:
            ev_date = time.strftime("%Y-%m-%d", time.gmtime(ev.event_time_ms / 1000.0))
            rows.append(
                {
                    "event_id": ev.event_id,
                    "principal_token": principal_token,
                    "event_time_ms": ev.event_time_ms,
                    "ingest_time_ms": ev.ingest_time_ms,
                    "event_date": ev_date,
                    "source_stream": ev.source_stream.value,
                    "action": ev.action,
                    "outcome": ev.outcome,
                    "actor_email": ev.actor_email,
                    "device_id": ev.device_id,
                    "session_id": ev.session_id,
                    "token_id": ev.token_id,
                    "source_ip": ev.source_ip,
                    "geo_country": ev.geo_country,
                    "geo_lat": ev.geo_lat,
                    "geo_lon": ev.geo_lon,
                    "geo_asn": ev.geo_asn,
                    "nat_egress_flag": ev.nat_egress_flag,
                    "target_resource": ev.target_resource,
                    "bytes_out": ev.bytes_out,
                    "evidence_ref": compute_evidence_ref([ev.event_id], "raw_event_pointer"),
                    "raw_payload_json": ev.model_dump_json(),
                }
            )
        if mode == "append":
            return self.append_rows("bronze.raw_security_evidence", rows)
        return self.overwrite_rows("bronze.raw_security_evidence", rows)

    def write_tokenized_events(
        self,
        events: list[TokenizedSecurityEvent],
        *,
        mode: str = "overwrite",
    ) -> int:
        rows = [ev.model_dump() for ev in events]
        if mode == "append":
            return self.append_rows("silver.tokenized_security_events", rows)
        return self.overwrite_rows("silver.tokenized_security_events", rows)

    def write_incidents(self, incidents: list[CepIncident]) -> int:
        rows = [
            {
                "incident_id": i.incident_id,
                "rule_id": i.rule_id,
                "rule_version": i.rule_version,
                "rule_ref": i.rule_ref,
                "severity": i.severity.value,
                "status": i.status.value,
                "principal_token": i.principal_token,
                "masked_email": i.masked_email,
                "ip_subnet_masked": i.ip_subnet_masked,
                "geo_country": i.geo_country,
                "first_event_time_ms": i.first_event_time_ms,
                "last_event_time_ms": i.last_event_time_ms,
                "detected_at_ms": i.detected_at_ms,
                "detection_delay_ms": i.detection_delay_ms,
                "event_count": i.event_count,
                "evidence_event_ids_json": json.dumps(i.evidence_event_ids),
                "evidence_ref": i.evidence_ref,
                "confidence_score": i.confidence_score,
                "summary": i.summary,
                "retracted_reason": i.retracted_reason,
                "disposition_by": i.disposition_by,
                "disposition_note": i.disposition_note,
                "disposition_at_ms": i.disposition_at_ms,
                "ground_truth_attack_id": i.ground_truth_attack_id,
            }
            for i in incidents
        ]
        return self.overwrite_rows("gold.cep_security_incidents", rows)

    def write_entity_risk(self, scores: list[EntityRiskScore]) -> int:
        rows = [
            {
                "principal_token": s.principal_token,
                "masked_email": s.masked_email,
                "risk_score": s.risk_score,
                "risk_tier": s.risk_tier,
                "active_incident_count": s.active_incident_count,
                "retracted_incident_count": s.retracted_incident_count,
                "rules_triggered_json": json.dumps(s.rules_triggered),
                "last_seen_ms": s.last_seen_ms,
                "updated_at_ms": s.updated_at_ms,
            }
            for s in scores
        ]
        return self.overwrite_rows("gold.entity_risk_scores", rows)

    def write_privacy_aggregates(self, aggregates: list[PrivacySafeAggregate]) -> int:
        rows = [a.model_dump() for a in aggregates]
        return self.overwrite_rows("gold.privacy_safe_aggregates", rows)

    def write_dq_results(self, results: list[DataQualityResult], *, append: bool = True) -> int:
        rows = [r.model_dump() for r in results]
        if append:
            return self.append_rows("quality.dq_results", rows)
        return self.overwrite_rows("quality.dq_results", rows)

    def append_audit_event(
        self,
        *,
        action_type: str,
        actor_id: str,
        actor_role: str,
        target_resource: str,
        decision: str,
        justification: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            audit_id=f"aud_{uuid.uuid4().hex[:16]}",
            event_time_ms=int(time.time() * 1000),
            action_type=action_type,
            actor_id=actor_id,
            actor_role=actor_role,
            target_resource=target_resource,
            decision=decision,
            justification=justification,
            details_json=json.dumps(details or {}, sort_keys=True),
        )
        self.append_rows("gold.retention_and_erasure_audit", [entry.model_dump()])
        return entry

    def get_raw_evidence_by_event_id(self, event_id: str) -> dict[str, Any] | None:
        arrow_tbl = self.read_arrow("bronze.raw_security_evidence")
        if arrow_tbl.num_rows == 0:
            return None
        con = duckdb.connect(":memory:")
        try:
            con.register("raw_ev", arrow_tbl)
            cur = con.execute(
                "SELECT * FROM raw_ev WHERE event_id = ? LIMIT 1",
                [event_id],
            )
            cols = [desc[0] for desc in cur.description or []]
            row = cur.fetchone()
            if row is None:
                return None
            return dict(zip(cols, row, strict=False))
        finally:
            con.close()

    def update_incident_disposition(
        self,
        *,
        incident_id: str,
        status: IncidentStatus,
        actor_id: str,
        note: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            rows = self.read_rows("gold.cep_security_incidents")
            updated: dict[str, Any] | None = None
            now_ms = int(time.time() * 1000)
            for row in rows:
                if row["incident_id"] == incident_id:
                    row["status"] = status.value
                    row["disposition_by"] = actor_id
                    row["disposition_note"] = note
                    row["disposition_at_ms"] = now_ms
                    updated = dict(row)
                    break
            if updated is None:
                return None
            self.overwrite_rows("gold.cep_security_incidents", rows)
            return updated

    def erase_subject_gdpr(
        self,
        *,
        principal_token: str,
        vault: PrivacyVault,
        actor_id: str,
        actor_role: str,
        justification: str,
    ) -> dict[str, Any]:
        """Execute GDPR Article 17 right-to-erasure: crypto-shredding + subject row purge.

        Guarantees 0 rows remain for `principal_token` in bronze raw evidence, silver tokenized events,
        silver identity map, and gold entity risk, while retaining non-PII k-anonymous aggregates.
        """
        with self._lock:
            shred_info = vault.crypto_shred_subject(principal_token)
            purged_counts: dict[str, int] = {}

            for tbl_name in (
                "bronze.raw_security_evidence",
                "silver.tokenized_security_events",
                "silver.identity_resolution_map",
                "gold.entity_risk_scores",
            ):
                rows = self.read_rows(tbl_name)
                kept = [r for r in rows if r["principal_token"] != principal_token]
                purged = len(rows) - len(kept)
                purged_counts[tbl_name] = purged
                if purged > 0:
                    self.overwrite_rows(tbl_name, kept)

            # Anonymize any historical incident row referencing the erased subject
            inc_rows = self.read_rows("gold.cep_security_incidents")
            inc_scrubbed = 0
            for inc in inc_rows:
                if inc["principal_token"] == principal_token:
                    inc["principal_token"] = "ERASED_GDPR_SUBJECT"
                    inc["masked_email"] = None
                    inc["summary"] = "[Subject identifiers erased under GDPR Article 17]"
                    inc_scrubbed += 1
            if inc_scrubbed > 0:
                self.overwrite_rows("gold.cep_security_incidents", inc_rows)
            purged_counts["gold.cep_security_incidents_scrubbed"] = inc_scrubbed

            agg_rows_preserved = self.table_row_count("gold.privacy_safe_aggregates")
            METRICS.privacy_erasures.inc()

            audit_entry = self.append_audit_event(
                action_type="GDPR_SUBJECT_ERASURE",
                actor_id=actor_id,
                actor_role=actor_role,
                target_resource=principal_token,
                decision="COMPLETED",
                justification=justification,
                details={
                    "crypto_shred": shred_info,
                    "purged_counts": purged_counts,
                    "privacy_safe_aggregates_preserved": agg_rows_preserved,
                },
            )
            return {
                "principal_token": principal_token,
                "crypto_shredded": True,
                "purged_counts": purged_counts,
                "remaining_raw_rows": 0,
                "remaining_tokenized_rows": 0,
                "remaining_identity_map_rows": 0,
                "privacy_safe_aggregates_preserved": agg_rows_preserved,
                "audit_id": audit_entry.audit_id,
            }

    def run_retention_sweep(
        self,
        *,
        reference_time_ms: int,
        actor_id: str,
        actor_role: str,
        justification: str = "Scheduled retention TTL enforcement sweep",
    ) -> dict[str, Any]:
        """Enforce table-specific retention TTL windows on restricted raw evidence and silver events."""
        with self._lock:
            raw_cutoff_ms = reference_time_ms - self.config.raw_retention_days * 86_400 * 1000
            silver_cutoff_ms = reference_time_ms - self.config.silver_retention_days * 86_400 * 1000

            purged: dict[str, int] = {}
            remaining: dict[str, int] = {}

            for tbl_name, cutoff_ms in (
                ("bronze.raw_security_evidence", raw_cutoff_ms),
                ("silver.tokenized_security_events", silver_cutoff_ms),
            ):
                rows = self.read_rows(tbl_name)
                kept = [r for r in rows if int(r["event_time_ms"]) >= cutoff_ms]
                removed = len(rows) - len(kept)
                purged[tbl_name] = removed
                remaining[tbl_name] = len(kept)
                if removed > 0:
                    self.overwrite_rows(tbl_name, kept)
                    METRICS.retention_purged_rows.labels(table=tbl_name).inc(removed)

            audit_entry = self.append_audit_event(
                action_type="RETENTION_TTL_SWEEP",
                actor_id=actor_id,
                actor_role=actor_role,
                target_resource="bronze.raw_security_evidence,silver.tokenized_security_events",
                decision="COMPLETED",
                justification=justification,
                details={
                    "reference_time_ms": reference_time_ms,
                    "raw_retention_days": self.config.raw_retention_days,
                    "silver_retention_days": self.config.silver_retention_days,
                    "purged_rows": purged,
                    "remaining_rows": remaining,
                },
            )
            return {
                "reference_time_ms": reference_time_ms,
                "raw_retention_days": self.config.raw_retention_days,
                "silver_retention_days": self.config.silver_retention_days,
                "purged_rows": purged,
                "remaining_rows": remaining,
                "audit_id": audit_entry.audit_id,
            }

    def compact_table(self, table_name: str) -> dict[str, Any]:
        """Compact fragmented Parquet data files in an Iceberg V2 table into consolidated files."""
        with self._lock:
            files_before = self.table_data_file_count(table_name)
            t0 = time.perf_counter()
            arrow_tbl = self.read_arrow(table_name)
            scan_before_ms = (time.perf_counter() - t0) * 1000.0

            t_compact = time.perf_counter()
            tbl = self.catalog.load_table(table_name)
            tbl.overwrite(arrow_tbl)
            compact_ms = (time.perf_counter() - t_compact) * 1000.0

            files_after = self.table_data_file_count(table_name)
            t1 = time.perf_counter()
            _ = self.read_arrow(table_name)
            scan_after_ms = (time.perf_counter() - t1) * 1000.0

            return {
                "table_name": table_name,
                "row_count": int(arrow_tbl.num_rows),
                "data_files_before": files_before,
                "data_files_after": files_after,
                "scan_before_ms": round(scan_before_ms, 3),
                "scan_after_ms": round(scan_after_ms, 3),
                "compaction_wall_ms": round(compact_ms, 3),
                "snapshot_count": len(tbl.snapshots()),
            }

    def run_duckdb_query(self, table_name: str, sql_query: str) -> list[dict[str, Any]]:
        """Execute a DuckDB SQL analytical query against an Apache Iceberg V2 table snapshot."""
        arrow_tbl = self.read_arrow(table_name)
        alias = table_name.replace(".", "_")
        con = duckdb.connect(":memory:")
        try:
            con.register(alias, arrow_tbl)
            cur = con.execute(sql_query)
            cols = [d[0] for d in cur.description or []]
            return [dict(zip(cols, row, strict=False)) for row in cur.fetchall()]
        finally:
            con.close()
