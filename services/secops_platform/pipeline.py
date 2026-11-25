"""End-to-end orchestration pipeline: WAL ingestion -> Avro/DLQ -> Tokenization/Identity -> CEP -> Iceberg V2."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from ingestion.generator import GeneratedBatch, generate_security_telemetry
from ingestion.wal_broker import DurableWalBroker
from models.contracts import PipelineRunSummary, SecurityEvent, TokenizedSecurityEvent
from processing.cep_engine import CepConfig, StreamingCepEngine
from processing.identity_resolver import IdentityResolver
from services.secops_platform.config import PlatformConfig
from services.secops_platform.dq import run_data_quality_gate, validate_and_split_events
from services.secops_platform.logging_obs import LocalSpanTracer, get_structured_logger
from services.secops_platform.privacy import PrivacyVault, build_privacy_safe_aggregates
from services.secops_platform.storage import PrivacyLakehouse

RAW_TOPIC = "security.telemetry.raw.v2"
DLQ_TOPIC = "security.telemetry.dlq.v2"
CONSUMER_GROUP = "secops-cep-processor"

logger = get_structured_logger("secops_platform.pipeline")


def _emit_openlineage_graph(
    config: PlatformConfig,
    run_id: str,
    summary: PipelineRunSummary,
) -> dict[str, Any]:
    """Write explicit OpenLineage-formatted dataset lineage graph (documented local_native export)."""
    lineage = {
        "spec": "OpenLineage-Compatible Local Export (Marquez target in distributed profile)",
        "run_id": run_id,
        "emitted_at_ms": int(time.time() * 1000),
        "job": {
            "namespace": "secops.privacy.platform",
            "name": "streaming_cep_and_privacy_lakehouse_pipeline",
        },
        "inputs": [
            {"namespace": "wal.broker", "name": RAW_TOPIC, "records": summary.events_ingested_wal},
        ],
        "outputs": [
            {
                "namespace": "iceberg.bronze",
                "name": "bronze.raw_security_evidence",
                "zone": "restricted_raw_pii",
                "records": summary.events_tokenized_silver,
            },
            {
                "namespace": "iceberg.bronze",
                "name": "bronze.quarantine_dlq",
                "zone": "restricted_quarantine",
                "records": summary.events_quarantined_dlq,
            },
            {
                "namespace": "iceberg.silver",
                "name": "silver.tokenized_security_events",
                "zone": "tokenized_analytics",
                "records": summary.events_tokenized_silver,
            },
            {
                "namespace": "iceberg.silver",
                "name": "silver.identity_resolution_map",
                "zone": "vault_managed_linkage",
            },
            {
                "namespace": "iceberg.gold",
                "name": "gold.cep_security_incidents",
                "zone": "tokenized_soc_incidents",
                "records": summary.incidents_active + summary.incidents_retracted,
            },
            {
                "namespace": "iceberg.gold",
                "name": "gold.entity_risk_scores",
                "zone": "tokenized_soc_risk",
                "records": summary.entity_risk_rows,
            },
            {
                "namespace": "iceberg.gold",
                "name": "gold.privacy_safe_aggregates",
                "zone": "privacy_safe_k_anon",
                "records": summary.privacy_safe_buckets,
            },
            {
                "namespace": "iceberg.quality",
                "name": "quality.dq_results",
                "zone": "governance_quality",
                "records": summary.dq_checks_total,
            },
        ],
        "edges": [
            {"from": RAW_TOPIC, "to": "bronze.raw_security_evidence", "transform": "avro_v2_validate_dedup"},
            {"from": RAW_TOPIC, "to": "bronze.quarantine_dlq", "transform": "dlq_poison_quarantine"},
            {"from": "bronze.raw_security_evidence", "to": "silver.tokenized_security_events", "transform": "hmac_sha256_masking"},
            {"from": "bronze.raw_security_evidence", "to": "silver.identity_resolution_map", "transform": "nat_safe_identity_resolution"},
            {"from": "silver.tokenized_security_events", "to": "gold.cep_security_incidents", "transform": "event_time_cep_interval_join"},
            {"from": "gold.cep_security_incidents", "to": "gold.entity_risk_scores", "transform": "severity_weighted_risk_scoring"},
            {"from": "silver.tokenized_security_events", "to": "gold.privacy_safe_aggregates", "transform": "k_anonymity_aggregation_k5"},
        ],
    }
    config.lineage_file_path.write_text(json.dumps(lineage, indent=2, sort_keys=True), encoding="utf-8")
    return lineage


def run_end_to_end_pipeline(
    config: PlatformConfig,
    *,
    seed: int = 42,
    total_events: int = 3000,
    base_time_ms: int = 1_795_500_000_000,
    nat_aware: bool = True,
    clock_skew_retraction_enabled: bool = True,
    reset_wal: bool = True,
    replay_only: bool = False,
    batch_override: GeneratedBatch | None = None,
) -> PipelineRunSummary:
    """Execute full deterministic pipeline (or replay from durable WAL) into Apache Iceberg V2."""
    t0 = time.perf_counter()
    config.ensure_directories()
    run_id = f"run_{seed}_{uuid.uuid4().hex[:8]}"
    trace_id = uuid.uuid4().hex
    tracer = LocalSpanTracer(config.traces_file_path)
    broker = DurableWalBroker(config.wal_dir)
    vault = PrivacyVault(config.hmac_master_key, config.key_version, config.vault_file_path)
    lakehouse = PrivacyLakehouse(config)

    ground_truth: dict[str, dict[str, Any]] = {}
    gdpr_emails: list[str] = []

    with tracer.start_span(
        "pipeline.run",
        trace_id=trace_id,
        attributes={"run_id": run_id, "seed": seed, "replay_only": replay_only},
    ):
        # Step 1: Generate & durably publish to WAL (unless replaying existing WAL)
        if not replay_only:
            with tracer.start_span("ingestion.generate_and_publish", trace_id=trace_id):
                batch = batch_override or generate_security_telemetry(
                    seed=seed,
                    total_events=total_events,
                    base_time_ms=base_time_ms,
                )
                ground_truth = batch.ground_truth_attacks
                gdpr_emails = batch.gdpr_deletion_emails
                if reset_wal:
                    broker.reset()
                broker.publish_batch(RAW_TOPIC, batch.raw_records)
        else:
            # Load previous ground truth metadata if present
            if config.metadata_file_path.exists():
                prev_meta = json.loads(config.metadata_file_path.read_text(encoding="utf-8"))
                ground_truth = prev_meta.get("ground_truth_attacks", {})
                gdpr_emails = prev_meta.get("gdpr_deletion_emails", [])

        # Step 2: Consume from WAL from offset 0 (deterministic idempotent processing)
        with tracer.start_span("processing.wal_consume_validate", trace_id=trace_id):
            envelopes = broker.read_from_offset(RAW_TOPIC, start_offset=0)
            raw_payloads = [env.payload for env in envelopes]
            valid_events, dlq_rows = validate_and_split_events(raw_payloads)
            if dlq_rows:
                broker.publish_batch(DLQ_TOPIC, dlq_rows)
            broker.commit_offset(CONSUMER_GROUP, RAW_TOPIC, len(envelopes))

        # Step 3: Identity resolution, cryptographic tokenization & streaming CEP correlation
        with tracer.start_span(
            "processing.identity_tokenize_cep",
            trace_id=trace_id,
            attributes={"valid_events": len(valid_events), "nat_aware": nat_aware},
        ):
            resolver = IdentityResolver(vault)
            cep = StreamingCepEngine(
                CepConfig(
                    nat_aware=nat_aware,
                    clock_skew_retraction_enabled=clock_skew_retraction_enabled,
                )
            )
            unique_raw_pairs: list[tuple[SecurityEvent, str]] = []
            unique_tokenized: list[TokenizedSecurityEvent] = []

            # Sort by ingest_time_ms (as delivered from broker), let CEP handle event-time order/lateness
            for ev in valid_events:
                principal_token = resolver.resolve(ev)
                tokenized = vault.tokenize_event(ev, principal_token)
                accepted = cep.process_event(ev, tokenized)
                if accepted:
                    unique_raw_pairs.append((ev, principal_token))
                    unique_tokenized.append(tokenized)

            vault.save()
            incidents = cep.get_incidents()
            entity_risk = cep.compute_entity_risk_scores(now_ms=base_time_ms + 3_600_000)
            privacy_aggs, suppressed_buckets = build_privacy_safe_aggregates(
                unique_tokenized, k_threshold=config.k_anonymity_threshold
            )
            cep_metrics = cep.evaluate_precision_recall(ground_truth)

        # Step 4: Persist into Apache Iceberg V2 privacy-separated zones
        with tracer.start_span("storage.iceberg_v2_commit", trace_id=trace_id):
            lakehouse.write_raw_evidence(unique_raw_pairs, mode="overwrite")
            lakehouse.overwrite_rows("bronze.quarantine_dlq", dlq_rows)
            lakehouse.write_tokenized_events(unique_tokenized, mode="overwrite")
            lakehouse.overwrite_rows(
                "silver.identity_resolution_map", resolver.export_identity_map_rows()
            )
            lakehouse.write_incidents(incidents)
            lakehouse.write_entity_risk(entity_risk)
            lakehouse.write_privacy_aggregates(privacy_aggs)

        # Step 5: Data quality & privacy compliance gate
        with tracer.start_span("quality.dq_gate", trace_id=trace_id):
            silver_rows = [ev.model_dump() for ev in unique_tokenized]
            inc_rows = lakehouse.read_rows("gold.cep_security_incidents")
            agg_rows = [a.model_dump() for a in privacy_aggs]
            dq_results = run_data_quality_gate(
                run_id=run_id,
                wal_ingested=len(envelopes),
                valid_count=len(valid_events),
                dlq_count=len(dlq_rows),
                deduplicated_count=cep.metrics.events_deduplicated,
                silver_rows=silver_rows,
                incident_rows=inc_rows,
                aggregate_rows=agg_rows,
                k_threshold=config.k_anonymity_threshold,
            )
            lakehouse.write_dq_results(dq_results, append=False)

        active_inc_count = sum(1 for i in incidents if i.status.value != "RETRACTED")
        retracted_inc_count = sum(1 for i in incidents if i.status.value == "RETRACTED")
        wall_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        summary = PipelineRunSummary(
            run_id=run_id,
            seed=seed,
            events_generated=len(envelopes),
            events_ingested_wal=len(envelopes),
            events_quarantined_dlq=len(dlq_rows),
            events_deduplicated=cep.metrics.events_deduplicated,
            events_tokenized_silver=len(unique_tokenized),
            incidents_active=active_inc_count,
            incidents_retracted=retracted_inc_count,
            entity_risk_rows=len(entity_risk),
            privacy_safe_buckets=len(privacy_aggs),
            privacy_suppressed_buckets=suppressed_buckets,
            dq_checks_passed=sum(1 for d in dq_results if d.passed),
            dq_checks_total=len(dq_results),
            cep_metrics=cep_metrics,
            wall_time_ms=wall_ms,
        )

        # Save run metadata + lineage graph
        _emit_openlineage_graph(config, run_id, summary)
        gdpr_candidate_tokens = [vault.hmac_token("prn", em) for em in gdpr_emails]
        meta = {
            "last_run_id": run_id,
            "last_updated_ms": int(time.time() * 1000),
            "base_time_ms": base_time_ms,
            "seed": seed,
            "summary": summary.model_dump(),
            "ground_truth_attacks": ground_truth,
            "gdpr_deletion_emails": gdpr_emails,
            "gdpr_candidate_tokens": gdpr_candidate_tokens,
        }
        config.metadata_file_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")

        logger.info(
            "Completed end-to-end security telemetry & privacy lakehouse run",
            extra={
                "run_id": run_id,
                "trace_id": trace_id,
                "extra_fields": {
                    "wal_events": len(envelopes),
                    "silver_events": len(unique_tokenized),
                    "dlq": len(dlq_rows),
                    "active_incidents": active_inc_count,
                    "retracted_incidents": retracted_inc_count,
                    "precision": cep_metrics["precision"],
                    "recall": cep_metrics["recall"],
                },
            },
        )
        return summary
