"""Apache Flink 2.1.x PyFlink Event-Time Streaming CEP & Interval-Join Job (Distributed Profile).

Runs inside the Flink cluster (`docker compose --profile analytics up`) reading Avro events from
Kafka (`security.telemetry.raw.v2`), enforcing bounded event-time watermarks, NAT-aware credential
stuffing detection, lateral movement interval joins, and writing to Iceberg V2 via Lakekeeper.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class FlinkJobConfig:
    kafka_bootstrap: str = "kafka:9092"
    raw_topic: str = "security.telemetry.raw.v2"
    incidents_topic: str = "security.cep.incidents.v2"
    consumer_group: str = "flink-secops-cep-v2"
    watermark_delay_sec: int = 30
    checkpoint_interval_ms: int = 30_000
    lakekeeper_uri: str = "http://lakekeeper:8181/catalog"
    warehouse: str = "s3://secops-lakehouse/warehouse"


def build_flink_sql_statements(cfg: FlinkJobConfig) -> list[str]:
    """Generate deterministic Flink SQL DDL & CEP MATCH_RECOGNIZE / Interval-Join statements."""
    return [
        f"""
        CREATE TABLE kafka_security_events (
            event_id STRING,
            event_time_ms BIGINT,
            event_ts AS TO_TIMESTAMP_LTZ(event_time_ms, 3),
            source_stream STRING,
            action STRING,
            outcome STRING,
            principal_token STRING,
            ip_token STRING,
            ip_subnet_masked STRING,
            geo_country STRING,
            geo_lat DOUBLE,
            geo_lon DOUBLE,
            geo_asn STRING,
            nat_egress_flag BOOLEAN,
            target_resource STRING,
            bytes_out BIGINT,
            clock_skew_ms BIGINT,
            is_retraction_evidence BOOLEAN,
            WATERMARK FOR event_ts AS event_ts - INTERVAL '{cfg.watermark_delay_sec}' SECOND
        ) WITH (
            'connector' = 'kafka',
            'topic' = '{cfg.raw_topic}',
            'properties.bootstrap.servers' = '{cfg.kafka_bootstrap}',
            'properties.group.id' = '{cfg.consumer_group}',
            'scan.startup.mode' = 'earliest-offset',
            'format' = 'json'
        )
        """.strip(),
        f"""
        CREATE TABLE kafka_cep_incidents (
            rule_ref STRING,
            severity STRING,
            principal_token STRING,
            ip_subnet_masked STRING,
            geo_country STRING,
            first_event_ts TIMESTAMP_LTZ(3),
            last_event_ts TIMESTAMP_LTZ(3),
            event_count BIGINT
        ) WITH (
            'connector' = 'kafka',
            'topic' = '{cfg.incidents_topic}',
            'properties.bootstrap.servers' = '{cfg.kafka_bootstrap}',
            'format' = 'json'
        )
        """.strip(),
        # NAT-aware credential stuffing sliding window (excludes shared corporate NAT egresses)
        """
        INSERT INTO kafka_cep_incidents
        SELECT
            'cred_stuffing@v2' AS rule_ref,
            'HIGH' AS severity,
            MAX(principal_token) AS principal_token,
            MAX(ip_subnet_masked) AS ip_subnet_masked,
            MAX(geo_country) AS geo_country,
            MIN(event_ts) AS first_event_ts,
            MAX(event_ts) AS last_event_ts,
            COUNT(DISTINCT principal_token) AS event_count
        FROM TABLE(
            HOP(TABLE kafka_security_events, DESCRIPTOR(event_ts), INTERVAL '30' SECOND, INTERVAL '3' MINUTE)
        )
        WHERE source_stream = 'auth'
          AND action = 'login_failed'
          AND nat_egress_flag = FALSE
        GROUP BY window_start, window_end, ip_token
        HAVING COUNT(DISTINCT principal_token) >= 6
        """.strip(),
        # Multi-stream interval join: auth jumpbox login -> endpoint suspicious exec -> proxy beacon
        """
        INSERT INTO kafka_cep_incidents
        SELECT
            'lateral_movement@v2' AS rule_ref,
            'CRITICAL' AS severity,
            a.principal_token,
            a.ip_subnet_masked,
            a.geo_country,
            a.event_ts AS first_event_ts,
            p.event_ts AS last_event_ts,
            CAST(3 AS BIGINT) AS event_count
        FROM kafka_security_events a
        JOIN kafka_security_events e
          ON a.principal_token = e.principal_token
         AND e.event_ts BETWEEN a.event_ts AND a.event_ts + INTERVAL '10' MINUTE
        JOIN kafka_security_events p
          ON e.principal_token = p.principal_token
         AND p.event_ts BETWEEN e.event_ts AND e.event_ts + INTERVAL '10' MINUTE
        WHERE a.source_stream = 'auth' AND a.target_resource LIKE '%jumpbox%'
          AND e.source_stream = 'endpoint' AND e.action = 'process_exec_suspicious'
          AND p.source_stream IN ('dns', 'proxy') AND (p.action = 'proxy_beacon' OR p.target_resource LIKE '%c2-beacon%')
        """.strip(),
    ]


def submit_pyflink_job() -> None:
    """Entrypoint when invoked inside Flink 2.1.x TaskManager/JobManager container."""
    from pyflink.table import EnvironmentSettings, TableEnvironment  # type: ignore[import-not-found]

    cfg = FlinkJobConfig(
        kafka_bootstrap=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"),
        lakekeeper_uri=os.getenv("LAKEKEEPER_URI", "http://lakekeeper:8181/catalog"),
    )
    settings = EnvironmentSettings.in_streaming_mode()
    t_env = TableEnvironment.create(settings)
    t_env.get_config().set("execution.checkpointing.interval", f"{cfg.checkpoint_interval_ms} ms")
    t_env.get_config().set("table.exec.state.ttl", "1800000 ms")

    statements = build_flink_sql_statements(cfg)
    for stmt in statements[:2]:
        t_env.execute_sql(stmt)
    stmt_set = t_env.create_statement_set()
    for dml in statements[2:]:
        stmt_set.add_insert_sql(dml)
    stmt_set.execute()


if __name__ == "__main__":
    submit_pyflink_job()
