"""Apache Spark 4.1.x Iceberg V2 Maintenance, Retention TTL Purge & GDPR Erasure Job (Distributed Profile)."""

from __future__ import annotations

import argparse


def build_maintenance_sql(
    *,
    catalog: str = "secops",
    raw_cutoff_ms: int,
    silver_cutoff_ms: int,
    erase_principal_token: str | None = None,
) -> list[str]:
    """Build Spark SQL statements for Iceberg V2 compaction, snapshot expiration, retention, and GDPR erasure."""
    statements = [
        # 1. Retention TTL enforcement
        f"DELETE FROM {catalog}.bronze.raw_security_evidence WHERE event_time_ms < {raw_cutoff_ms}",
        f"DELETE FROM {catalog}.silver.tokenized_security_events WHERE event_time_ms < {silver_cutoff_ms}",
        # 2. Data file compaction (binpack) to eliminate small Parquet files
        f"CALL {catalog}.system.rewrite_data_files(table => 'silver.tokenized_security_events', strategy => 'binpack')",
        f"CALL {catalog}.system.rewrite_data_files(table => 'bronze.raw_security_evidence', strategy => 'binpack')",
        # 3. Expire stale snapshots older than retention policy
        f"CALL {catalog}.system.expire_snapshots(table => 'silver.tokenized_security_events', retain_last => 5)",
    ]
    if erase_principal_token:
        safe_tok = erase_principal_token.replace("'", "")
        statements.extend(
            [
                f"DELETE FROM {catalog}.bronze.raw_security_evidence WHERE principal_token = '{safe_tok}'",
                f"DELETE FROM {catalog}.silver.tokenized_security_events WHERE principal_token = '{safe_tok}'",
                f"DELETE FROM {catalog}.silver.identity_resolution_map WHERE principal_token = '{safe_tok}'",
                f"DELETE FROM {catalog}.gold.entity_risk_scores WHERE principal_token = '{safe_tok}'",
            ]
        )
    return statements


def run_spark_maintenance(
    raw_cutoff_ms: int,
    silver_cutoff_ms: int,
    erase_principal_token: str | None = None,
) -> None:
    from pyspark.sql import SparkSession  # type: ignore[import-not-found]

    spark = (
        SparkSession.builder.appName("secops-iceberg-retention-compaction")
        .config("spark.sql.extensions", "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")
        .config("spark.sql.catalog.secops", "org.apache.iceberg.spark.SparkCatalog")
        .config("spark.sql.catalog.secops.type", "rest")
        .config("spark.sql.catalog.secops.uri", "http://lakekeeper:8181/catalog")
        .getOrCreate()
    )
    try:
        for stmt in build_maintenance_sql(
            raw_cutoff_ms=raw_cutoff_ms,
            silver_cutoff_ms=silver_cutoff_ms,
            erase_principal_token=erase_principal_token,
        ):
            spark.sql(stmt)
    finally:
        spark.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-cutoff-ms", type=int, required=True)
    parser.add_argument("--silver-cutoff-ms", type=int, required=True)
    parser.add_argument("--erase-principal-token", type=str, default=None)
    ns = parser.parse_args()
    run_spark_maintenance(ns.raw_cutoff_ms, ns.silver_cutoff_ms, ns.erase_principal_token)
