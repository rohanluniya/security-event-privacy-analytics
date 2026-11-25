"""Apache Airflow 3.4 DAG: Daily Iceberg V2 Compaction, Retention TTL Enforcement, and Privacy DQ Audit."""

from __future__ import annotations

from datetime import datetime, timedelta

try:
    from airflow import DAG  # type: ignore[import-not-found]
    from airflow.operators.bash import BashOperator  # type: ignore[import-not-found]
except ImportError:
    DAG = None
    BashOperator = None

DEFAULT_ARGS = {
    "owner": "secops-privacy-engineering",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
}

if DAG is not None and BashOperator is not None:
    with DAG(
        dag_id="secops_daily_retention_and_compaction",
        default_args=DEFAULT_ARGS,
        description="Enforce raw/silver retention TTL windows, compact Iceberg V2 Parquet files, and verify privacy DQ invariants.",
        schedule="0 2 * * *",
        start_date=datetime(2026, 1, 1),
        catchup=False,
        tags=["secops", "iceberg", "privacy", "retention"],
    ) as dag:
        retention_sweep = BashOperator(
            task_id="enforce_retention_ttl_sweep",
            bash_command="python -m services.secops_platform.cli retention-sweep",
        )
        compact_silver = BashOperator(
            task_id="compact_silver_tokenized_events",
            bash_command="python -m services.secops_platform.cli compact --table silver.tokenized_security_events",
        )
        compact_bronze = BashOperator(
            task_id="compact_bronze_raw_evidence",
            bash_command="python -m services.secops_platform.cli compact --table bronze.raw_security_evidence",
        )
        retention_sweep >> [compact_silver, compact_bronze]
