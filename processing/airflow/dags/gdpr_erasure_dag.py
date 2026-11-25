"""Apache Airflow 3.4 DAG: Event-Driven GDPR Article 17 Crypto-Shredding & Subject Erasure Verification."""

from __future__ import annotations

from datetime import datetime, timedelta

try:
    from airflow import DAG  # type: ignore[import-not-found]
    from airflow.operators.bash import BashOperator  # type: ignore[import-not-found]
except ImportError:
    DAG = None
    BashOperator = None

DEFAULT_ARGS = {
    "owner": "privacy-officer-automation",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=2),
}

if DAG is not None and BashOperator is not None:
    with DAG(
        dag_id="secops_gdpr_article17_erasure",
        default_args=DEFAULT_ARGS,
        description="Execute OpenBao crypto-shredding and Iceberg V2 subject row purge for parameterized principal_token.",
        schedule=None,
        start_date=datetime(2026, 1, 1),
        catchup=False,
        tags=["gdpr", "crypto-shredding", "privacy-officer"],
    ) as dag:
        erase_subject = BashOperator(
            task_id="crypto_shred_and_purge_subject",
            bash_command=(
                "python -m services.secops_platform.cli erase-subject "
                "--subject-token '{{ dag_run.conf.get(\"principal_token\", \"\") }}' "
                "--justification '{{ dag_run.conf.get(\"ticket_id\", \"GDPR-TICKET-AUTO\") }}'"
            ),
        )
        compact_post_erasure = BashOperator(
            task_id="compact_erased_tables",
            bash_command="python -m services.secops_platform.cli compact --table silver.tokenized_security_events",
        )
        erase_subject >> compact_post_erasure
