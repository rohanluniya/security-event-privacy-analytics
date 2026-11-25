# Known Limitations & Explicit Scope Disclosures

1. **Host Container Runtime (`local_native` vs Distributed Execution):**
   - The verification workstation (Apple M4 Pro, macOS `Darwin 24.6.0`) does not have Docker, Podman, or a host JVM installed. Consequently, all runtime benchmarks, chaos drills, API tests, and screenshots were executed against the real `local_native` Python 3.12 runtime (`WAL broker + StreamingCepEngine + PrivacyVault + PyIceberg 0.12.0 + DuckDB 2.0.0 + Embedded OPA-Parity ABAC + FastAPI`).
   - Distributed artifacts (`docker-compose.yml`, `processing/flink/security_cep_job.py`, `processing/spark/retention_and_compaction.py`, `processing/airflow/dags/`, `infra/opa/security_abac.rego`, `infra/openbao/config.hcl`, `infra/kubernetes/`) are pinned, syntax-checked, and SQL-builder unit-tested, but require a Docker/Kubernetes host for live multi-container execution.
2. **Lineage & Tracing Export in `local_native` Mode:**
   - Automatic Marquez / OTLP Collector push requires running the `observability` Docker Compose profile. In `local_native` mode, OpenLineage-formatted lineage is exported deterministically to `.local_data/lineage/lineage_events.json` (served at `/v1/lineage`) and OpenTelemetry-compatible spans are written to `.local_data/traces/spans.jsonl` (served at `/v1/traces`).
3. **Dev/Demo Auth & Local Vault Keys:**
   - The local API uses constant-time `X-API-Key` binding configured via `.env.example` and stores subject salts in `.local_data/restricted_vault/subject_keys.json`. Production deployments MUST integrate OIDC/JWT identity tokens, live OPA sidecars, and HSM-backed OpenBao 2.7.3 Transit keys.
4. **Synthetic Telemetry Only:**
   - All security events and attack campaigns are deterministically synthesized via `ingestion/generator.py` (no customer PII, no external datasets, zero pretrained ML weights downloaded). Real production rules require continuous threshold calibration against live SIEM false-positive feedback loops.
5. **Iceberg Snapshot Physical File Cleanup After GDPR Erasure:**
   - `erase_subject_gdpr()` atomically rewrites active Iceberg snapshots so all current queries return `0` rows for the erased subject, and shreds the subject salt in the vault. Physical removal of prior pre-erasure Parquet files from storage requires running Spark `expire_snapshots` + `remove_orphan_files` (`processing/spark/retention_and_compaction.py`).
