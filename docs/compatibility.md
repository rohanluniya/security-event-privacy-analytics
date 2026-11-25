# Component Compatibility, Pinning & License Matrix

All runtime libraries and distributed container images are open-source and strictly pinned to explicit versions. Zero pretrained ML model weights are downloaded or redistributed.

## 1. Local Native Runtime (Verified on macOS ARM64 & Linux x86_64)

| Component | Pinned Version | License | Role |
| :--- | :--- | :--- | :--- |
| Python | `3.12.8` | PSF-2.0 | Core runtime (`uv.lock` locked) |
| `pyiceberg[sql-sqlite,pyiceberg-core]` | `0.12.0` (`pyiceberg-core 0.10.1`) | Apache-2.0 | Apache Iceberg V2 catalog & Parquet table engine |
| `duckdb` | `2.0.0` | MIT | Analytical SQL engine over Iceberg Arrow scans |
| `pyarrow` | `25.0.1` | Apache-2.0 | Columnar memory & Parquet I/O |
| `fastavro` | `1.13.1` | MIT | Avro v1/v2 contract validation & binary codecs |
| `fastapi` / `uvicorn` | `0.163.2` / `0.54.0` | MIT / BSD-3-Clause | RBAC/ABAC Control Plane API & SOC Dashboard |
| `prometheus-client` | `0.26.0` | Apache-2.0 | `/metrics` exposition endpoint |
| `hypothesis` / `pytest` | `6.170.15` / `9.2.0` | MPL-2.0 / MIT | Property-based & integration/chaos test suites |
| `matplotlib` | `3.11.2` | PSF-based | Benchmark visualization generation |

## 2. Distributed Container Profile (`docker-compose.yml`)

| Service | Pinned Image Tag | License | Profile(s) | Arch Notes |
| :--- | :--- | :--- | :--- | :--- |
| Apache Kafka | `apache/kafka:4.3.2` | Apache-2.0 | `core`, `full` | ARM64 & AMD64 native |
| Apicurio Registry | `apicurio/apicurio-registry:3.3.5` | Apache-2.0 | `core`, `full` | Avro v1/v2 schema registry |
| Open Policy Agent | `openpolicyagent/opa:1.22.3` | Apache-2.0 | `core`, `full` | Evaluates `infra/opa/security_abac.rego` |
| OpenBao | `openbao/openbao:2.7.3` | MPL-2.0 | `core`, `full` | Community Vault fork for HMAC & crypto-shredding keys |
| PostgreSQL + PostGIS | `imresamu/postgis:17-3.6.1-alpine3.23` | PostgreSQL / GPL-2 (container) | `core`, `analytics`, `full` | Lakekeeper catalog metadata & geo queries |
| RustFS | `rustfs/rustfs:1.0.6` | Apache-2.0 | `core`, `analytics`, `full` | S3-compatible object store for Iceberg warehouse |
| Lakekeeper | `quay.io/lakekeeper/catalog:v0.15.1` | Apache-2.0 | `core`, `analytics`, `full` | Iceberg REST Catalog |
| Apache Flink | `flink:2.1.3-scala_2.12-java17` | Apache-2.0 | `analytics`, `full` | Executes `processing/flink/security_cep_job.py` |
| Apache Spark | `apache/spark:4.1.4-scala2.13-java17-python3-ubuntu` | Apache-2.0 | `analytics`, `full` | Executes `processing/spark/retention_and_compaction.py` |
| OpenSearch | `opensearchproject/opensearch:3.9.0` | Apache-2.0 | `analytics`, `full` | Optional tokenized alert full-text search index |
| Apache Airflow | `apache/airflow:slim-3.4.0-python3.12` | Apache-2.0 | `analytics`, `full` | Orchestrates retention & GDPR erasure DAGs |
| Prometheus | `prom/prometheus:v3.16.0` | Apache-2.0 | `observability`, `full` | Scrapes `/metrics` & evaluates `alerts.yml` |
| Grafana | `grafana/grafana:13.0.14` | AGPL-3.0 (external service) | `observability`, `full` | Dashboards (`grafana_dashboard.json`) |
| Grafana Loki | `grafana/loki:3.6.22` | AGPL-3.0 (external service) | `observability`, `full` | Structured JSON log aggregation |
| OTel Collector | `otel/opentelemetry-collector-contrib:0.166.0-${OTEL_ARCH:-arm64}` | Apache-2.0 | `observability`, `full` | OTLP trace receiver |
| Marquez | `marquezproject/marquez:0.51.1` | Apache-2.0 | `observability`, `full` | Pinned `platform: linux/amd64` (Rosetta/QEMU on ARM64) |

## 3. Host Compatibility Disclosure

- **macOS ARM64 (Apple Silicon) without Docker:** Runs the complete `local_native` vertical slice (`uv` + Python 3.12 + WAL broker + Streaming CEP + PyIceberg V2 + DuckDB + Embedded OPA-Parity ABAC + FastAPI + SOC Dashboard).
- **Linux x86_64 / Docker-enabled macOS:** Supports both `docker-compose.standalone.yml` and full multi-profile `docker-compose.yml` (`core`, `analytics`, `observability`, `full`).
- **Automated License Audit:** `uv run python scripts/check_licenses.py` audits all 61 installed Python packages and writes `results/sbom/license_audit.json`.
