# Platform Requirements, SLOs & Data Contracts

## 1. Functional Requirements

1. **Multi-Source Security Telemetry Ingestion:** Deterministically ingest 6 telemetry streams (`auth`, `endpoint`, `dns`, `proxy`, `api_gateway`, `application`) validated against Avro v1/v2 contracts (`schemas/avro/security_event_v1.avsc`, `security_event_v2.avsc`) into a durable append-only WAL/Kafka broker with DLQ quarantine for malformed payloads.
2. **Real-Time Streaming CEP & Interval Joins:** Detect five attack classes (`cred_stuffing`, `impossible_travel`, `stolen_token_misuse`, `lateral_movement`, `anomalous_access_burst`) under event-time watermarks, allowed lateness, deduplication, rule versioning (`@v1`, `@v2`), late-event retractions, and analyst disposition (`NEW -> TRIAGING -> CONFIRMED_TP / FALSE_POSITIVE / RETRACTED`).
3. **NAT-Safe Identity Resolution:** Map `actor_email`, `token_id`, `session_id`, and `device_id` to a canonical pseudonymous `principal_token` while prohibiting conflation across shared corporate NAT/VPN egress IPs.
4. **Privacy-Preserving Lakehouse & Tokenization:** Separate restricted raw PII (`bronze.raw_security_evidence`, 7-day TTL) from tokenized analytics (`silver.tokenized_security_events`, 90-day TTL) and k-anonymous aggregates (`gold.privacy_safe_aggregates`, `k >= 5`). Link incidents to raw evidence solely via immutable SHA-256 `evidence_ref` digests.
5. **ABAC/RBAC & GDPR Compliance:** Enforce default-deny OPA Rego policies across four roles (`analyst_privacy_safe`, `soc_responder`, `ir_lead_raw_evidence`, `privacy_officer`), log every access denial and break-glass read immutably, enforce retention TTL windows, and execute GDPR Article 17 crypto-shredding + subject row purges.

## 2. Service-Level Objectives (SLOs)

| Dimension | Target SLO | Measured (`local_native`, stress profile) |
| :--- | :--- | :--- |
| CEP Per-Event Processing Latency (p95) | `< 1.0 ms` | `0.004 ms` |
| Event-to-Alert Detection Delay (p95) | `< 5,000 ms` | `300.0 ms` |
| Synthetic Attack Recall (5 rule classes) | `>= 98%` | `100.0%` (`40/40`) |
| Corporate NAT & Clock-Skew False Positives | `0` | `0` (`precision 100.0%`, `4` retracted) |
| Silver/Gold Raw PII Leak Count | `0` | `0` (verified by DQ gate & Hypothesis) |
| k-Anonymity Bucket Floor | `>= 5` distinct principals | `min k = 6` (`27` small buckets suppressed) |
| Control Plane Health Availability | HTTP `200` with freshness metadata | Verified at `http://127.0.0.1:8080/health` |

## 3. Data Contract & Storage Grain Summary

| Table | Privacy Zone | Grain | Primary Key | Partition | Retention |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `bronze.raw_security_evidence` | Restricted Raw PII | 1 row per unique valid event | `event_id` | `event_date` | `7 days` |
| `bronze.quarantine_dlq` | Restricted Quarantine | 1 row per invalid poison payload | `dlq_id` | Unpartitioned | `14 days` |
| `silver.tokenized_security_events` | Tokenized Analytics | 1 row per deduplicated event | `event_id` | `event_date` | `90 days` |
| `silver.identity_resolution_map` | Vault-Managed Linkage | 1 row per `(principal, alias_type, alias)` | Composite | Unpartitioned | Crypto-shredded on GDPR |
| `gold.cep_security_incidents` | Tokenized SOC | 1 row per deduplicated incident | `incident_id` | Unpartitioned | `365 days` |
| `gold.entity_risk_scores` | Tokenized SOC | 1 row per `principal_token` | `principal_token` | Unpartitioned | Rolling |
| `gold.privacy_safe_aggregates` | Privacy-Safe (`k >= 5`) | 1 row per `(date, stream, country, action)` | Composite | Unpartitioned | Indefinite (non-PII) |
| `gold.retention_and_erasure_audit` | Immutable Governance | 1 row per audited access/erasure/sweep | `audit_id` | Unpartitioned | `7 years` (compliance) |
| `quality.dq_results` | Governance Quality | 1 row per `(run_id, check_name)` | Composite | Unpartitioned | `365 days` |
