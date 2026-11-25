# ADR-001: Apache Iceberg V2 Lakehouse with Strict Privacy Zone Separation

## Status
Accepted

## Context
Security analytics requires preserving raw forensic indicators (client IP addresses, user emails, device hardware IDs) for active Incident Response (IR) investigations while simultaneously enabling SOC triage, long-term trend analytics, and GDPR Article 17 right-to-erasure without exposing raw PII to general analysts.

## Decision
Partition the Apache Iceberg V2 lakehouse into two physically and policy-isolated zones:
1. **Restricted Raw Evidence Zone (`bronze.raw_security_evidence`, `bronze.quarantine_dlq`):**
   - Partitioned by `event_date`, Zstandard Parquet compression, strict **7-day retention TTL**.
   - Directly inaccessible to `analyst_privacy_safe`, `soc_responder`, and `privacy_officer`.
   - Accessible exclusively to `ir_lead_raw_evidence` with a mandatory `X-Justification` header (`>= 12 chars`), generating an immutable audit entry per read.
2. **Tokenized & Privacy-Safe Analytics Zone (`silver.*`, `gold.*`):**
   - `silver.tokenized_security_events` (90-day TTL): keyed HMAC-SHA256 tokens, masked emails (`a***h@a***.example`), `/24` IP subnets, and coarsened coordinates (`0.1°`).
   - `gold.cep_security_incidents`: links back to raw bronze rows solely via immutable SHA-256 `evidence_ref` digests.
   - `gold.privacy_safe_aggregates`: strictly enforces `k >= 5` distinct principals per emitted bucket; non-PII counts survive GDPR subject erasures.

## Consequences
- **Positive:** Eliminates accidental PII joins in BI/analytics queries; supports atomic Iceberg V2 snapshot time-travel, file compaction, and auditable row-level purges.
- **Tradeoff:** Storing both raw bronze (7d) and tokenized silver (90d) adds short-term storage overhead (~15% during the 7-day overlap window) and requires compaction after GDPR erasures or retention deletes.
