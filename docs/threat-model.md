# Threat Model (STRIDE) & Dev-vs-Production Security Boundaries

## 1. STRIDE Threat Matrix

| Threat Category | Attack Surface / Scenario | Implemented Mitigation | Residual Risk / Prod Hardening |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Forged `X-Role` header or missing credentials attempting raw PII read | Role derived exclusively via constant-time `hmac.compare_digest` key lookup; missing/bad `X-API-Key` returns `401` and logs `ABAC_ACCESS_DENIED` | Replace static dev API keys with OIDC/JWT bearer tokens verified against IdP JWKS + mTLS service mesh |
| **Tampering** | Malicious insider alters incident evidence or erases audit history | Immutable SHA-256 `evidence_ref` computed over sorted event IDs; separation of duties blocks `ir_lead_raw_evidence` from erasure/retention (`403`) | Store `gold.retention_and_erasure_audit` in WORM / Object Lock S3 bucket with cryptographic log chaining |
| **Repudiation** | IR responder views raw PII without leaving a forensic trace | Mandatory `X-Justification` (`>= 12 chars`) enforced by OPA Rego + embedded engine; every read appends `BREAK_GLASS_RAW_EVIDENCE_READ` with actor, role, timestamp, and justification | Bind justification to live ticketing system (Jira/ServiceNow) webhook validation |
| **Information Disclosure** | BI analyst joins raw emails/IPs or singles out rare individuals in aggregates | Strict physical zone separation (`bronze` vs `silver`/`gold`); HMAC-SHA256 tokenization + `/24` IP masking; automated PII leak scanner DQ check; `k >= 5` bucket suppression; log redaction filter | Add differential privacy noise calibration for repeated overlapping aggregate queries |
| **Denial of Service** | High-cardinality botnet IP spray exhausts CEP state memory | Hard `OrderedDict` LRU eviction caps across all 6 CEP state maps; RocksDB state backend + 30m TTL in Flink profile | Add Kafka per-source rate quotas and Flink backpressure autoscaling |
| **Elevation of Privilege** | Single compromised account both reads raw PII and invokes GDPR erasure | Separation of duties in `infra/opa/security_abac.rego`: `ir_lead_raw_evidence` cannot call `/v1/privacy/*`; `privacy_officer` cannot call `/v1/evidence/raw/*` | Require dual-control approval (two-person integrity) for bulk GDPR erasures |

## 2. Explicit Dev vs. Production Limitations

1. **Key Management:** `local_native` mode persists dev subject salts in `.local_data/restricted_vault/subject_keys.json` and uses an environment-configured dev HMAC key (`.env.example`). Production deployments MUST run **OpenBao 2.7.3** (`infra/openbao/config.hcl`) with HSM/KMS auto-unseal and automated 30-day Transit key rotation.
2. **Authentication:** The interactive dashboard includes a dev-only role switcher bound to non-secret demo keys so reviewers can test live `403` policy enforcement without setting up an external IdP. Production deployments MUST remove the client-side key map and enforce OIDC SSO + signed JWTs.
3. **File-System Storage Isolation:** On a single laptop (`local_native`), Bronze and Silver Parquet directories live under `.local_data/iceberg_warehouse/`. In production, `bronze.*` and `silver.*`/`gold.*` MUST map to separate S3/RustFS buckets with distinct IAM/Lakekeeper policies so no compute worker running analyst queries holds read credentials to the Bronze bucket.
