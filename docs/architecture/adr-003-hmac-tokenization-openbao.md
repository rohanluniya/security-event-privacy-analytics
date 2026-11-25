# ADR-003: Keyed HMAC-SHA256 Tokenization & Per-Subject Crypto-Shredding via OpenBao

## Status
Accepted

## Context
Security correlation requires consistent join keys across `auth`, `endpoint`, `dns`, `proxy`, `api_gateway`, and `application` streams, yet privacy regulations (GDPR Article 17) prohibit keeping re-identifiable PII after a subject exercises their right to erasure.

## Decision
Adopt a two-tier cryptographic tokenization design backed by OpenBao 2.7.3 (MPL-2.0 open-source Vault fork) in distributed deployments and `PrivacyVault` in `local_native` mode:
1. **Deterministic Keyed HMAC-SHA256 (`<ns>_<key_version>_<20-hex>`):** Enables exact cross-stream joins in Silver/Gold without storing raw emails, device IDs, or host IPs. Key versions (`v1`, `v2`, ...) allow scheduled key rotation.
2. **Per-Subject Crypto-Shredding Keys (`subject_keys` KV-v2):** Each `principal_token` is assigned a unique `subject_key_id` stored outside the analytics warehouse. On GDPR erasure, `crypto_shred_subject()` permanently destroys the subject salt (`SHREDDED` tombstone) and purges active rows from `bronze.raw_security_evidence`, `silver.tokenized_security_events`, `silver.identity_resolution_map`, and `gold.entity_risk_scores` while leaving `gold.privacy_safe_aggregates` (`k >= 5`) intact.

## Consequences
- **Positive:** Deterministic joins work at streaming speed with zero external database round-trips per event, while erasure provides both physical row removal and cryptographic unlinkability.
- **Tradeoff:** Local native mode stores dev-only keys on disk (`.local_data/restricted_vault/subject_keys.json`); production deployments MUST use OpenBao Transit + HSM-backed unseal keys.
