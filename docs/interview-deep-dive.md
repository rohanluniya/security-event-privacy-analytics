# Staff Data & Security Engineering Interview Deep Dive

## Q1: Why not group authentication failures solely by `source_ip` in real-time CEP?
Enterprise users egress through shared corporate VPNs, ZTNA proxies, and office NAT gateways. When an SSO password rotation or IdP hiccup hits an office of 40 employees sharing `198.51.100.10`, a naive IP-grouped rule sees 14+ distinct users failing login within 60 seconds and pages the SOC for credential stuffing. In our measured ablation (`results/benchmarks/nat_ablation.csv`), the `v1` NAT-naive rule generated 8 false positives (`16.3%` FP rate) while `v2` NAT-aware correlation achieved `0` false positives at `100.0%` recall. Crucially, `IdentityResolver` never binds `source_ip` into the identity alias graph so endpoint and DNS events behind the same NAT never cross-contaminate employee identities.

## Q2: How do you handle event-time clock skew without delaying real-time alerts for hours?
Holding every `impossible_travel` alert for 3 hours waiting for possible NTP drift would violate SOC detection latency SLOs. Instead, `impossible_travel@v2` emits a speculative alert immediately (measured p95 detection delay: `300 ms`) tagged with an immutable SHA-256 `evidence_ref`. When a delayed authoritative NTP/MFA reconciliation event (`is_retraction_evidence=True`) arrives within allowed lateness, the CEP engine transitions the incident state to `RETRACTED`, records the retraction reason, updates `evidence_ref`, and zeros that incident's weight in `gold.entity_risk_scores`.

## Q3: How does GDPR Article 17 erasure work on immutable Parquet/Iceberg lakehouses?
Two mechanisms work together:
1. **Crypto-shredding:** Per-subject key salts live in an isolated vault (`OpenBao 2.7.3` KV-v2 in distributed mode; `PrivacyVault` locally), never in Parquet. Destroying the subject key breaks cryptographic linkability immediately.
2. **Iceberg V2 Atomic Rewrite & Compaction:** `bronze.raw_security_evidence`, `silver.tokenized_security_events`, `silver.identity_resolution_map`, and `gold.entity_risk_scores` atomically remove all rows matching `principal_token`, followed by snapshot expiration (`expire_snapshots`) so historical Parquet files containing deleted PII age out of object storage. Non-PII `gold.privacy_safe_aggregates` (`k >= 5`) remain intact for year-over-year security trend reporting.

## Q4: How do you prevent OOM crashes during high-cardinality DDoS or credential-spray attacks?
Every stateful map in `StreamingCepEngine` (`seen_event_ids`, `ip_auth_failures`, `principal_last_auth`, `token_usage_state`, `lateral_state`, `burst_windows`) is backed by a bounded `OrderedDict` LRU structure with explicit cardinality caps (`max_dedup_ids`, `max_ip_keys`, `max_principal_keys`, `max_token_keys`). In our scaling benchmark, increasing event volume 13.8x (`1,545 -> 21,363`) plateaued peak state cleanly at `3,301` entries beneath the `5,500` eviction ceiling at `43.2k ev/s`. In distributed Flink 2.1, RocksDB state backend + `table.exec.state.ttl = 30m` enforces the same bound across TaskManagers.

## Q5: Why enforce separation of duties between Incident Response and Privacy Officers?
If a single privileged role can both inspect raw PII forensic evidence and execute subject erasure or retention sweeps, a compromised admin credential could exfiltrate PII and erase its own evidence trail. `infra/opa/security_abac.rego` explicitly forbids `ir_lead_raw_evidence` from calling `/v1/privacy/erase/*` or `/v1/privacy/retention-sweep` (`403`) and forbids `privacy_officer` from reading `/v1/evidence/raw/*` (`403`).
