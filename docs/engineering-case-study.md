# Engineering Case Study: Balancing Real-Time Threat Correlation with Privacy-by-Design

## 1. The Core Tension in Modern Security Analytics
Enterprise security platforms face two competing mandates:
- **Detection teams** need sub-second correlation across authentication, endpoint, DNS, proxy, API gateway, and application logs to catch credential stuffing, impossible travel, stolen tokens, and lateral movement before exfiltration completes.
- **Privacy & compliance teams** must restrict raw PII (emails, client IPs, device IDs), prevent re-identification in analytical aggregates, enforce short retention windows on forensic logs, and honor GDPR Article 17 right-to-erasure requests without breaking historical compliance reporting.

## 2. Key Architectural Decisions & Measured Outcomes

1. **NAT-Safe Identity Resolution & Rule Versioning (`v1` vs `v2`):**
   - Naive IP-grouped credential-stuffing rules conflated 28 benign corporate employees behind shared NAT gateways (`198.51.100.10`, `203.0.113.25`), producing **8 false positives** (`precision 83.3%`, `FP rate 16.3%`) at `local`/`stress` scale.
   - Separating identity resolution (`actor_email -> token_id -> session_id -> device_id`, strictly prohibiting `source_ip` as an identity join key) and introducing `cred_stuffing@v2` + `impossible_travel@v2` with late-event clock-skew retractions eliminated all **8 false positives** (`precision 100.0%`, `recall 100.0%`, `4` clock-skewed alerts cleanly retracted).
2. **Physical Privacy Zones & Cryptographic Crypto-Shredding:**
   - Raw PII is confined strictly to `bronze.raw_security_evidence` (7-day TTL). `silver.tokenized_security_events` stores only HMAC-SHA256 tokens, masked emails (`e***3@a***.example`), `/24` IP subnets, and `0.1°` coarsened coordinates.
   - Automated DQ checks (`zero_raw_pii_leak_silver`, `zero_raw_pii_leak_gold_incidents`) and 40+ Hypothesis property tests verify zero raw PII leakage across arbitrary email/IPv4 inputs.
   - Executing GDPR Article 17 erasure shreds the per-subject salt in the vault and purges all subject rows (`0` remaining in bronze, silver, identity map, entity risk) while retaining non-PII `k >= 5` aggregates (`19` buckets preserved in chaos drill 04).
3. **Separation-of-Duties ABAC (`infra/opa/security_abac.rego`):**
   - No single persona holds both forensic raw PII read access and deletion rights. `ir_lead_raw_evidence` can read raw evidence only with an audited `X-Justification` (`>= 12 chars`) and receives HTTP `403` on `/v1/privacy/erase/*`; `privacy_officer` executes erasure and retention sweeps and receives HTTP `403` on `/v1/evidence/raw/*`.
4. **Iceberg V2 Storage Maintenance:**
   - Micro-batch streaming appends fragmented `silver.tokenized_security_events` into 26 small Parquet files (`32.6 ms` median scan). Compacting into 2 partition-aligned files reduced file count by **92.3%** and improved full-scan speed by **7.96x** (`4.1 ms` median).
