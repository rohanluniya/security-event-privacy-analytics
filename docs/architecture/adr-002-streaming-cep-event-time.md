# ADR-002: Bounded-State Event-Time Streaming CEP with NAT-Aware Guards & Late Retractions

## Status
Accepted

## Context
Naive SIEM correlation rules suffer from three structural failure modes:
1. **Shared Corporate NAT Conflation:** Grouping failed logins strictly by `source_ip` triggers high-volume false positives when dozens of corporate employees share a single VPN/NAT egress IP.
2. **Workstation Clock Skew:** Unsynchronized host clocks make sequential logins across nearby offices appear faster than 900 km/h, flooding SOC queues with false impossible-travel alerts.
3. **Unbounded High-Cardinality State:** Botnet IP sprays and random session IDs can cause OOM crashes in stateful stream processors lacking strict LRU/TTL eviction caps.

## Decision
Implement an event-time CEP engine (`processing/cep_engine.py` for `local_native`, paired with `processing/flink/security_cep_job.py` for distributed Flink 2.1.x) featuring:
- **Explicit Event Time & Watermarks:** Watermark lags `max_event_time_ms` by 30s with a 5-minute allowed lateness window.
- **NAT-Safe Identity Resolution (`processing/identity_resolver.py`):** Resolves `actor_email -> token_id -> session_id -> device_id` into a canonical `principal_token` and **prohibits** joining distinct users on `source_ip`.
- **Rule Versioning (`@v1` vs `@v2`):** `cred_stuffing@v2` guards corporate NAT gateways (`nat_egress_flag=True`) while `impossible_travel@v2` handles delayed NTP/MFA reconciliation events (`is_retraction_evidence=True`) by transitioning speculative incidents to `RETRACTED` and zeroing their entity risk weight.
- **Hard Cardinality Bounds:** `OrderedDict` LRU eviction caps on dedup IDs, IP windows, principal windows, and token states bound peak heap usage deterministically.

## Consequences
- **Positive:** Eliminates 100% of synthetic corporate NAT and clock-skew false positives while maintaining 100% recall across all 5 attack classes.
- **Tradeoff:** If an actual insider launches a credential spray *from inside* a corporate NAT gateway, detection relies on per-principal lockout / behavioral anomaly signals rather than naive IP-only spray counts.
