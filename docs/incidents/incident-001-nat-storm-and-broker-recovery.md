# Controlled Failure Incident Report: Corporate NAT Login Storm & Mid-Stream WAL Recovery

## Summary
During automated fault-injection testing (`tests/chaos/test_chaos_drills.py`, Drills 01, 02, and 06), the platform was subjected to three compound adversarial conditions: (1) a shared corporate NAT authentication failure storm concurrent with real credential stuffing, (2) a -3 hour host clock skew creating false impossible-travel velocity, and (3) a mid-stream consumer crash with derived Silver/Gold state loss.

## Observed Behavior & Recovery Evidence (`results/chaos/chaos_results.json`)

1. **Corporate NAT Storm (`drill_01`):**
   - **Baseline (`v1` NAT-naive):** Produced **4 false positives** (`precision 83.3%`) by attributing normal corporate SSO password-rotation retries behind `198.51.100.10` and `203.0.113.25` to credential stuffing.
   - **Production (`v2` NAT-aware):** Produced **0 false positives** (`precision 100.0%`, `recall 100.0%`), isolating all legitimate external credential-stuffing campaigns cleanly.
2. **Clock-Skew Retraction (`drill_02`):**
   - Speculative impossible-travel incidents fired initially on skewed `GB -> DE` login timestamps. When late NTP/MFA reconciliation events arrived within allowed lateness, **2 incidents transitioned to `RETRACTED`** with explicit audit reasons and their entity risk scores dropped to `0.0`.
3. **Consumer Crash & WAL Replay (`drill_06`):**
   - After rewinding the consumer offset to `711 / 1,422` and wiping `silver.tokenized_security_events` and `gold.cep_security_incidents` to `0` rows, replaying from the durable WAL restored **`1,364 / 1,364` silver rows** and **100% identical incident IDs** with zero duplicate inflation.

## Follow-Up Actions
- Keep `nat_egress_flag` enriched upstream from authoritative corporate egress CIDR inventories.
- Maintain Prometheus alert `UnauthorizedRawEvidenceSpike` and scheduled Iceberg compaction after high-volume recovery replays.
