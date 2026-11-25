# Capacity Model & Resource Sizing

## 1. Workload Assumptions

- **Single-Host Local Native Baseline (Measured on Apple M4 Pro, 14 cores, 48 GiB RAM):**
  - Pure Streaming CEP + Identity Resolution + HMAC Tokenization: **42,231–44,257 events/sec** single-threaded Python (`0.004 ms` p95 per event).
  - Full E2E WAL + Avro Validation + Iceberg V2 Parquet Commit + 7 DQ Checks: **10,379–12,544 events/sec** at `local`/`stress` scale (`4,553`–`17,861` valid events).
- **Target Distributed Production Profile (Kafka 4.3 + Flink 2.1 + Iceberg V2 on RustFS/S3):**
  - Design target: **50,000 sustained events/sec** (~4.32 billion events/day), peak burst **150,000 events/sec**.
  - Average serialized JSON/Avro event payload: ~450 bytes raw; Zstandard Parquet compressed: ~85 bytes/row.

## 2. Storage Sizing Projection (Derived from Compression Assumptions)

| Layer | Retention | Estimated Daily Volume @ 50k ev/s | Compressed Footprint (Zstd Parquet) |
| :--- | :--- | :--- | :--- |
| `bronze.raw_security_evidence` | 7 days | 4.32B rows/day | ~2.57 TiB total retained |
| `silver.tokenized_security_events` | 90 days | 4.19B unique rows/day (after ~3% dedup) | ~32.0 TiB total retained |
| `gold.cep_security_incidents` | 365 days | ~100k incidents/day | < 20 GiB total retained |
| `gold.privacy_safe_aggregates` | Indefinite | ~50k buckets/day | < 1 GiB/year |

*Note: Production storage figures above are capacity planning estimates based on standard Parquet compression ratios; local measured benchmarks are reported strictly in `docs/benchmarks/benchmark-report.md` and `results/benchmarks/`.*

## 3. Bounded CEP State Memory Budget

The CEP engine bounds memory across six structures (`seen_event_ids`, `ip_auth_failures`, `principal_last_auth`, `token_usage_state`, `lateral_state`, `burst_windows`). Under default caps (`50k` dedup IDs + `10k–20k` entity keys), worst-case local Python heap stays under ~120 MiB. In distributed Flink 2.1 deployments (`docker-compose.yml`), `state.backend.type: rocksdb` spills keyed state to local NVMe with `table.exec.state.ttl = 1800000 ms` (30 minutes).
