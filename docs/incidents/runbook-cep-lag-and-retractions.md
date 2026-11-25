# Operator Runbook: CEP Lag, Retraction Storms, ABAC Denials & Privacy DQ Failures

## 1. Alert: `HighCepDetectionLatencyP95` (> 5,000 ms)
1. Check `/health` freshness and `/metrics` (`secops_cep_detection_delay_ms_bucket`, `secops_cep_state_entries`).
2. Inspect `/v1/traces` for spikes in `processing.identity_tokenize_cep` vs `storage.iceberg_v2_commit`.
3. If `bronze` or `silver` data file count exceeds 50 due to frequent micro-batches, run:
   ```bash
   uv run python -m services.secops_platform.cli compact --table silver.tokenized_security_events
   ```

## 2. Alert: `UnauthorizedRawEvidenceSpike` (>= 5 `DENY` on `raw_evidence_read`)
1. Query the immutable governance ledger as `privacy_officer` or `ir_lead_raw_evidence`:
   ```bash
   curl -s -H "X-API-Key: $SECOPS_KEY_PRIVACY_OFFICER" http://127.0.0.1:8080/v1/audit | jq '.items[:10]'
   ```
2. Inspect `actor_id`, `actor_role`, and `details_json.reason`. Distinguish misconfigured client scripts missing `X-Justification` from unauthorized privilege probing by `analyst_privacy_safe` or `soc_responder`.
3. Rotate compromised role keys immediately via OpenBao and revoke active OIDC sessions.

## 3. Alert: `PrivacyDataQualityCheckFailed`
1. Inspect `/v1/quality` to identify the exact failed check (`zero_raw_pii_leak_silver`, `k_anonymity_threshold_invariant`, or `wal_to_bronze_reconciliation`).
2. If a PII leak check fails, immediately pause downstream dashboard exposure, isolate the offending schema/ingestion parser, roll back the Iceberg snapshot (`tbl.manage_snapshots()`), and replay from the WAL after fixing masking rules.

## 4. Consumer Crash & Deterministic WAL Replay
If a streaming consumer terminates mid-batch or derived Silver/Gold tables become corrupted:
```bash
uv run python -m services.secops_platform.cli replay --seed 42
```
Verify `dq_checks_passed == 7` and confirm zero duplicate `event_id` rows in `silver.tokenized_security_events`.
