# Live Interactive Demo Script (5-Minute Walkthrough)

## 1. Start the Platform (Zero-Docker One Command)
```bash
./scripts/run_portable.sh
```
Open `http://127.0.0.1:8080/` in a browser and verify `http://127.0.0.1:8080/health` returns `200 OK`.

## 2. Inspect Correlated CEP Incidents & Clock-Skew Retractions (`soc_responder`)
1. Observe the top KPI row: **20 Active CEP Incidents**, **2 Retracted (clock-skew)**, **100.0% / 100.0% Precision/Recall**, **7/7 DQ Gate PASS**, **30 DLQ Quarantined**.
2. Locate an `impossible_travel@v2` row with purple `RETRACTED` badge — triggered speculatively on a skewed laptop clock and retracted automatically when the late NTP/MFA event arrived.
3. Click **TP** on any `NEW` incident to record a live analyst disposition (`POST /v1/incidents/{id}/disposition`).

## 3. Prove Live RBAC / ABAC Policy Enforcement (`HTTP 403` vs `200 Audited`)
1. Stay on role **`soc_responder`** and click **Query Raw Evidence** -> observe real **`HTTP 403`** denial logged to the immutable audit ledger.
2. Switch the top Role dropdown to **`analyst_privacy_safe`** -> observe that **Correlated Incidents** and **Entity Risk** both display **`HTTP 403`**, while **Privacy-Safe k-Anonymous Aggregates (`k >= 5`)** remain accessible.
3. Switch to **`ir_lead_raw_evidence`**:
   - Clear the justification box and click **Query Raw Evidence** -> **`HTTP 403`** (`X-Justification >= 12 characters required`).
   - Restore the justification (`INC-2026-0091 lateral movement forensic review`) and click **Query Raw Evidence** -> **`HTTP 200`** returning raw IP/email from `bronze.raw_security_evidence` along with an immutable `audit_id`.
   - Click **GDPR Erase Subject** as `ir_lead_raw_evidence` -> **`HTTP 403`** (separation of duties).

## 4. Execute GDPR Article 17 Crypto-Shredding & Retention TTL Sweep (`privacy_officer`)
1. Switch role to **`privacy_officer`**.
2. Click **GDPR Erase Subject** -> returns `crypto_shredded: true`, `remaining_raw_rows: 0`, `remaining_tokenized_rows: 0`, while preserving `privacy_safe_aggregates_preserved`.
3. Click **Run Retention Sweep** -> purges all 15 aged (>7-day) raw bronze rows while keeping fresh evidence intact.

## 5. Inspect CLI & Prometheus Observability
```bash
curl -s http://127.0.0.1:8080/metrics | grep -E "secops_(events_ingested|cep_incidents|abac_decisions|privacy_erasures)"
```
