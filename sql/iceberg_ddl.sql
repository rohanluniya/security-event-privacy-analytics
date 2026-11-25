-- Apache Iceberg V2 Lakehouse DDL for Real-Time Security Event & Privacy-Preserving Analytics Platform
-- Privacy Zone Architecture:
--   RESTRICTED RAW ZONE:  bronze.raw_security_evidence, bronze.quarantine_dlq (IR Lead break-glass ONLY)
--   TOKENIZED ZONE:       silver.tokenized_security_events, silver.identity_resolution_map
--   SERVING / GOLD ZONE:  gold.cep_security_incidents, gold.entity_risk_scores, gold.privacy_safe_aggregates (k >= 5)
--   GOVERNANCE / AUDIT:   gold.retention_and_erasure_audit, quality.dq_results

CREATE NAMESPACE IF NOT EXISTS bronze;
CREATE NAMESPACE IF NOT EXISTS silver;
CREATE NAMESPACE IF NOT EXISTS gold;
CREATE NAMESPACE IF NOT EXISTS quality;

-- 1. Restricted Raw Evidence Zone (TTL: 7 days; raw PII strictly confined here)
CREATE TABLE IF NOT EXISTS bronze.raw_security_evidence (
  event_id          STRING    NOT NULL,
  principal_token   STRING    NOT NULL,
  event_time_ms     BIGINT    NOT NULL,
  ingest_time_ms    BIGINT    NOT NULL,
  event_date        STRING    NOT NULL,
  source_stream     STRING    NOT NULL,
  action            STRING    NOT NULL,
  outcome           STRING    NOT NULL,
  actor_email       STRING,
  device_id         STRING,
  session_id        STRING,
  token_id          STRING,
  source_ip         STRING    NOT NULL,
  geo_country       STRING    NOT NULL,
  geo_lat           DOUBLE    NOT NULL,
  geo_lon           DOUBLE    NOT NULL,
  geo_asn           STRING    NOT NULL,
  nat_egress_flag   BOOLEAN   NOT NULL,
  target_resource   STRING    NOT NULL,
  bytes_out         BIGINT    NOT NULL,
  evidence_ref      STRING    NOT NULL,
  raw_payload_json  STRING    NOT NULL
)
USING iceberg
PARTITIONED BY (event_date)
TBLPROPERTIES (
  'format-version' = '2',
  'secops.privacy_zone' = 'restricted_raw_pii',
  'secops.retention_days' = '7',
  'write.parquet.compression-codec' = 'zstd'
);

-- 2. Quarantine Dead-Letter Queue (malformed / schema-invalid poison records)
CREATE TABLE IF NOT EXISTS bronze.quarantine_dlq (
  dlq_id            STRING    NOT NULL,
  ingested_at_ms    BIGINT    NOT NULL,
  error_code        STRING    NOT NULL,
  error_reason      STRING    NOT NULL,
  raw_payload_json  STRING    NOT NULL
)
USING iceberg
TBLPROPERTIES (
  'format-version' = '2',
  'secops.privacy_zone' = 'restricted_quarantine',
  'secops.retention_days' = '14'
);

-- 3. Silver Tokenized Security Events (TTL: 90 days; ZERO raw emails or host IPs)
CREATE TABLE IF NOT EXISTS silver.tokenized_security_events (
  event_id               STRING    NOT NULL,
  event_time_ms          BIGINT    NOT NULL,
  ingest_time_ms         BIGINT    NOT NULL,
  event_date             STRING    NOT NULL,
  source_stream          STRING    NOT NULL,
  action                 STRING    NOT NULL,
  outcome                STRING    NOT NULL,
  principal_token        STRING    NOT NULL,
  masked_email           STRING,
  device_token           STRING,
  session_token          STRING,
  token_hash             STRING,
  ip_token               STRING    NOT NULL,
  ip_subnet_masked       STRING    NOT NULL,
  geo_country            STRING    NOT NULL,
  geo_lat_coarse         DOUBLE    NOT NULL,
  geo_lon_coarse         DOUBLE    NOT NULL,
  geo_asn                STRING    NOT NULL,
  nat_egress_flag        BOOLEAN   NOT NULL,
  target_resource        STRING    NOT NULL,
  http_status            INT,
  bytes_out              BIGINT    NOT NULL,
  clock_skew_ms          BIGINT    NOT NULL,
  is_retraction_evidence BOOLEAN   NOT NULL,
  key_version            STRING    NOT NULL,
  evidence_ref           STRING    NOT NULL,
  scenario_label         STRING    NOT NULL,
  attack_id              STRING,
  schema_version         INT       NOT NULL
)
USING iceberg
PARTITIONED BY (event_date)
TBLPROPERTIES (
  'format-version' = '2',
  'secops.privacy_zone' = 'tokenized_analytics',
  'secops.retention_days' = '90',
  'write.parquet.compression-codec' = 'zstd'
);

-- 4. Vault-Managed Identity Resolution Alias Table (crypto-shredded on GDPR Article 17 erasure)
CREATE TABLE IF NOT EXISTS silver.identity_resolution_map (
  principal_token  STRING   NOT NULL,
  alias_type       STRING   NOT NULL,
  alias_token      STRING   NOT NULL,
  subject_key_id   STRING   NOT NULL,
  first_seen_ms    BIGINT   NOT NULL,
  last_seen_ms     BIGINT   NOT NULL,
  key_version      STRING   NOT NULL
)
USING iceberg
TBLPROPERTIES (
  'format-version' = '2',
  'secops.privacy_zone' = 'vault_managed_linkage'
);

-- 5. Gold CEP Correlated Security Incidents (with immutable SHA-256 evidence_ref & disposition)
CREATE TABLE IF NOT EXISTS gold.cep_security_incidents (
  incident_id             STRING   NOT NULL,
  rule_id                 STRING   NOT NULL,
  rule_version            STRING   NOT NULL,
  rule_ref                STRING   NOT NULL,
  severity                STRING   NOT NULL,
  status                  STRING   NOT NULL,
  principal_token         STRING   NOT NULL,
  masked_email            STRING,
  ip_subnet_masked        STRING   NOT NULL,
  geo_country             STRING   NOT NULL,
  first_event_time_ms     BIGINT   NOT NULL,
  last_event_time_ms      BIGINT   NOT NULL,
  detected_at_ms          BIGINT   NOT NULL,
  detection_delay_ms      BIGINT   NOT NULL,
  event_count             INT      NOT NULL,
  evidence_event_ids_json STRING   NOT NULL,
  evidence_ref            STRING   NOT NULL,
  confidence_score        DOUBLE   NOT NULL,
  summary                 STRING   NOT NULL,
  retracted_reason        STRING,
  disposition_by          STRING,
  disposition_note        STRING,
  disposition_at_ms       BIGINT,
  ground_truth_attack_id  STRING
)
USING iceberg
TBLPROPERTIES (
  'format-version' = '2',
  'secops.privacy_zone' = 'tokenized_soc_incidents',
  'secops.retention_days' = '365'
);

-- 6. Gold Entity Risk Scores (pseudonymous principal risk scores)
CREATE TABLE IF NOT EXISTS gold.entity_risk_scores (
  principal_token          STRING   NOT NULL,
  masked_email             STRING,
  risk_score               DOUBLE   NOT NULL,
  risk_tier                STRING   NOT NULL,
  active_incident_count    INT      NOT NULL,
  retracted_incident_count INT      NOT NULL,
  rules_triggered_json     STRING   NOT NULL,
  last_seen_ms             BIGINT   NOT NULL,
  updated_at_ms            BIGINT   NOT NULL
)
USING iceberg
TBLPROPERTIES (
  'format-version' = '2',
  'secops.privacy_zone' = 'tokenized_soc_risk'
);

-- 7. Gold Privacy-Safe Aggregates (strict k-anonymity threshold k >= 5; non-PII)
CREATE TABLE IF NOT EXISTS gold.privacy_safe_aggregates (
  bucket_date               STRING   NOT NULL,
  source_stream             STRING   NOT NULL,
  geo_country               STRING   NOT NULL,
  action                    STRING   NOT NULL,
  event_count               BIGINT   NOT NULL,
  distinct_principals       BIGINT   NOT NULL,
  failure_count             BIGINT   NOT NULL,
  bytes_out_sum             BIGINT   NOT NULL,
  k_anonymity_threshold     INT      NOT NULL,
  suppressed_buckets_merged INT      NOT NULL
)
USING iceberg
TBLPROPERTIES (
  'format-version' = '2',
  'secops.privacy_zone' = 'privacy_safe_k_anon',
  'secops.k_anonymity_threshold' = '5'
);

-- 8. Immutable Retention, Break-Glass Access & GDPR Erasure Audit Trail
CREATE TABLE IF NOT EXISTS gold.retention_and_erasure_audit (
  audit_id         STRING   NOT NULL,
  event_time_ms    BIGINT   NOT NULL,
  action_type      STRING   NOT NULL,
  actor_id         STRING   NOT NULL,
  actor_role       STRING   NOT NULL,
  target_resource  STRING   NOT NULL,
  decision         STRING   NOT NULL,
  justification    STRING,
  details_json     STRING   NOT NULL
)
USING iceberg
TBLPROPERTIES (
  'format-version' = '2',
  'secops.privacy_zone' = 'immutable_governance_audit'
);

-- 9. Automated Data Quality Gate Ledger
CREATE TABLE IF NOT EXISTS quality.dq_results (
  run_id           STRING   NOT NULL,
  checked_at_ms    BIGINT   NOT NULL,
  check_name       STRING   NOT NULL,
  table_name       STRING   NOT NULL,
  passed           BOOLEAN  NOT NULL,
  observed_value   DOUBLE   NOT NULL,
  threshold_value  DOUBLE   NOT NULL,
  details          STRING   NOT NULL
)
USING iceberg
TBLPROPERTIES (
  'format-version' = '2',
  'secops.privacy_zone' = 'governance_quality'
);
