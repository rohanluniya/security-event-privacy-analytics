-- Privacy-Safe & SOC Operational Analytical Queries (DuckDB / Spark SQL / Trino compatible)

-- 1. Verify k-anonymity threshold invariant (MUST return 0 rows)
SELECT bucket_date, source_stream, geo_country, action, event_count, distinct_principals
FROM gold_privacy_safe_aggregates
WHERE distinct_principals < 5 OR event_count < 5;

-- 2. Active incident summary by rule version and severity (excluding clock-skew retractions)
SELECT
  rule_ref,
  severity,
  COUNT(*) AS incident_count,
  ROUND(AVG(detection_delay_ms), 2) AS avg_detection_delay_ms,
  ROUND(AVG(confidence_score), 3) AS avg_confidence
FROM gold_cep_security_incidents
WHERE status NOT IN ('RETRACTED', 'FALSE_POSITIVE')
GROUP BY rule_ref, severity
ORDER BY incident_count DESC, rule_ref ASC;

-- 3. Retraction audit report (clock-skewed speculative alerts reconciled by late events)
SELECT
  incident_id,
  rule_ref,
  principal_token,
  retracted_reason,
  evidence_ref
FROM gold_cep_security_incidents
WHERE status = 'RETRACTED';

-- 4. Top high-risk pseudonymous entities
SELECT
  principal_token,
  masked_email,
  risk_score,
  risk_tier,
  active_incident_count,
  retracted_incident_count
FROM gold_entity_risk_scores
ORDER BY risk_score DESC
LIMIT 20;

-- 5. Break-glass & ABAC denial governance audit summary
SELECT
  action_type,
  actor_role,
  decision,
  COUNT(*) AS event_count
FROM gold_retention_and_erasure_audit
GROUP BY action_type, actor_role, decision
ORDER BY event_count DESC;
