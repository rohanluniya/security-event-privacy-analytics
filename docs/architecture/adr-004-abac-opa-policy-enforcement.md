# ADR-004: Default-Deny OPA-Aligned ABAC/RBAC with Separation of Duties

## Status
Accepted

## Context
A common breach pattern in security data lakes is over-privileged "super-admin" roles that can simultaneously read raw PII evidence and delete audit/evidence records, or BI analysts inadvertently querying raw IP/email columns.

## Decision
Enforce a strict default-deny RBAC/ABAC policy defined in `infra/opa/security_abac.rego` and executed either via a live OPA 1.22.3 sidecar (`SECOPS_OPA_URL`) or the identical embedded Rego-parity evaluator (`services/secops_platform/abac.py`) across four mutually scoped roles:
- `analyst_privacy_safe`: k-anonymous aggregates (`k >= 5`), overview, DQ, lineage ONLY (`403` on incidents, entity risk, raw evidence, erasure).
- `soc_responder`: tokenized incident triage, disposition updates, entity risk (`403` on raw evidence, erasure, retention sweep).
- `ir_lead_raw_evidence`: SOC capabilities + audited break-glass reads on `/v1/evidence/raw/{event_id}` **only when** `X-Justification` length `>= 12` (`403` on GDPR erasure and retention sweeps — enforcing separation of duties).
- `privacy_officer`: GDPR subject erasure, retention TTL sweeps, immutable audit ledger reads (`403` on raw forensic PII evidence and incident dispositions).

## Consequences
- **Positive:** Every unauthorized request returns HTTP `401`/`403` and appends an immutable `ABAC_ACCESS_DENIED` entry to `gold.retention_and_erasure_audit`. No single role can both inspect raw PII and erase evidence.
- **Tradeoff:** Demo/local authentication uses environment-injected role API keys; production deployments must bind roles from signed OIDC/JWT claims verified at an API gateway.
