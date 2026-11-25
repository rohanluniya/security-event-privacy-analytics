package secops.abac

import rego.v1

# Default-deny ABAC/RBAC policy for Real-Time Security Event & Privacy-Preserving Analytics Platform.
# Enforces strict separation between Restricted Raw Evidence Zone and Tokenized/Privacy-Safe Analytics Zone.

default allow := false

default deny_reason := "Access denied by default-deny ABAC policy"

# Role -> permitted logical resources
role_permissions := {
	"analyst_privacy_safe": {
		"overview",
		"privacy_safe_aggregates",
		"quality",
		"lineage",
		"abac_matrix",
	},
	"soc_responder": {
		"overview",
		"privacy_safe_aggregates",
		"incidents_read",
		"incidents_disposition",
		"entity_risk",
		"quality",
		"lineage",
		"traces",
		"abac_matrix",
	},
	"ir_lead_raw_evidence": {
		"overview",
		"privacy_safe_aggregates",
		"incidents_read",
		"incidents_disposition",
		"entity_risk",
		"raw_evidence_read",
		"audit_read",
		"quality",
		"lineage",
		"traces",
		"abac_matrix",
	},
	"privacy_officer": {
		"overview",
		"privacy_safe_aggregates",
		"audit_read",
		"privacy_erase",
		"retention_sweep",
		"quality",
		"lineage",
		"abac_matrix",
	},
}

# Standard non-raw-evidence resources require only role authorization
allow if {
	input.authenticated == true
	input.resource != "raw_evidence_read"
	permitted := role_permissions[input.role]
	input.resource in permitted
}

# Break-glass raw evidence access requires ir_lead_raw_evidence role AND audited justification >= 12 chars
allow if {
	input.authenticated == true
	input.role == "ir_lead_raw_evidence"
	input.resource == "raw_evidence_read"
	is_string(input.justification)
	count(trim_space(input.justification)) >= 12
}

deny_reason := "Unauthenticated request: missing or invalid credentials" if {
	input.authenticated != true
}

deny_reason := "Break-glass raw evidence requires X-Justification header (>= 12 characters)" if {
	input.authenticated == true
	input.role == "ir_lead_raw_evidence"
	input.resource == "raw_evidence_read"
	not valid_justification
}

deny_reason := sprintf("Role '%s' is not permitted to access resource '%s' (privacy zone / separation-of-duties boundary)", [input.role, input.resource]) if {
	input.authenticated == true
	permitted := role_permissions[input.role]
	not (input.resource in permitted)
}

valid_justification if {
	is_string(input.justification)
	count(trim_space(input.justification)) >= 12
}
