package secops.abac_test

import data.secops.abac
import rego.v1

test_analyst_allowed_privacy_safe_aggregates if {
	abac.allow with input as {
		"authenticated": true,
		"role": "analyst_privacy_safe",
		"resource": "privacy_safe_aggregates",
		"justification": "",
	}
}

test_analyst_denied_raw_evidence if {
	not abac.allow with input as {
		"authenticated": true,
		"role": "analyst_privacy_safe",
		"resource": "raw_evidence_read",
		"justification": "trying to inspect raw IP",
	}
}

test_soc_responder_denied_raw_evidence if {
	not abac.allow with input as {
		"authenticated": true,
		"role": "soc_responder",
		"resource": "raw_evidence_read",
		"justification": "incident triage check",
	}
}

test_ir_lead_denied_raw_evidence_without_justification if {
	not abac.allow with input as {
		"authenticated": true,
		"role": "ir_lead_raw_evidence",
		"resource": "raw_evidence_read",
		"justification": "short",
	}
}

test_ir_lead_allowed_raw_evidence_with_justification if {
	abac.allow with input as {
		"authenticated": true,
		"role": "ir_lead_raw_evidence",
		"resource": "raw_evidence_read",
		"justification": "INC-2026-0042 confirmed lateral movement forensics",
	}
}

test_ir_lead_denied_gdpr_erasure_separation_of_duties if {
	not abac.allow with input as {
		"authenticated": true,
		"role": "ir_lead_raw_evidence",
		"resource": "privacy_erase",
		"justification": "attempting erasure",
	}
}

test_privacy_officer_allowed_gdpr_erasure if {
	abac.allow with input as {
		"authenticated": true,
		"role": "privacy_officer",
		"resource": "privacy_erase",
		"justification": "GDPR Article 17 request #991",
	}
}

test_privacy_officer_denied_raw_evidence if {
	not abac.allow with input as {
		"authenticated": true,
		"role": "privacy_officer",
		"resource": "raw_evidence_read",
		"justification": "GDPR Article 17 check",
	}
}
