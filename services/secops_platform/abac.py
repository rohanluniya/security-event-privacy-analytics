"""OPA-aligned RBAC/ABAC policy decision engine enforcing privacy zones and separation of duties."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

import requests

from models.contracts import Role
from services.secops_platform.config import PlatformConfig
from services.secops_platform.logging_obs import METRICS

# Mirrors infra/opa/security_abac.rego exactly
ROLE_PERMISSIONS: dict[str, set[str]] = {
    Role.ANALYST_PRIVACY_SAFE.value: {
        "overview",
        "privacy_safe_aggregates",
        "quality",
        "lineage",
        "abac_matrix",
    },
    Role.SOC_RESPONDER.value: {
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
    Role.IR_LEAD_RAW_EVIDENCE.value: {
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
    Role.PRIVACY_OFFICER.value: {
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

ALL_RESOURCES: list[str] = [
    "overview",
    "privacy_safe_aggregates",
    "incidents_read",
    "incidents_disposition",
    "entity_risk",
    "raw_evidence_read",
    "privacy_erase",
    "retention_sweep",
    "audit_read",
    "quality",
    "lineage",
    "traces",
]

MIN_JUSTIFICATION_LEN = 12


@dataclass(frozen=True)
class AbacDecision:
    allow: bool
    reason: str
    role: str
    resource: str
    requires_audit: bool
    evaluated_by: str


class AbacPolicyEngine:
    """Evaluates RBAC/ABAC requests via optional live OPA sidecar or embedded Rego-parity engine."""

    def __init__(self, config: PlatformConfig) -> None:
        self.config = config

    def authenticate(self, api_key: str | None) -> tuple[bool, str | None]:
        """Constant-time verification of API key -> canonical role."""
        if not api_key:
            return False, None
        for role_name, expected_key in self.config.role_api_keys.items():
            if hmac.compare_digest(api_key.strip(), expected_key):
                return True, role_name
        return False, None

    def evaluate(
        self,
        *,
        authenticated: bool,
        role: str | None,
        resource: str,
        justification: str | None = None,
    ) -> AbacDecision:
        role_str = role or "anonymous"
        requires_audit = resource in {"raw_evidence_read", "privacy_erase", "retention_sweep"}

        if self.config.opa_url:
            opa_result = self._try_opa_sidecar(
                authenticated=authenticated,
                role=role_str,
                resource=resource,
                justification=justification or "",
            )
            if opa_result is not None:
                METRICS.abac_decisions.labels(
                    role=role_str,
                    resource=resource,
                    decision="ALLOW" if opa_result.allow else "DENY",
                ).inc()
                return opa_result

        decision = self._evaluate_embedded(
            authenticated=authenticated,
            role=role_str,
            resource=resource,
            justification=justification or "",
            requires_audit=requires_audit,
        )
        METRICS.abac_decisions.labels(
            role=role_str,
            resource=resource,
            decision="ALLOW" if decision.allow else "DENY",
        ).inc()
        return decision

    def _try_opa_sidecar(
        self,
        *,
        authenticated: bool,
        role: str,
        resource: str,
        justification: str,
    ) -> AbacDecision | None:
        try:
            resp = requests.post(
                self.config.opa_url,
                json={
                    "input": {
                        "authenticated": authenticated,
                        "role": role,
                        "resource": resource,
                        "justification": justification,
                    }
                },
                timeout=1.5,
            )
            if resp.status_code == 200:
                body = resp.json().get("result", {})
                allow = bool(body.get("allow", False))
                reason = str(body.get("deny_reason", "Allowed by OPA")) if not allow else "Allowed by OPA policy"
                return AbacDecision(
                    allow=allow,
                    reason=reason,
                    role=role,
                    resource=resource,
                    requires_audit=resource in {"raw_evidence_read", "privacy_erase", "retention_sweep"},
                    evaluated_by="opa_sidecar",
                )
        except requests.RequestException:
            return None
        return None

    def _evaluate_embedded(
        self,
        *,
        authenticated: bool,
        role: str,
        resource: str,
        justification: str,
        requires_audit: bool,
    ) -> AbacDecision:
        if not authenticated:
            return AbacDecision(
                allow=False,
                reason="Unauthenticated request: missing or invalid credentials",
                role=role,
                resource=resource,
                requires_audit=True,
                evaluated_by="embedded_opa_parity",
            )

        permitted = ROLE_PERMISSIONS.get(role, set())
        if resource not in permitted:
            return AbacDecision(
                allow=False,
                reason=(
                    f"Role '{role}' is not permitted to access resource '{resource}' "
                    "(privacy zone / separation-of-duties boundary)"
                ),
                role=role,
                resource=resource,
                requires_audit=True,
                evaluated_by="embedded_opa_parity",
            )

        if resource == "raw_evidence_read":
            if len(justification.strip()) < MIN_JUSTIFICATION_LEN:
                return AbacDecision(
                    allow=False,
                    reason=(
                        "Break-glass raw evidence requires X-Justification header "
                        f"(>= {MIN_JUSTIFICATION_LEN} characters)"
                    ),
                    role=role,
                    resource=resource,
                    requires_audit=True,
                    evaluated_by="embedded_opa_parity",
                )

        return AbacDecision(
            allow=True,
            reason=f"Authorized role '{role}' for resource '{resource}'",
            role=role,
            resource=resource,
            requires_audit=requires_audit,
            evaluated_by="embedded_opa_parity",
        )

    def get_policy_matrix(self) -> list[dict[str, Any]]:
        """Return complete role x resource policy matrix for governance visibility."""
        matrix: list[dict[str, Any]] = []
        for role in (
            Role.ANALYST_PRIVACY_SAFE.value,
            Role.SOC_RESPONDER.value,
            Role.IR_LEAD_RAW_EVIDENCE.value,
            Role.PRIVACY_OFFICER.value,
        ):
            row: dict[str, Any] = {"role": role, "permissions": {}}
            for res in ALL_RESOURCES:
                if res == "raw_evidence_read":
                    dec = self._evaluate_embedded(
                        authenticated=True,
                        role=role,
                        resource=res,
                        justification="INC-AUDIT-CHECK-1234",
                        requires_audit=True,
                    )
                    row["permissions"][res] = "ALLOW_WITH_JUSTIFICATION" if dec.allow else "DENY"
                else:
                    dec = self._evaluate_embedded(
                        authenticated=True,
                        role=role,
                        resource=res,
                        justification="",
                        requires_audit=False,
                    )
                    row["permissions"][res] = "ALLOW" if dec.allow else "DENY"
            matrix.append(row)
        return matrix
