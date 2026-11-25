"""FastAPI Security & Privacy Control Plane with OPA-aligned RBAC/ABAC enforcement and Prometheus metrics."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse

from models.contracts import DispositionUpdateRequest
from services.secops_platform.abac import AbacPolicyEngine
from services.secops_platform.config import PlatformConfig
from services.secops_platform.logging_obs import (
    METRICS,
    LocalSpanTracer,
    get_structured_logger,
)
from services.secops_platform.privacy import PrivacyVault
from services.secops_platform.storage import PrivacyLakehouse

logger = get_structured_logger("secops_platform.api")
DASHBOARD_HTML = Path(__file__).resolve().parents[2] / "apps" / "secops-dashboard" / "index.html"


@dataclass(frozen=True)
class AuthContext:
    actor_id: str
    role: str
    justification: str | None
    evaluated_by: str


def create_app(config: PlatformConfig | None = None) -> FastAPI:
    cfg = config or PlatformConfig.from_env()
    cfg.ensure_directories()
    lakehouse = PrivacyLakehouse(cfg)
    policy = AbacPolicyEngine(cfg)
    tracer = LocalSpanTracer(cfg.traces_file_path)

    app = FastAPI(
        title="Real-Time Security Event & Privacy-Preserving Analytics Platform",
        version="1.0.0",
        description=(
            "Streaming CEP incident correlation, cryptographic tokenization, Apache Iceberg V2 "
            "privacy zones, OPA-aligned RBAC/ABAC enforcement, and GDPR right-to-erasure control plane."
        ),
    )
    app.state.config = cfg
    app.state.lakehouse = lakehouse
    app.state.policy = policy
    app.state.tracer = tracer

    @app.middleware("http")
    async def observe_requests(request: Request, call_next: Any) -> Response:
        t0 = time.perf_counter()
        response: Response = await call_next(request)
        elapsed = time.perf_counter() - t0
        endpoint = request.url.path
        METRICS.api_request_duration.labels(
            endpoint=endpoint,
            method=request.method,
            status=str(response.status_code),
        ).observe(elapsed)
        return response

    def require_abac(resource: str) -> Any:
        def _dependency(
            x_api_key: str | None = Header(default=None, alias="X-API-Key"),
            x_actor_id: str | None = Header(default=None, alias="X-Actor-Id"),
            x_justification: str | None = Header(default=None, alias="X-Justification"),
        ) -> AuthContext:
            authenticated, role = policy.authenticate(x_api_key)
            actor = (x_actor_id or (f"actor-{role}" if role else "unauthenticated")).strip()
            if not authenticated or role is None:
                policy.evaluate(
                    authenticated=False,
                    role=None,
                    resource=resource,
                    justification=x_justification,
                )
                lakehouse.append_audit_event(
                    action_type="ABAC_ACCESS_DENIED",
                    actor_id=actor,
                    actor_role="anonymous",
                    target_resource=resource,
                    decision="DENY_401",
                    justification=None,
                    details={"reason": "Missing or invalid X-API-Key"},
                )
                raise HTTPException(
                    status_code=401,
                    detail="Unauthorized: valid X-API-Key header required.",
                )

            decision = policy.evaluate(
                authenticated=True,
                role=role,
                resource=resource,
                justification=x_justification,
            )
            if not decision.allow:
                lakehouse.append_audit_event(
                    action_type="ABAC_ACCESS_DENIED",
                    actor_id=actor,
                    actor_role=role,
                    target_resource=resource,
                    decision="DENY_403",
                    justification=x_justification,
                    details={"reason": decision.reason, "evaluated_by": decision.evaluated_by},
                )
                raise HTTPException(status_code=403, detail=decision.reason)

            return AuthContext(
                actor_id=actor,
                role=role,
                justification=x_justification,
                evaluated_by=decision.evaluated_by,
            )

        return Depends(_dependency)

    @app.get("/", include_in_schema=False)
    def serve_dashboard() -> Response:
        if DASHBOARD_HTML.exists():
            return FileResponse(DASHBOARD_HTML)
        return PlainTextResponse("SecOps Dashboard not built yet.", status_code=404)

    @app.get("/health")
    def health() -> dict[str, Any]:
        meta: dict[str, Any] = {}
        if cfg.metadata_file_path.exists():
            meta = json.loads(cfg.metadata_file_path.read_text(encoding="utf-8"))
        now_ms = int(time.time() * 1000)
        last_updated = int(meta.get("last_updated_ms", 0))
        freshness_sec = round(max(0.0, (now_ms - last_updated) / 1000.0), 2) if last_updated else None
        return {
            "status": "healthy",
            "runtime_mode": cfg.runtime_mode,
            "k_anonymity_threshold": cfg.k_anonymity_threshold,
            "raw_retention_days": cfg.raw_retention_days,
            "last_run_id": meta.get("last_run_id"),
            "freshness_seconds": freshness_sec,
            "tables": {
                "bronze_raw_security_evidence": lakehouse.table_row_count("bronze.raw_security_evidence"),
                "bronze_quarantine_dlq": lakehouse.table_row_count("bronze.quarantine_dlq"),
                "silver_tokenized_security_events": lakehouse.table_row_count("silver.tokenized_security_events"),
                "silver_identity_resolution_map": lakehouse.table_row_count("silver.identity_resolution_map"),
                "gold_cep_security_incidents": lakehouse.table_row_count("gold.cep_security_incidents"),
                "gold_entity_risk_scores": lakehouse.table_row_count("gold.entity_risk_scores"),
                "gold_privacy_safe_aggregates": lakehouse.table_row_count("gold.privacy_safe_aggregates"),
                "gold_retention_and_erasure_audit": lakehouse.table_row_count("gold.retention_and_erasure_audit"),
                "quality_dq_results": lakehouse.table_row_count("quality.dq_results"),
            },
        }

    @app.get("/metrics")
    def prometheus_metrics() -> Response:
        return Response(
            content=METRICS.render_prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/v1/overview")
    def get_overview(ctx: AuthContext = require_abac("overview")) -> dict[str, Any]:
        meta: dict[str, Any] = {}
        if cfg.metadata_file_path.exists():
            meta = json.loads(cfg.metadata_file_path.read_text(encoding="utf-8"))

        incidents = lakehouse.read_rows("gold.cep_security_incidents")
        dq_rows = lakehouse.read_rows("quality.dq_results")
        aggs = lakehouse.read_rows("gold.privacy_safe_aggregates")
        audit_rows = lakehouse.read_rows("gold.retention_and_erasure_audit")

        by_rule: dict[str, int] = {}
        by_status: dict[str, int] = {}
        sample_event_ids: list[str] = []
        for inc in incidents:
            rref = str(inc["rule_ref"])
            st = str(inc["status"])
            by_rule[rref] = by_rule.get(rref, 0) + 1
            by_status[st] = by_status.get(st, 0) + 1
            if len(sample_event_ids) < 5:
                ev_ids = json.loads(str(inc["evidence_event_ids_json"]))
                if ev_ids:
                    sample_event_ids.append(str(ev_ids[0]))

        min_k_observed = min((int(a["distinct_principals"]) for a in aggs), default=cfg.k_anonymity_threshold)
        now_ms = int(time.time() * 1000)
        last_updated = int(meta.get("last_updated_ms", 0))
        return {
            "actor_role": ctx.role,
            "policy_engine": ctx.evaluated_by,
            "runtime_mode": cfg.runtime_mode,
            "last_run_id": meta.get("last_run_id"),
            "last_updated_ms": last_updated,
            "freshness_seconds": round(max(0.0, (now_ms - last_updated) / 1000.0), 2) if last_updated else None,
            "summary": meta.get("summary", {}),
            "counts": {
                "raw_evidence_rows": lakehouse.table_row_count("bronze.raw_security_evidence"),
                "quarantine_dlq_rows": lakehouse.table_row_count("bronze.quarantine_dlq"),
                "silver_tokenized_rows": lakehouse.table_row_count("silver.tokenized_security_events"),
                "identity_map_rows": lakehouse.table_row_count("silver.identity_resolution_map"),
                "incidents_total": len(incidents),
                "incidents_active": sum(1 for i in incidents if i["status"] != "RETRACTED"),
                "incidents_retracted": sum(1 for i in incidents if i["status"] == "RETRACTED"),
                "entity_risk_rows": lakehouse.table_row_count("gold.entity_risk_scores"),
                "privacy_safe_buckets": len(aggs),
                "audit_events": len(audit_rows),
            },
            "incidents_by_rule": by_rule,
            "incidents_by_status": by_status,
            "privacy_posture": {
                "k_anonymity_threshold": cfg.k_anonymity_threshold,
                "min_distinct_principals_observed": min_k_observed,
                "raw_retention_days": cfg.raw_retention_days,
                "silver_retention_days": cfg.silver_retention_days,
                "zone_isolation": "strict_bronze_restricted_vs_silver_gold_tokenized",
            },
            "dq_status": {
                "passed": sum(1 for d in dq_rows if d["passed"]),
                "total": len(dq_rows),
            },
            "gdpr_candidate_tokens": meta.get("gdpr_candidate_tokens", []),
            "sample_evidence_event_ids": sample_event_ids,
        }

    @app.get("/v1/incidents")
    def list_incidents(
        status: str | None = Query(default=None),
        rule_id: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
        ctx: AuthContext = require_abac("incidents_read"),
    ) -> dict[str, Any]:
        with tracer.start_span("api.list_incidents", attributes={"role": ctx.role}):
            rows = lakehouse.read_rows("gold.cep_security_incidents")
            filtered: list[dict[str, Any]] = []
            for row in rows:
                if status and row["status"] != status:
                    continue
                if rule_id and row["rule_id"] != rule_id:
                    continue
                if severity and row["severity"] != severity:
                    continue
                item = dict(row)
                item["evidence_event_ids"] = json.loads(str(item.pop("evidence_event_ids_json")))
                filtered.append(item)
            filtered.sort(key=lambda r: int(r["detected_at_ms"]), reverse=True)
            return {
                "actor_role": ctx.role,
                "total": len(filtered),
                "items": filtered[:limit],
            }

    @app.post("/v1/incidents/{incident_id}/disposition")
    def update_disposition(
        incident_id: str,
        payload: DispositionUpdateRequest,
        ctx: AuthContext = require_abac("incidents_disposition"),
    ) -> dict[str, Any]:
        with tracer.start_span(
            "api.update_disposition",
            attributes={"incident_id": incident_id, "status": payload.status.value},
        ):
            updated = lakehouse.update_incident_disposition(
                incident_id=incident_id,
                status=payload.status,
                actor_id=ctx.actor_id,
                note=payload.note,
            )
            if updated is None:
                raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
            audit = lakehouse.append_audit_event(
                action_type="INCIDENT_DISPOSITION_UPDATE",
                actor_id=ctx.actor_id,
                actor_role=ctx.role,
                target_resource=incident_id,
                decision="UPDATED",
                justification=payload.note,
                details={"new_status": payload.status.value},
            )
            updated["evidence_event_ids"] = json.loads(str(updated.pop("evidence_event_ids_json")))
            return {"incident": updated, "audit_id": audit.audit_id}

    @app.get("/v1/entities/risk")
    def list_entity_risk(
        limit: int = Query(default=50, ge=1, le=500),
        ctx: AuthContext = require_abac("entity_risk"),
    ) -> dict[str, Any]:
        rows = lakehouse.read_rows("gold.entity_risk_scores")
        items = []
        for row in rows:
            item = dict(row)
            item["rules_triggered"] = json.loads(str(item.pop("rules_triggered_json")))
            items.append(item)
        items.sort(key=lambda r: (float(r["risk_score"]), int(r["active_incident_count"])), reverse=True)
        return {"actor_role": ctx.role, "total": len(items), "items": items[:limit]}

    @app.get("/v1/aggregates/privacy-safe")
    def list_privacy_safe_aggregates(
        source_stream: str | None = Query(default=None),
        geo_country: str | None = Query(default=None),
        ctx: AuthContext = require_abac("privacy_safe_aggregates"),
    ) -> dict[str, Any]:
        rows = lakehouse.read_rows("gold.privacy_safe_aggregates")
        filtered = [
            r
            for r in rows
            if (not source_stream or r["source_stream"] == source_stream)
            and (not geo_country or r["geo_country"] == geo_country)
        ]
        filtered.sort(key=lambda r: int(r["event_count"]), reverse=True)
        return {
            "actor_role": ctx.role,
            "k_anonymity_threshold": cfg.k_anonymity_threshold,
            "total": len(filtered),
            "items": filtered,
        }

    @app.get("/v1/evidence/raw/{event_id}")
    def get_raw_evidence(
        event_id: str,
        ctx: AuthContext = require_abac("raw_evidence_read"),
    ) -> dict[str, Any]:
        with tracer.start_span(
            "api.break_glass_raw_evidence",
            trace_id=uuid.uuid4().hex,
            attributes={"actor_role": ctx.role, "event_id": event_id},
        ):
            record = lakehouse.get_raw_evidence_by_event_id(event_id)
            audit = lakehouse.append_audit_event(
                action_type="BREAK_GLASS_RAW_EVIDENCE_READ",
                actor_id=ctx.actor_id,
                actor_role=ctx.role,
                target_resource=event_id,
                decision="ALLOW_AUDITED" if record is not None else "ALLOW_NOT_FOUND",
                justification=ctx.justification,
                details={"zone": "bronze.raw_security_evidence", "found": record is not None},
            )
            if record is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Raw evidence event {event_id} not found (may be purged by retention or GDPR erasure).",
                )
            return {
                "zone": "bronze.raw_security_evidence (RESTRICTED)",
                "audit_id": audit.audit_id,
                "actor_id": ctx.actor_id,
                "actor_role": ctx.role,
                "justification": ctx.justification,
                "evidence": record,
            }

    @app.post("/v1/privacy/erase/{subject_token}")
    def erase_subject(
        subject_token: str,
        ctx: AuthContext = require_abac("privacy_erase"),
    ) -> dict[str, Any]:
        vault = PrivacyVault(cfg.hmac_master_key, cfg.key_version, cfg.vault_file_path)
        with tracer.start_span("api.gdpr_subject_erasure", attributes={"subject": subject_token}):
            result = lakehouse.erase_subject_gdpr(
                principal_token=subject_token,
                vault=vault,
                actor_id=ctx.actor_id,
                actor_role=ctx.role,
                justification=ctx.justification or "GDPR Article 17 Subject Erasure Request",
            )
        return result

    @app.post("/v1/privacy/retention-sweep")
    def trigger_retention_sweep(
        reference_time_ms: int | None = Query(default=None),
        ctx: AuthContext = require_abac("retention_sweep"),
    ) -> dict[str, Any]:
        if reference_time_ms is None:
            meta: dict[str, Any] = {}
            if cfg.metadata_file_path.exists():
                meta = json.loads(cfg.metadata_file_path.read_text(encoding="utf-8"))
            reference_time_ms = int(meta.get("base_time_ms", int(time.time() * 1000))) + 3_600_000
        with tracer.start_span("api.retention_sweep", attributes={"reference_time_ms": reference_time_ms}):
            return lakehouse.run_retention_sweep(
                reference_time_ms=reference_time_ms,
                actor_id=ctx.actor_id,
                actor_role=ctx.role,
                justification=ctx.justification or "Policy-enforced retention TTL sweep",
            )

    @app.get("/v1/audit")
    def list_audit_events(
        limit: int = Query(default=100, ge=1, le=500),
        ctx: AuthContext = require_abac("audit_read"),
    ) -> dict[str, Any]:
        rows = lakehouse.read_rows("gold.retention_and_erasure_audit")
        rows.sort(key=lambda r: int(r["event_time_ms"]), reverse=True)
        return {"actor_role": ctx.role, "total": len(rows), "items": rows[:limit]}

    @app.get("/v1/quality")
    def list_quality_results(
        ctx: AuthContext = require_abac("quality"),
    ) -> dict[str, Any]:
        dq_rows = lakehouse.read_rows("quality.dq_results")
        dlq_rows = lakehouse.read_rows("bronze.quarantine_dlq")
        dlq_by_code: dict[str, int] = {}
        for row in dlq_rows:
            code = str(row["error_code"])
            dlq_by_code[code] = dlq_by_code.get(code, 0) + 1
        return {
            "actor_role": ctx.role,
            "checks": dq_rows,
            "passed": sum(1 for d in dq_rows if d["passed"]),
            "total": len(dq_rows),
            "dlq_total": len(dlq_rows),
            "dlq_by_error_code": dlq_by_code,
            "dlq_samples": dlq_rows[:10],
        }

    @app.get("/v1/lineage")
    def get_lineage(ctx: AuthContext = require_abac("lineage")) -> dict[str, Any]:
        if cfg.lineage_file_path.exists():
            return dict(json.loads(cfg.lineage_file_path.read_text(encoding="utf-8")))
        return {"actor_role": ctx.role, "inputs": [], "outputs": [], "edges": []}

    @app.get("/v1/traces")
    def get_traces(
        limit: int = Query(default=30, ge=1, le=200),
        ctx: AuthContext = require_abac("traces"),
    ) -> dict[str, Any]:
        return {
            "actor_role": ctx.role,
            "spans": tracer.read_recent_spans(limit=limit),
        }

    @app.get("/v1/abac/matrix")
    def get_abac_matrix(ctx: AuthContext = require_abac("abac_matrix")) -> dict[str, Any]:
        return {
            "actor_role": ctx.role,
            "policy_source": "infra/opa/security_abac.rego",
            "evaluated_by": ctx.evaluated_by,
            "matrix": policy.get_policy_matrix(),
        }

    return app


app = create_app()
