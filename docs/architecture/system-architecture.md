# System Architecture & Privacy Zone Isolation

## 1. Component & Privacy-Zone Diagram

```mermaid
flowchart LR
    subgraph Sources["6 Multi-Source Security Telemetry Streams"]
        S1["auth"]
        S2["endpoint"]
        S3["dns"]
        S4["proxy"]
        S5["api_gateway"]
        S6["application"]
    end

    subgraph Ingestion["Durable Ingestion & Contract Gate"]
        WAL["Durable WAL Broker / Kafka 4.3.2\n(security.telemetry.raw.v2)"]
        AVRO["Avro v1/v2 Validator\n& Quarantine Router"]
        DLQ["bronze.quarantine_dlq\n(Malformed Poison Events)"]
    end

    subgraph PrivacyCompute["Cryptographic Tokenization & Streaming CEP"]
        VAULT["PrivacyVault / OpenBao 2.7.3\n(HMAC-SHA256 + Per-Subject Salt)"]
        IDRES["NAT-Safe Identity Resolver\n(Bounded LRU Alias Graph)"]
        CEP["Event-Time Streaming CEP Engine\n(Watermarks, Dedup, Retractions)"]
    end

    subgraph Lakehouse["Apache Iceberg V2 Lakehouse (Strict Zone Separation)"]
        subgraph RestrictedZone["RESTRICTED RAW EVIDENCE ZONE (7d TTL)"]
            BRONZE["bronze.raw_security_evidence\n(Raw IP, Email, Device — IR Lead Break-Glass ONLY)"]
        end
        subgraph TokenizedZone["TOKENIZED & PRIVACY-SAFE ZONE (90d-365d TTL)"]
            SILVER["silver.tokenized_security_events\n(Zero Raw PII, /24 Subnet, Masked Email)"]
            IDMAP["silver.identity_resolution_map\n(Crypto-Shredded on GDPR Erasure)"]
            INC["gold.cep_security_incidents\n(Versioned Rules + SHA-256 evidence_ref)"]
            RISK["gold.entity_risk_scores\n(Pseudonymous Risk Leaderboard)"]
            KANON["gold.privacy_safe_aggregates\n(Strict k >= 5 Suppression)"]
            AUDIT["gold.retention_and_erasure_audit\n(Immutable Governance Ledger)"]
            DQ["quality.dq_results\n(PII Leak & Reconciliation Checks)"]
        end
    end

    subgraph ControlPlane["Serving & OPA-Aligned ABAC Control Plane"]
        OPA["OPA Rego Policy\n(security_abac.rego)"]
        API["FastAPI Control Plane (:8080)\n+ Prometheus /metrics"]
        UI["SOC & Privacy Control Tower UI"]
    end

    Sources --> WAL --> AVRO
    AVRO -- "invalid schema / bad IP / coords" --> DLQ
    AVRO -- "valid events" --> IDRES
    VAULT <--> IDRES
    IDRES --> CEP
    AVRO -- "restricted copy" --> BRONZE
    CEP --> SILVER
    IDRES --> IDMAP
    CEP --> INC
    CEP --> RISK
    SILVER --> KANON
    SILVER --> DQ
    OPA <--> API
    BRONZE -. "403 unless ir_lead + justification" .-> API
    INC --> API
    RISK --> API
    KANON --> API
    AUDIT --> API
    DQ --> API
    API --> UI
```

## 2. Event-Time Correlation, Clock-Skew Retraction & Break-Glass Sequence

```mermaid
sequenceDiagram
    participant Src as Multi-Source Telemetry
    participant WAL as Durable WAL / Kafka
    participant CEP as Streaming CEP Engine
    participant Vault as PrivacyVault / OpenBao
    participant Ice as Apache Iceberg V2
    participant API as FastAPI + OPA ABAC

    Src->>WAL: Append auth/endpoint/dns/proxy/api/app events (with duplicates & clock skew)
    WAL->>CEP: Consume from offset 0 (watermark = max_event_time - 30s)
    CEP->>Vault: HMAC-SHA256 tokenize principal/device/session/token/IP (NEVER conflate NAT IP)
    CEP->>Ice: Write raw PII -> bronze.raw_security_evidence (Restricted Zone)
    CEP->>Ice: Write zero-PII events -> silver.tokenized_security_events
    CEP->>Ice: Emit speculative impossible_travel@v2 incident + SHA-256 evidence_ref
    Src->>WAL: Late NTP/MFA reconciliation event (is_retraction_evidence=true)
    WAL->>CEP: Process retraction within allowed lateness
    CEP->>Ice: Transition incident status -> RETRACTED & zero entity risk weight
    Note over API: Analyst attempts GET /v1/evidence/raw/{event_id}
    API->>Ice: Log ABAC_ACCESS_DENIED (HTTP 403) in gold.retention_and_erasure_audit
    Note over API: IR Lead sends GET /v1/evidence/raw/{event_id} + X-Justification (>=12 chars)
    API->>Ice: Return raw evidence + append BREAK_GLASS_RAW_EVIDENCE_READ audit record
```

## 3. Failure-Domain & Consistency Boundaries

| Boundary | Delivery / Consistency Guarantee | Recovery Mechanism |
| :--- | :--- | :--- |
| Telemetry -> WAL Broker | At-least-once durable append (`fsync` per batch) | Producer retries absorbed downstream by `event_id` deduplication |
| WAL -> CEP Engine | Effectively-once business state via deterministic `event_id` dedup + deterministic `incident_id` upsert | Replay from WAL offset `0` reproduces identical Silver rows and Gold incident IDs |
| CEP -> Apache Iceberg V2 | Atomic snapshot commits (`append` / `overwrite`) | Time-travel rollback via Iceberg snapshot history |
| GDPR Erasure | Atomic per-subject salt destruction + table rewrites + immutable audit append | Re-running erasure for an already-shredded token is idempotent and returns `0` remaining rows |
| ABAC Policy Check | Fail-closed (`default allow := false`) | Missing OPA sidecar falls back only to identical embedded Rego-parity evaluator (never fail-open) |
