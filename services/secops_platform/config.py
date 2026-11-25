"""Runtime configuration for the Security Event & Privacy-Preserving Analytics Platform."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PlatformConfig:
    runtime_mode: str = "local_native"
    data_dir: Path = Path(".local_data")
    api_host: str = "127.0.0.1"
    api_port: int = 8080

    # Privacy & cryptographic settings (DEV ONLY defaults; inject via OpenBao in prod)
    hmac_master_key: str = "dev-only-hmac-key-replace-via-openbao-transit-32b"
    key_version: str = "v1"
    k_anonymity_threshold: int = 5
    raw_retention_days: int = 7
    silver_retention_days: int = 90
    gold_retention_days: int = 365

    # Optional external OPA server URL (e.g., http://localhost:8181/v1/data/secops/abac)
    opa_url: str = ""

    # Role API keys (DEV ONLY demo keys; replace with OIDC/JWT + OpenBao in prod)
    role_api_keys: dict[str, str] = field(
        default_factory=lambda: {
            "analyst_privacy_safe": "secops-dev-analyst-key",
            "soc_responder": "secops-dev-soc-key",
            "ir_lead_raw_evidence": "secops-dev-ir-lead-key",
            "privacy_officer": "secops-dev-privacy-officer-key",
        }
    )

    @property
    def wal_dir(self) -> Path:
        return self.data_dir / "wal"

    @property
    def warehouse_dir(self) -> Path:
        return self.data_dir / "iceberg_warehouse"

    @property
    def catalog_db_path(self) -> Path:
        return self.data_dir / "iceberg_catalog.sqlite"

    @property
    def vault_file_path(self) -> Path:
        return self.data_dir / "restricted_vault" / "subject_keys.json"

    @property
    def traces_file_path(self) -> Path:
        return self.data_dir / "traces" / "spans.jsonl"

    @property
    def lineage_file_path(self) -> Path:
        return self.data_dir / "lineage" / "lineage_events.json"

    @property
    def metadata_file_path(self) -> Path:
        return self.data_dir / "run_metadata.json"

    def ensure_directories(self) -> None:
        for directory in (
            self.data_dir,
            self.wal_dir,
            self.warehouse_dir,
            self.vault_file_path.parent,
            self.traces_file_path.parent,
            self.lineage_file_path.parent,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls, data_dir: Path | str | None = None) -> PlatformConfig:
        resolved_dir = Path(data_dir) if data_dir is not None else Path(
            os.getenv("SECOPS_DATA_DIR", ".local_data")
        )
        return cls(
            runtime_mode=os.getenv("SECOPS_RUNTIME_MODE", "local_native"),
            data_dir=resolved_dir.resolve(),
            api_host=os.getenv("SECOPS_API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("SECOPS_API_PORT", "8080")),
            hmac_master_key=os.getenv(
                "SECOPS_HMAC_MASTER_KEY",
                "dev-only-hmac-key-replace-via-openbao-transit-32b",
            ),
            key_version=os.getenv("SECOPS_KEY_VERSION", "v1"),
            k_anonymity_threshold=int(os.getenv("SECOPS_K_ANONYMITY_THRESHOLD", "5")),
            raw_retention_days=int(os.getenv("SECOPS_RAW_RETENTION_DAYS", "7")),
            silver_retention_days=int(os.getenv("SECOPS_SILVER_RETENTION_DAYS", "90")),
            gold_retention_days=int(os.getenv("SECOPS_GOLD_RETENTION_DAYS", "365")),
            opa_url=os.getenv("SECOPS_OPA_URL", "").strip(),
            role_api_keys={
                "analyst_privacy_safe": os.getenv(
                    "SECOPS_KEY_ANALYST", "secops-dev-analyst-key"
                ),
                "soc_responder": os.getenv("SECOPS_KEY_SOC", "secops-dev-soc-key"),
                "ir_lead_raw_evidence": os.getenv(
                    "SECOPS_KEY_IR_LEAD", "secops-dev-ir-lead-key"
                ),
                "privacy_officer": os.getenv(
                    "SECOPS_KEY_PRIVACY_OFFICER", "secops-dev-privacy-officer-key"
                ),
            },
        )
