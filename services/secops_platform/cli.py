"""Command-line interface for running the security analytics pipeline, replay, privacy sweeps, and API server."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import uvicorn

from services.secops_platform.config import PlatformConfig
from services.secops_platform.pipeline import run_end_to_end_pipeline
from services.secops_platform.privacy import PrivacyVault
from services.secops_platform.storage import PrivacyLakehouse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secops-platform",
        description="Real-Time Security Event & Privacy-Preserving Analytics Platform CLI",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Override local data directory (defaults to SECOPS_DATA_DIR or .local_data)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run-pipeline", help="Generate deterministic telemetry and run full Iceberg V2 pipeline")
    p_run.add_argument("--seed", type=int, default=42)
    p_run.add_argument("--events", type=int, default=3000)
    p_run.add_argument("--nat-naive", action="store_true", help="Disable NAT-aware guard (v1 baseline mode)")

    p_replay = sub.add_parser("replay", help="Replay durable WAL from offset 0 into Iceberg V2")
    p_replay.add_argument("--seed", type=int, default=42)

    p_erase = sub.add_parser("erase-subject", help="Run GDPR Article 17 crypto-shredding and purge for a principal_token")
    p_erase.add_argument("--subject-token", required=True)
    p_erase.add_argument("--actor-id", default="cli-privacy-officer")
    p_erase.add_argument("--justification", default="CLI GDPR Article 17 erasure")

    p_ret = sub.add_parser("retention-sweep", help="Enforce raw & silver retention TTL windows")
    p_ret.add_argument("--reference-time-ms", type=int, default=None)

    p_comp = sub.add_parser("compact", help="Compact Iceberg V2 Parquet files for a table")
    p_comp.add_argument("--table", default="silver.tokenized_security_events")

    p_serve = sub.add_parser("serve", help="Start FastAPI Security & Privacy Control Plane + Dashboard")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = PlatformConfig.from_env(data_dir=Path(args.data_dir) if args.data_dir else None)

    if args.command == "run-pipeline":
        summary = run_end_to_end_pipeline(
            cfg,
            seed=args.seed,
            total_events=args.events,
            nat_aware=not args.nat_naive,
            clock_skew_retraction_enabled=not args.nat_naive,
        )
        print(json.dumps(summary.model_dump(), indent=2, sort_keys=True))
        return 0

    if args.command == "replay":
        summary = run_end_to_end_pipeline(cfg, seed=args.seed, replay_only=True, reset_wal=False)
        print(json.dumps(summary.model_dump(), indent=2, sort_keys=True))
        return 0

    if args.command == "erase-subject":
        lakehouse = PrivacyLakehouse(cfg)
        vault = PrivacyVault(cfg.hmac_master_key, cfg.key_version, cfg.vault_file_path)
        res = lakehouse.erase_subject_gdpr(
            principal_token=args.subject_token,
            vault=vault,
            actor_id=args.actor_id,
            actor_role="privacy_officer",
            justification=args.justification,
        )
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.command == "retention-sweep":
        lakehouse = PrivacyLakehouse(cfg)
        ref_ms = args.reference_time_ms
        if ref_ms is None and cfg.metadata_file_path.exists():
            meta = json.loads(cfg.metadata_file_path.read_text(encoding="utf-8"))
            ref_ms = int(meta.get("base_time_ms", 1_795_500_000_000)) + 3_600_000
        res = lakehouse.run_retention_sweep(
            reference_time_ms=ref_ms or 1_795_503_600_000,
            actor_id="cli-privacy-officer",
            actor_role="privacy_officer",
        )
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.command == "compact":
        lakehouse = PrivacyLakehouse(cfg)
        res = lakehouse.compact_table(args.table)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.command == "serve":
        uvicorn.run(
            "services.secops_platform.api:app",
            host=args.host,
            port=args.port,
            log_level="info",
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
