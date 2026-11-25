#!/usr/bin/env bash
set -euo pipefail

SEED="${SECOPS_SEED:-42}"
EVENTS="${SECOPS_EVENTS:-3000}"
HOST="${SECOPS_API_HOST:-0.0.0.0}"
PORT="${SECOPS_API_PORT:-8080}"

echo "[secops-standalone] Running deterministic telemetry -> CEP -> Iceberg V2 bootstrap (seed=${SEED}, events=${EVENTS})..."
.venv/bin/python -m services.secops_platform.cli run-pipeline --seed "${SEED}" --events "${EVENTS}"

echo "[secops-standalone] Starting FastAPI Security & Privacy Control Plane on http://${HOST}:${PORT}"
exec .venv/bin/python -m services.secops_platform.cli serve --host "${HOST}" --port "${PORT}"
