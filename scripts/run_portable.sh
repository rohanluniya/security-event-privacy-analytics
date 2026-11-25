#!/usr/bin/env bash
# Zero-Docker portable one-command runner for macOS (ARM64/x86_64) and Linux.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

HOST="${SECOPS_API_HOST:-127.0.0.1}"
PORT="${SECOPS_API_PORT:-8080}"
SEED="${SECOPS_SEED:-42}"
EVENTS="${SECOPS_EVENTS:-3000}"

if ! command -v uv >/dev/null 2>&1; then
  echo "[run_portable] Error: 'uv' is required. Install via: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
  exit 1
fi

echo "[run_portable] Syncing pinned Python 3.12 environment via uv.lock..."
uv sync --frozen --python 3.12

echo "[run_portable] Executing deterministic security telemetry -> CEP -> Iceberg V2 vertical slice..."
uv run python -m services.secops_platform.cli run-pipeline --seed "${SEED}" --events "${EVENTS}"

echo "[run_portable] Launching Security & Privacy Control Tower on http://${HOST}:${PORT}"
echo "[run_portable] Health: http://${HOST}:${PORT}/health | Dashboard: http://${HOST}:${PORT}/"
exec uv run python -m services.secops_platform.cli serve --host "${HOST}" --port "${PORT}"
