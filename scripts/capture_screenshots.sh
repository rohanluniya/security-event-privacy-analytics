#!/usr/bin/env bash
# Capture headless Chrome screenshots of the live SOC & Privacy Control Tower dashboard
# using a concurrency lock to prevent overlapping headless Chrome runs.
set -euo pipefail

URL="${1:-http://127.0.0.1:8080/}"
OUT_DIR="docs/assets"
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

mkdir -p "${OUT_DIR}"

while ! mkdir /tmp/chrome_screenshot_lock 2>/dev/null; do
  sleep 1
done
trap 'rmdir /tmp/chrome_screenshot_lock 2>/dev/null || true' EXIT

echo "[capture_screenshots] Capturing above-the-fold view -> ${OUT_DIR}/secops_control_tower_top.png"
"${CHROME_BIN}" \
  --headless=new \
  --disable-gpu \
  --no-sandbox \
  --hide-scrollbars \
  --virtual-time-budget=5000 \
  --window-size=1440,900 \
  --screenshot="${OUT_DIR}/secops_control_tower_top.png" \
  "${URL}"

sleep 1.5

echo "[capture_screenshots] Capturing full-page view -> ${OUT_DIR}/secops_control_tower_full.png"
"${CHROME_BIN}" \
  --headless=new \
  --disable-gpu \
  --no-sandbox \
  --hide-scrollbars \
  --virtual-time-budget=5000 \
  --window-size=1440,1780 \
  --screenshot="${OUT_DIR}/secops_control_tower_full.png" \
  "${URL}"

ls -lh "${OUT_DIR}/secops_control_tower_top.png" "${OUT_DIR}/secops_control_tower_full.png"
