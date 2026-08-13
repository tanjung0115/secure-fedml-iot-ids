#!/usr/bin/env bash
# ============================================================
# run_server.sh — Jalankan FedML Server
# Cara pakai: bash scripts/run_server.sh
# ============================================================
set -e
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/server_$(date +%Y%m%d_%H%M%S).log"

echo "=============================================="
echo "  FedML Server — RSA+AES Signcryption"
echo "=============================================="
echo "  Python : $PYTHON"
echo "  Config : ./fedml_config.yaml"
echo "  Log    : $LOG_FILE"
echo "=============================================="

exec "$PYTHON" fedml_server_rsa_aes.py --config ./fedml_config.yaml \
    2>&1 | tee "$LOG_FILE"
