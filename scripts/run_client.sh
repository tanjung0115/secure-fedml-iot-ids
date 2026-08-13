#!/usr/bin/env bash
# ============================================================
# run_client.sh — Jalankan FedML Client (auto-detect node)
# Cara pakai: bash scripts/run_client.sh
# Script ini di-copy ke setiap RPi dan langsung bisa jalan
# tanpa perlu tahu client_id — otomatis detect dari username
# (whoami), karena username di tiap RPi = node-a/b/c/...
# ============================================================
set -e
cd "/home/$(whoami)/fedml-mija"

# ----- Mapping username → client_id -----
# Pakai whoami (bukan hostname) karena hostname RPi = "raspberrypi"
# tapi username sudah unik: node-a, node-b, ... node-g
declare -A CLIENT_MAP=(
    [node-a]="rpi_client1"
    [node-b]="rpi_client2"
    [node-c]="rpi_client3"
    [node-d]="rpi_client4"
    [node-e]="rpi_client5"
    [node-f]="rpi_client6"
    [node-g]="rpi_client7"
)

# ----- Mapping username → python venv (node-f pakai fl_env) -----
declare -A PYTHON_MAP=(
    [node-f]="/home/node-f/fl_env/bin/python3"
)

NODE_USER=$(whoami)
CLIENT_ID="${CLIENT_MAP[$NODE_USER]}"
PYTHON="${PYTHON_MAP[$NODE_USER]:-$HOME/flenv/bin/python3}"

if [ -z "$CLIENT_ID" ]; then
    echo "ERROR: User '$NODE_USER' tidak dikenal di CLIENT_MAP." >&2
    echo "       Tambahkan entry di scripts/run_client.sh jika ini node baru." >&2
    exit 1
fi

mkdir -p logs
LOG_FILE="logs/client_${CLIENT_ID}_$(date +%Y%m%d_%H%M%S).log"

echo "=============================================="
echo "  FedML Client — RSA+AES Signcryption"
echo "=============================================="
echo "  User      : $NODE_USER"
echo "  Client ID : $CLIENT_ID"
echo "  Python    : $PYTHON"
echo "  Log       : $LOG_FILE"
echo "=============================================="

exec "$PYTHON" fedml_client_rsa_aes.py \
    --client_id "$CLIENT_ID" \
    --config ./fedml_config.yaml \
    2>&1 | tee "$LOG_FILE"
