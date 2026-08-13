#!/usr/bin/env bash
# ============================================================
# stop_all_clients.sh — Stop semua client RPi
# Cara pakai: bash scripts/stop_all_clients.sh
# ============================================================

NODES=(node-a node-b node-c node-d node-e node-f node-g)

echo "=============================================="
echo "  Stopping FedML Clients di semua RPi"
echo "=============================================="

for node in "${NODES[@]}"; do
    echo -n "  → $node ... "
    ssh -o ConnectTimeout=8 "$node" \
        "pkill python3 2>/dev/null && echo 'stopped' || echo 'tidak ada proses berjalan'"
done

echo "=============================================="
echo "  Selesai."
echo "=============================================="
