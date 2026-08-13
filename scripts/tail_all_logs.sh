#!/usr/bin/env bash
# ============================================================
# tail_all_logs.sh — Pantau log semua RPi secara real-time
# Cara pakai: bash scripts/tail_all_logs.sh
# Ctrl+C untuk berhenti.
# ============================================================

NODES=(node-a node-b node-c node-d node-e node-f node-g)

echo "Memantau log semua node... (Ctrl+C untuk berhenti)"
echo "----------------------------------------------"

for node in "${NODES[@]}"; do
    DIR="/home/${node}/fedml-mija"
    ssh -o ConnectTimeout=8 "$node" \
        "tail -f $DIR/logs/client_latest.log 2>/dev/null || echo '[$node] log belum tersedia'" \
        | sed "s/^/[${node}] /" &
done

# Tunggu semua background SSH
trap "kill 0" SIGINT SIGTERM
wait
