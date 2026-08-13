#!/usr/bin/env bash
# ============================================================
# start_all_clients.sh — Start semua 7 client RPi dari server
# Cara pakai: bash scripts/start_all_clients.sh
# Jalankan SETELAH run_server.sh sudah berjalan.
# ============================================================

NODES=(node-a node-b node-c node-d node-e node-f node-g)
FAILED=()

echo "=============================================="
echo "  Starting FedML Clients di semua RPi"
echo "=============================================="

for node in "${NODES[@]}"; do
    echo -n "  → $node ... "
    DIR="/home/${node}/fedml-mija"
    if ssh -o ConnectTimeout=8 "$node" "pkill python3 2>/dev/null; sleep 1; mkdir -p $DIR/logs; nohup bash $DIR/scripts/run_client.sh </dev/null > $DIR/logs/client_latest.log 2>&1 & disown; echo ok"; then
        echo "✓ started"
    else
        echo "✗ GAGAL"
        FAILED+=("$node")
    fi
done

echo "=============================================="
if [ ${#FAILED[@]} -eq 0 ]; then
    echo "  Semua client berhasil distart (${#NODES[@]}/${#NODES[@]})"
else
    echo "  ⚠ Gagal: ${FAILED[*]}"
fi
echo ""
echo "  Monitor log semua node:"
echo "    bash scripts/tail_all_logs.sh"
echo ""
echo "  Stop semua client:"
echo "    bash scripts/stop_all_clients.sh"
echo "=============================================="
