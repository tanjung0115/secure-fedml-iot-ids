#!/bin/bash
# =============================================================================
# Generate Self-Signed TLS Certificates untuk MQTT Broker (Mosquitto)
# [Fix 3] MQTT TLS Security
#
# Menghasilkan:
#   certs/ca.key        - CA private key
#   certs/ca.crt        - CA certificate (perlu di-copy ke semua Raspberry Pi)
#   certs/server.key    - Broker server private key
#   certs/server.crt    - Broker server certificate
#
# Penggunaan:
#   bash scripts/generate_certs.sh
#
# Setelah generate, konfigurasikan Mosquitto broker:
#   listener 8883
#   cafile   /path/to/certs/ca.crt
#   certfile /path/to/certs/server.crt
#   keyfile  /path/to/certs/server.key
#   require_certificate false   # client hanya verifikasi server cert
#
# Kemudian salin ca.crt ke semua Raspberry Pi di folder ./certs/ca.crt
# dan set USE_TLS: true + BROKER_PORT: 8883 di mqtt_config.yaml
# =============================================================================

set -e

CERT_DIR="./certs"
BROKER_IP="${1:-127.0.0.1}"   # Argumen pertama = IP/hostname broker
DAYS_VALID=3650                    # 10 tahun
KEY_SIZE=2048

echo "============================================================"
echo "  Generate MQTT TLS Certificates"
echo "  Broker IP : ${BROKER_IP}"
echo "  Output    : ${CERT_DIR}/"
echo "============================================================"

mkdir -p "${CERT_DIR}"

# ----- 1. Generate CA (Certificate Authority) -----
echo ""
echo "[1/3] Generating CA key and certificate..."
openssl genrsa -out "${CERT_DIR}/ca.key" ${KEY_SIZE}
openssl req -new -x509 -days ${DAYS_VALID} \
    -key "${CERT_DIR}/ca.key" \
    -out "${CERT_DIR}/ca.crt" \
    -subj "/C=ID/ST=Indonesia/L=Bandung/O=FedML-IDS/OU=Research/CN=FedML-CA"

echo "✓ CA certificate generated: ${CERT_DIR}/ca.crt"

# ----- 2. Generate Server (Broker) Certificate -----
echo ""
echo "[2/3] Generating server key and certificate..."
openssl genrsa -out "${CERT_DIR}/server.key" ${KEY_SIZE}
openssl req -new \
    -key "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.csr" \
    -subj "/C=ID/ST=Indonesia/L=Bandung/O=FedML-IDS/OU=Broker/CN=${BROKER_IP}"

# Sign server cert dengan CA, tambahkan SAN untuk IP
cat > "${CERT_DIR}/server_ext.cnf" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = IP:${BROKER_IP},IP:127.0.0.1
EOF

openssl x509 -req -days ${DAYS_VALID} \
    -in  "${CERT_DIR}/server.csr" \
    -CA  "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/server.crt" \
    -extfile "${CERT_DIR}/server_ext.cnf" \
    -extensions v3_req

echo "✓ Server certificate generated: ${CERT_DIR}/server.crt"

# ----- 3. Set permissions -----
echo ""
echo "[3/3] Setting permissions..."
chmod 600 "${CERT_DIR}/ca.key" "${CERT_DIR}/server.key"
chmod 644 "${CERT_DIR}/ca.crt" "${CERT_DIR}/server.crt"
rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/server_ext.cnf"

echo ""
echo "============================================================"
echo "  SELESAI! File yang dihasilkan:"
echo "    ${CERT_DIR}/ca.crt     ← Copy ke semua Raspberry Pi"
echo "    ${CERT_DIR}/server.crt ← Untuk Mosquitto broker"
echo "    ${CERT_DIR}/server.key ← Untuk Mosquitto broker (RAHASIA)"
echo ""
echo "  Langkah berikutnya:"
echo "  1. Salin ca.crt ke tiap RPi di folder ./certs/ca.crt"
echo "  2. Konfigurasi Mosquitto:"
echo "       listener 8883"
echo "       cafile   $(realpath ${CERT_DIR}/ca.crt)"
echo "       certfile $(realpath ${CERT_DIR}/server.crt)"
echo "       keyfile  $(realpath ${CERT_DIR}/server.key)"
echo "  3. Edit mqtt_config.yaml:"
echo "       BROKER_PORT: 8883"
echo "       USE_TLS: true"
echo "       CA_CERT: './certs/ca.crt'"
echo "============================================================"
