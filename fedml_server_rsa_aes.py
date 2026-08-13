#!/usr/bin/env python3
"""
FedML Server with MQTT Communication — SECURED (Thesis-Grade)
Federated Learning IDS - CICIoT2023 Dataset — TCMS IoT Security

Security Layers Implemented:
  [S1] Signcryption model (RSA-2048 + AES-256-GCM) — confidentiality + authenticity
  [S2] Tanda-tangan instruksi broadcast (RSA-PSS) — auth tanpa enkripsi
  [S3] Anti-replay: timestamp ≤10 detik + nonce satu-kali-pakai
  [S4] Validasi round number pada setiap model update
  [S5] Client whitelist — hanya client terdaftar yang diterima
  [S6] Batas ukuran payload (10 MB) — cegah DoS
  [S7] torch.load weights_only=True — cegah arbitrary code execution
  [S8] Metadata (timestamp, round, samples) di dalam payload terenkripsi
"""

import os
import sys
import ssl
import yaml
import time
import json
import base64
import io
import hashlib
import logging
import argparse
from pathlib import Path
from collections import defaultdict

import torch
import numpy as np
import paho.mqtt.client as mqtt

from model import get_model
from crypto.key_manager_rsa_aes import KeyManager
from crypto.signcryption import SigncryptionManager
from cryptography.exceptions import InvalidSignature

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== Konstanta Keamanan ====================
MAX_PAYLOAD_BYTES  = 10 * 1024 * 1024   # [S6] Batas 10 MB per payload
REPLAY_WINDOW_SEC  = 10                  # [S3] Jendela anti-replay 10 detik
NONCE_CLEANUP_SEC  = 60                  # Bersihkan nonce lama setiap 60 detik


class FedMLServer:
    def __init__(self, config_path='./fedml_config.yaml'):
        self.config = self.load_config(config_path)

        mqtt_cfg = self.load_mqtt_config()
        self.mqtt_host      = mqtt_cfg.get('BROKER_HOST', 'localhost')
        self.mqtt_port      = mqtt_cfg.get('BROKER_PORT', 1883)
        self.mqtt_keepalive = mqtt_cfg.get('MQTT_KEEPALIVE', 60)
        self.topic_prefix   = mqtt_cfg.get('TOPIC_PREFIX', 'fedml')
        self.use_tls        = mqtt_cfg.get('USE_TLS', False)
        self.ca_cert        = mqtt_cfg.get('CA_CERT', './certs/ca.crt')
        self.mqtt_user      = mqtt_cfg.get('MQTT_USER', '')
        self.mqtt_pwd       = mqtt_cfg.get('MQTT_PWD', '')

        # --- Keamanan ---
        logger.info("Menginisialisasi Manajer Kunci...")
        try:
            self.key_manager = KeyManager(base_dir="./keys")
            self.signcryption = SigncryptionManager()
            self.server_private_key, self.server_public_key = self.key_manager.load_server_keys()
            self.client_public_keys = self.load_all_client_public_keys()
            logger.info(f"✓ Kunci server dan {len(self.client_public_keys)} kunci klien dimuat.")
        except Exception as e:
            logger.error(f"✗ GAGAL inisialisasi keamanan: {e}")
            sys.exit(1)

        # [S5] Client whitelist: hanya client yang sudah punya kunci terdaftar
        self.allowed_clients = set(self.client_public_keys.keys())
        logger.info(f"[S5] Whitelist: {sorted(self.allowed_clients)}")

        # [S3] Nonce tracker: set of (nonce, client_id) yang sudah dipakai
        self._used_nonces: dict[str, float] = {}   # nonce → timestamp
        self._last_nonce_cleanup = time.time()

        # Training config
        self.min_clients        = self.config['train_args']['client_num_in_total']
        self.clients_per_round  = self.config['train_args']['client_num_per_round']
        self.num_rounds         = self.config['train_args']['comm_round']
        self.epochs             = self.config['train_args']['epochs']

        # Model
        self.model_type = self.config['model_args'].get('model_type', 'dnn').lower()
        self.global_model = get_model(
            model_type = self.model_type,
            input_dim  = self.config['model_args']['input_dim'],
            hidden_dim = self.config['model_args']['hidden_dim'],
            output_dim = self.config['model_args']['output_dim']
        )
        total_params = sum(p.numel() for p in self.global_model.parameters())
        logger.info(f"Model aktif : {self.model_type.upper()} ({self.global_model.__class__.__name__}) — {total_params:,} params")

        # State
        self.connected_clients  = {}
        self.current_round      = 0
        self.client_models      = {}
        self.client_metrics     = {}
        self.waiting_for_clients= set()
        self.round_in_progress  = False
        self.final_avg_test_acc = 0.0
        self.final_avg_test_loss= 0.0

        # Dashboard history & event feed — disimpan per model_type
        self.metrics_history: list = []
        self.history_file = f"metrics_history_{self.model_type}.json"

        # MQTT
        self.mqtt_client = mqtt.Client(client_id="fedml_server")
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        if self.mqtt_user:
            self.mqtt_client.username_pw_set(self.mqtt_user, self.mqtt_pwd)

        Path(self.config['tracking_args']['log_file_dir']).mkdir(exist_ok=True)
        self.state_file = "dashboard_state.json"
        self.print_header()
        self.update_dashboard_state("Server Started & Ready")

    # ==================== Config ====================
    def load_config(self, p):
        with open(p) as f: return yaml.safe_load(f)

    def load_mqtt_config(self):
        with open(self.config['comm_args']['mqtt_config_path']) as f:
            return yaml.safe_load(f)

    def load_all_client_public_keys(self):
        keys = {}
        for cid in self.key_manager.get_all_client_ids():
            try:
                keys[cid] = self.key_manager.load_client_public_key(cid)
            except Exception as e:
                logger.warning(f"Gagal muat kunci {cid}: {e}")
        return keys

    # ==================== Dashboard ====================
    def _pub_event(self, event_type: str, msg: str):
        """Publish a plain-text dashboard event to MQTT (no encryption — UI only)."""
        payload = json.dumps({
            "type":     event_type,
            "msg":      msg,
            "time_str": time.strftime("%H:%M:%S"),
            "timestamp": time.time()
        })
        try:
            self.mqtt_client.publish("fedml/dashboard/events", payload, qos=0)
        except Exception:
            pass

    def _write_metrics_history(self):
        """Persist per-round aggregated metrics to metrics_history_{model_type}.json (atomic)."""
        tmp = self.history_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.metrics_history, f)
        os.replace(tmp, self.history_file)

    def update_dashboard_state(self, last_event):
        if self.client_metrics:
            avg_acc  = np.mean([m['test_acc']         for m in self.client_metrics.values()])
            avg_loss = np.mean([m['test_loss']         for m in self.client_metrics.values()])
            avg_prec = np.mean([m.get('precision', 0)  for m in self.client_metrics.values()])
            avg_rec  = np.mean([m.get('recall', 0)     for m in self.client_metrics.values()])
            avg_f1   = np.mean([m.get('f1_score', 0)   for m in self.client_metrics.values()])
        else:
            avg_acc = avg_loss = avg_prec = avg_rec = avg_f1 = 0

        state = {
            "current_round":    self.current_round,
            "total_rounds":     self.num_rounds,
            "connected_clients":list(self.connected_clients),
            "waiting_for":      [c for c in self.connected_clients if c not in self.client_models],
            "metrics": {
                "test_acc":  avg_acc,  "test_loss": avg_loss,
                "precision": avg_prec, "recall":    avg_rec, "f1_score": avg_f1
            },
            "last_event": last_event,
            "timestamp":  time.time()
        }
        # Atomic write: tulis ke tmp lalu rename
        tmp = self.state_file + ".tmp"
        with open(tmp, "w") as f: json.dump(state, f)
        os.replace(tmp, self.state_file)

    def print_header(self):
        logger.info("=" * 70)
        logger.info("   FEDML SERVER — FL-IDS TCMS (SECURED, Thesis-Grade)")
        logger.info("=" * 70)
        logger.info(f"  Anti-replay window : {REPLAY_WINDOW_SEC}s")
        logger.info(f"  Max payload        : {MAX_PAYLOAD_BYTES//1024//1024} MB")
        logger.info(f"  TLS                : {'AKTIF' if self.use_tls else 'TIDAK AKTIF ⚠️'}")
        logger.info(f"  Metrics file       : {self.history_file}")
        logger.info("=" * 70)

    # ==================== Nonce Management [S3] ====================
    def _cleanup_nonces(self):
        now = time.time()
        if now - self._last_nonce_cleanup < NONCE_CLEANUP_SEC:
            return
        expired = [n for n, ts in self._used_nonces.items() if now - ts > NONCE_CLEANUP_SEC]
        for n in expired:
            del self._used_nonces[n]
        self._last_nonce_cleanup = now

    def _check_and_consume_nonce(self, nonce: str, timestamp: float) -> bool:
        """Kembalikan True jika nonce valid (belum pernah dipakai dan masih dalam window)."""
        self._cleanup_nonces()
        now = time.time()
        # Cek timestamp window
        if abs(now - timestamp) > REPLAY_WINDOW_SEC:
            return False
        # Cek nonce belum pernah dipakai
        if nonce in self._used_nonces:
            return False
        # Konsumsi nonce
        self._used_nonces[nonce] = now
        return True

    # ==================== MQTT ====================
    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("✓ Connected to MQTT Broker")
            topics = [
                (f"{self.topic_prefix}/client/+/register", 1),
                (f"{self.topic_prefix}/client/+/model",    1),
                (f"{self.topic_prefix}/client/+/metrics",  1),
                (f"{self.topic_prefix}/client/+/ready",    1),
                (f"{self.topic_prefix}/client/+/status",   1),
            ]
            for t, q in topics: client.subscribe(t, q)
        else:
            logger.error(f"MQTT connection failed: rc={rc}")

    def on_message(self, client, userdata, msg):
        try:
            # [S6] Tolak payload terlalu besar
            if len(msg.payload) > MAX_PAYLOAD_BYTES:
                logger.warning(f"⚠️ Payload terlalu besar dari {msg.topic}: {len(msg.payload)} bytes")
                return

            parts = msg.topic.split('/')
            if len(parts) < 4: return
            client_id, msg_type = parts[2], parts[3]

            if   msg_type == "register": self.handle_client_register(client_id, msg.payload)
            elif msg_type == "model":    self.handle_client_model(client_id, msg.payload)
            elif msg_type == "metrics":  self.handle_client_metrics(client_id, msg.payload)
            elif msg_type == "ready":    self.handle_client_ready(client_id, msg.payload)
            elif msg_type == "status":   self.handle_client_status(client_id, msg.payload)
        except Exception as e:
            logger.error(f"Error on {msg.topic}: {e}")

    # ==================== Handlers ====================
    def handle_client_register(self, client_id, payload):
        # [S5] Tolak client yang tidak ada di whitelist
        if client_id not in self.allowed_clients:
            logger.warning(f"🚫 REJECTED: {client_id} tidak ada di whitelist!")
            self._pub_event("S5_REJECT", f"[S5] REJECTED unknown client: {client_id}")
            return

        data = json.loads(payload.decode())
        self.connected_clients[client_id] = data
        logger.info(f"📡 Client {client_id} registered")
        self._pub_event("REGISTER", f"{client_id} joined ({len(self.connected_clients)}/{self.min_clients} ready)")
        self.update_dashboard_state(f"Client {client_id} Joined")
        self.send_global_model(client_id)

    def handle_client_ready(self, client_id, payload):
        if client_id not in self.allowed_clients: return
        logger.info(f"✓ Client {client_id} is ready")
        if len(self.connected_clients) >= self.min_clients and not self.round_in_progress:
            self.start_new_round()

    def handle_client_model(self, client_id, payload):
        """
        [S1] Unsigncrypt model update
        [S3] Verifikasi timestamp + nonce (anti-replay ketat)
        [S4] Validasi round number
        [S5] Verifikasi client ada di whitelist
        [S7] torch.load weights_only=True
        """
        # [S5]
        if client_id not in self.allowed_clients:
            logger.warning(f"🚫 Model dari client tidak dikenal: {client_id}")
            return

        sender_pub = self.client_public_keys.get(client_id)
        if sender_pub is None:
            logger.error(f"✗ Public key {client_id} tidak ditemukan, tolak.")
            return

        try:
            package = json.loads(payload.decode())

            # [S1] Dekripsi + verifikasi signature
            payload_bytes = self.signcryption.unsigncrypt(
                package=package,
                receiver_private_key=self.server_private_key,
                sender_public_key=sender_pub
            )

            inner       = json.loads(payload_bytes.decode())
            timestamp   = inner['timestamp']
            nonce       = inner['nonce']
            round_num   = inner['round']
            num_samples = inner['num_samples']
            weights_b64 = inner['weights_b64']

            # [S3] Anti-replay: cek timestamp + nonce satu-kali-pakai
            if not self._check_and_consume_nonce(nonce, timestamp):
                logger.warning(
                    f"⚠️ REPLAY/STALE from {client_id} "
                    f"(age={time.time()-timestamp:.1f}s, nonce={'reused' if nonce in self._used_nonces else 'expired'})"
                )
                self._pub_event("S3_REJECT", f"[S3] REPLAY blocked from {client_id}")
                return

            # [S4] Validasi round number
            if round_num != self.current_round:
                logger.warning(
                    f"⚠️ Round mismatch dari {client_id}: "
                    f"diterima round={round_num}, expected={self.current_round}"
                )
                self._pub_event("S4_REJECT", f"[S4] Round mismatch from {client_id} (got {round_num}, expected {self.current_round})")
                return

            # [S7] Deserialisi aman
            weights_bytes = base64.b64decode(weights_b64)
            buf    = io.BytesIO(weights_bytes)
            weights = torch.load(buf, map_location='cpu', weights_only=True)

            # Validasi arsitektur: pastikan kunci bobot sesuai dengan model aktif
            expected_keys = set(self.global_model.state_dict().keys())
            received_keys = set(weights.keys())
            if received_keys != expected_keys:
                logger.warning(
                    f"⚠️ ARSITEKTUR TIDAK COCOK dari {client_id} "
                    f"(model_type={self.model_type}) — DITOLAK. "
                    f"Diterima: {sorted(received_keys)[:3]}... "
                    f"Diharapkan: {sorted(expected_keys)[:3]}..."
                )
                self._pub_event("ARCH_REJECT", f"[ARCH] {client_id} kirim bobot {len(received_keys)} keys, expected {len(expected_keys)} — DITOLAK")
                self.waiting_for_clients.discard(client_id)
                if len(self.waiting_for_clients) == 0 and self.client_models:
                    self.aggregate_models()
                return

            self.client_models[client_id] = {
                'weights':     {k: v.numpy() for k, v in weights.items()},
                'num_samples': num_samples,
                'round':       round_num
            }

            logger.info(f"📥 ✓ Model verified: {client_id} | round={round_num} | samples={num_samples}")
            self._pub_event("S1_OK", f"[S1] Unsigncrypt OK — {client_id} round={round_num} samples={num_samples}")
            self.update_dashboard_state(f"Received Model: {client_id}")
            self.waiting_for_clients.discard(client_id)

            if len(self.waiting_for_clients) == 0:
                self.aggregate_models()

        except InvalidSignature:
            logger.error(f"🚨 SECURITY ALERT: Signature tidak valid dari {client_id}!")
            self._pub_event("S1_FAIL", f"[S1] INVALID SIGNATURE from {client_id} — DROPPED")
        except (KeyError, json.JSONDecodeError) as e:
            logger.error(f"✗ Format payload salah dari {client_id}: {e}")
        except Exception as e:
            logger.error(f"✗ Error proses model dari {client_id}: {e}")

    def handle_client_metrics(self, client_id, payload):
        """[S1] Metrics diterima terenkripsi + diverifikasi."""
        if client_id not in self.allowed_clients: return
        sender_pub = self.client_public_keys.get(client_id)
        if not sender_pub: return
        try:
            package = json.loads(payload.decode())
            pb = self.signcryption.unsigncrypt(package, self.server_private_key, sender_pub)
            data = json.loads(pb.decode())

            # Sanity check nilai metrik
            if not (0 <= data.get('test_acc', -1) <= 100):
                logger.warning(f"⚠️ Nilai test_acc tidak wajar dari {client_id}: {data.get('test_acc')}")
                return
            if data.get('test_loss', -1) < 0:
                logger.warning(f"⚠️ Nilai test_loss negatif dari {client_id}: {data.get('test_loss')}")
                return

            self.client_metrics[client_id] = data
            logger.info(f"📊 Metrics {client_id}: acc={data.get('test_acc',0):.2f}% f1={data.get('f1_score',0):.2f}%")
        except InvalidSignature:
            logger.error(f"🚨 Metrics signature tidak valid dari {client_id}!")
            self._pub_event("S1_FAIL", f"[S1] Metrics signature INVALID from {client_id}")
        except Exception as e:
            logger.error(f"✗ Metrics error dari {client_id}: {e}")

    def handle_client_status(self, client_id, payload):
        """Status disconnect dari client — tidak perlu enkripsi, hanya state update."""
        if client_id not in self.connected_clients: return
        try:
            data = json.loads(payload.decode())
            if data.get('status') == 'disconnected':
                del self.connected_clients[client_id]
                self.waiting_for_clients.discard(client_id)
                self.update_dashboard_state(f"Client {client_id} Left")
                logger.info(f"Client {client_id} disconnected")
        except Exception:
            pass

    # ==================== Model Operations ====================
    def aggregate_models(self):
        """[S4] Hanya agregasi model dari round yang benar."""
        valid_models = {
            cid: m for cid, m in self.client_models.items()
            if m.get('round') == self.current_round
        }

        if len(valid_models) < len(self.client_models):
            stale = set(self.client_models) - set(valid_models)
            logger.warning(f"⚠️ Mengabaikan model stale dari: {stale}")

        if not valid_models:
            logger.error("✗ Tidak ada model valid untuk diagregasi!")
            return

        total_samples = sum(m['num_samples'] for m in valid_models.values())
        if total_samples == 0: return

        logger.info(f"AGGREGATING — Round {self.current_round}, {len(valid_models)} clients")
        aggregated = {}
        for m in valid_models.values():
            w = m['num_samples'] / total_samples
            for key, val in m['weights'].items():
                if key not in aggregated:
                    aggregated[key] = np.zeros_like(val)
                aggregated[key] += w * val

        self.global_model.load_state_dict(
            {k: torch.from_numpy(v) for k, v in aggregated.items()}
        )

        if self.client_metrics:
            self.final_avg_test_acc  = np.mean([m.get('test_acc',0)  for m in self.client_metrics.values()])
            self.final_avg_test_loss = np.mean([m.get('test_loss',0) for m in self.client_metrics.values()])
            avg_prec = np.mean([m.get('precision', 0) for m in self.client_metrics.values()])
            avg_rec  = np.mean([m.get('recall', 0)    for m in self.client_metrics.values()])
            avg_f1   = np.mean([m.get('f1_score', 0)  for m in self.client_metrics.values()])

            # Append round record to history
            self.metrics_history.append({
                "round":      self.current_round,
                "test_acc":   float(self.final_avg_test_acc),
                "test_loss":  float(self.final_avg_test_loss),
                "precision":  float(avg_prec),
                "recall":     float(avg_rec),
                "f1_score":   float(avg_f1),
                "per_client": {
                    cid: {
                        "test_acc":  float(m.get('test_acc',  0)),
                        "test_loss": float(m.get('test_loss', 0)),
                        "f1_score":  float(m.get('f1_score',  0)),
                    }
                    for cid, m in self.client_metrics.items()
                },
                "num_clients": len(valid_models),
                "timestamp":  time.time()
            })
            self._write_metrics_history()
            self._pub_event("ROUND", f"Round {self.current_round} complete — acc={self.final_avg_test_acc:.2f}% f1={avg_f1:.2f}%")

        self.update_dashboard_state(f"Round {self.current_round} Complete ✓")
        self.send_global_model()
        self.start_next_round_or_finish()

    def send_global_model(self, client_id=None):
        """[S1][S3][S8] Kirim model terenkripsi+ditandatangani ke client."""
        state_dict = self.global_model.state_dict()
        buf = io.BytesIO()
        torch.save(state_dict, buf)
        weights_bytes = buf.getvalue()

        inner = {
            'weights_b64': base64.b64encode(weights_bytes).decode(),
            'round':       self.current_round,
            'timestamp':   time.time(),
            'nonce':       base64.b64encode(os.urandom(16)).decode()
        }
        payload_bytes = json.dumps(inner).encode()

        targets = [client_id] if client_id else list(self.connected_clients)
        for target in targets:
            pub = self.client_public_keys.get(target)
            if not pub: continue
            try:
                package = self.signcryption.signcrypt(payload_bytes, self.server_private_key, pub)
                self.mqtt_client.publish(
                    f"{self.topic_prefix}/server/model/{target}",
                    json.dumps(package), qos=1
                )
            except Exception as e:
                logger.error(f"Gagal kirim model ke {target}: {e}")

    def start_new_round(self):
        """[S2] Instruksi training di-sign dengan private key server."""
        self.current_round += 1
        self.round_in_progress = True
        self.waiting_for_clients = set(self.connected_clients)
        self.client_models, self.client_metrics = {}, {}

        logger.info(f"\n{'='*50}")
        logger.info(f"  ROUND {self.current_round}/{self.num_rounds} START")
        logger.info(f"{'='*50}")
        self._pub_event("ROUND_START", f"Round {self.current_round}/{self.num_rounds} started — {len(self.connected_clients)} nodes")

        nonce = base64.b64encode(os.urandom(16)).decode()
        msg = {
            'round':     self.current_round,
            'action':    'train',
            'epochs':    self.epochs,
            'timestamp': time.time(),
            'nonce':     nonce
        }
        # [S2] Tanda-tangani instruksi (bukan enkripsi karena broadcast)
        msg_bytes = json.dumps(msg, sort_keys=True).encode()
        msg['signature'] = self.signcryption.sign(msg_bytes, self.server_private_key)

        self.mqtt_client.publish(
            f"{self.topic_prefix}/server/instruction",
            json.dumps(msg), qos=1
        )
        self.update_dashboard_state(f"Starting Round {self.current_round}")

    def start_next_round_or_finish(self):
        if self.current_round >= self.num_rounds:
            self.finish_training()
        else:
            self.round_in_progress = False
            time.sleep(3)
            self.start_new_round()

    def finish_training(self):
        logger.info("✓ FL TRAINING COMPLETE!")
        self._pub_event("COMPLETE", f"FL Training COMPLETE — {self.num_rounds} rounds, final acc={self.final_avg_test_acc:.2f}%")
        nonce = base64.b64encode(os.urandom(16)).decode()
        msg = {'action': 'complete', 'timestamp': time.time(), 'nonce': nonce}
        msg_bytes = json.dumps(msg, sort_keys=True).encode()
        msg['signature'] = self.signcryption.sign(msg_bytes, self.server_private_key)
        self.mqtt_client.publish(
            f"{self.topic_prefix}/server/instruction", json.dumps(msg), qos=1
        )
        self.update_dashboard_state("Training Finished ✓")
        model_filename = f'./final_global_model_{self.model_type}.pth'
        torch.save(self.global_model.state_dict(), model_filename)
        logger.info(f"✓ Global model saved: {model_filename}")
        time.sleep(5)
        self.mqtt_client.disconnect()

    def run(self):
        if self.use_tls:
            logger.info(f"Mengaktifkan TLS (CA: {self.ca_cert})")
            self.mqtt_client.tls_set(ca_certs=self.ca_cert, tls_version=ssl.PROTOCOL_TLS_CLIENT)

        logger.info(f"Connecting to MQTT {self.mqtt_host}:{self.mqtt_port} ...")
        self.mqtt_client.connect(self.mqtt_host, self.mqtt_port, self.mqtt_keepalive)
        self.mqtt_client.loop_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='./fedml_config.yaml')
    args = parser.parse_args()
    FedMLServer(config_path=args.config).run()
