#!/usr/bin/env python3
"""
FedML Client with MQTT Communication — SECURED (Thesis-Grade)
Federated Learning IDS - CICIoT2023 Dataset — TCMS IoT Security

Security Layers:
  [S1] Signcryption model (RSA-2048 + AES-256-GCM)
  [S2] Verifikasi tanda-tangan instruksi server (RSA-PSS)
  [S3] Anti-replay: timestamp + nonce satu-kali-pakai
  [S4] Validasi round number pada global model
  [S6] Batas ukuran payload
  [S7] torch.load weights_only=True
  [S8] Metadata di dalam payload terenkripsi
"""

import os
import sys
import ssl
import yaml
import time
import json
import base64
import io
import logging
import argparse
from pathlib import Path

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

import numpy as np
import pandas as pd
import paho.mqtt.client as mqtt

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    psutil = None
    _PSUTIL_OK = False

from model import get_model
from crypto.signcryption import SigncryptionManager
from cryptography.exceptions import InvalidSignature

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES = 10 * 1024 * 1024   # [S6] 10 MB
REPLAY_WINDOW_SEC = 10                  # [S3] 10 detik


class FedMLClient:
    def __init__(self, client_id, config_path='./fedml_config.yaml'):
        self.client_id = client_id

        self.config      = self.load_config(config_path)
        self.mqtt_config = self.load_mqtt_config()

        self.mqtt_host      = self.mqtt_config.get('BROKER_HOST', 'localhost')
        self.mqtt_port      = self.mqtt_config.get('BROKER_PORT', 1883)
        self.mqtt_keepalive = self.mqtt_config.get('MQTT_KEEPALIVE', 60)
        self.topic_prefix   = self.mqtt_config.get('TOPIC_PREFIX', 'fedml')
        self.use_tls        = self.mqtt_config.get('USE_TLS', False)
        self.ca_cert        = self.mqtt_config.get('CA_CERT', './certs/ca.crt')
        self.mqtt_user      = self.mqtt_config.get('MQTT_USER', '')
        self.mqtt_pwd       = self.mqtt_config.get('MQTT_PWD', '')

        self.setup_security()

        self.batch_size   = self.config['train_args']['batch_size']
        self.lr           = self.config['train_args']['learning_rate']
        self.weight_decay = self.config['train_args']['weight_decay']
        self.input_dim    = self.config['model_args']['input_dim']
        self.output_dim   = self.config['model_args']['output_dim']
        hidden_dim        = self.config['model_args']['hidden_dim']
        self.model_type   = self.config['model_args'].get('model_type', 'dnn').lower()

        self.device = torch.device('cpu')
        self.model  = get_model(self.model_type, self.input_dim, hidden_dim, self.output_dim)
        self.model.to(self.device)
        total_params = sum(p.numel() for p in self.model.parameters())
        logger.info(f"Model aktif : {self.model_type.upper()} ({self.model.__class__.__name__}) — {total_params:,} params")

        self.train_loader      = None
        self.test_loader       = None
        self.num_train_samples = 0
        self.current_round     = 0
        self.is_training       = False

        # [S3] Nonce tracker untuk instruksi dari server
        self._used_instruction_nonces: set = set()

        # Telemetry
        self._telemetry_stop = False

        self.mqtt_client = mqtt.Client(client_id=f"fedml_{client_id}")
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        if self.mqtt_user:
            self.mqtt_client.username_pw_set(self.mqtt_user, self.mqtt_pwd)

        self.print_header()

    def load_config(self, p):
        with open(p) as f: return yaml.safe_load(f)

    def load_mqtt_config(self):
        with open(self.config['comm_args']['mqtt_config_path']) as f:
            return yaml.safe_load(f)

    def setup_security(self):
        logger.info("Menginisialisasi Keamanan (RSA+AES)...")
        try:
            self.signcryption = SigncryptionManager()
            key_dir = Path("./keys")
            self.client_private_key = self.signcryption.load_private_key(key_dir / "client_private.pem")
            self.server_public_key  = self.signcryption.load_public_key(key_dir / "server_public.pem")
            logger.info("✓ Kunci Kriptografi Siap.")
        except Exception as e:
            logger.error(f"✗ GAGAL Load Kunci: {e}")
            sys.exit(1)

    def print_header(self):
        logger.info("=" * 60)
        logger.info(f"   CLIENT: {self.client_id} — FL-IDS TCMS")
        logger.info("=" * 60)
        logger.info(f"  Broker : {self.mqtt_host}:{self.mqtt_port}")
        logger.info(f"  TLS    : {'AKTIF' if self.use_tls else 'TIDAK AKTIF ⚠️'}")
        logger.info(f"  Input  : {self.input_dim} features → {self.output_dim} classes")
        logger.info(f"  Model  : {self.model_type.upper()}")
        logger.info("=" * 60)

    # ==================== Data Loading ====================
    def load_global_metadata(self):
        data_dir = Path(self.config['data_args']['data_cache_dir'])
        try:
            with open(data_dir / "label_map.json") as f:
                self.label_map = json.load(f)
            logger.info(f"✓ Label Map: {len(self.label_map)} classes")
        except FileNotFoundError:
            logger.error("✗ label_map.json tidak ditemukan!"); sys.exit(1)
        try:
            with open(data_dir / "scaler_params.json") as f:
                sp = json.load(f)
            self.global_mean  = np.array(sp['mean'],  dtype=np.float32)
            self.global_scale = np.array(sp['scale'], dtype=np.float32)
            logger.info("✓ Scaler Params loaded.")
        except FileNotFoundError:
            logger.error("✗ scaler_params.json tidak ditemukan!"); sys.exit(1)

    def load_data(self):
        logger.info("\n[1/3] Loading Data...")
        data_dir  = Path(self.config['data_args']['data_cache_dir'])
        dist_type = self.config['data_args'].get('data_distribution', 'iid')
        filename  = "non_iid_train.csv" if dist_type == 'noniid' else "iid_train.csv"
        file_path = data_dir / filename

        if not file_path.exists():
            for fb in ["data_non_iid.csv", "data_iid.csv", "data_train.csv"]:
                if (data_dir / fb).exists():
                    logger.warning(f"Fallback ke '{fb}'")
                    file_path = data_dir / fb; break
            else:
                logger.error(f"✗ Data tidak ditemukan: {file_path}"); sys.exit(1)

        try:
            df = pd.read_csv(file_path)
            X  = df.drop(columns=['label']).values.astype(np.float32)
            y  = df['label'].values.astype(np.int64)
            # Data CSV sudah pre-normalized (z-score) oleh pipeline preprocessing.
            # JANGAN normalisasi ulang — double normalization merusak fitur → akurasi drop.

            if y.max() >= self.output_dim:
                logger.error(f"✗ Label {y.max()} >= output_dim={self.output_dim}"); sys.exit(1)

            X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
            self.train_dataset     = TensorDataset(torch.from_numpy(X_tr), torch.from_numpy(y_tr))
            self.test_dataset      = TensorDataset(torch.from_numpy(X_te), torch.from_numpy(y_te))
            self.num_train_samples = len(self.train_dataset)
            self.train_loader = DataLoader(self.train_dataset, batch_size=self.batch_size, shuffle=True)
            self.test_loader  = DataLoader(self.test_dataset,  batch_size=self.batch_size)
            logger.info(f"✓ Data: {self.num_train_samples} train, {len(self.test_dataset)} test ({file_path.name})")
        except Exception as e:
            logger.error(f"Error load data: {e}"); sys.exit(1)

    # ==================== MQTT ====================
    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("✓ Connected to MQTT Broker")
            client.subscribe(f"{self.topic_prefix}/server/instruction", 1)
            client.subscribe(f"{self.topic_prefix}/server/model/{self.client_id}", 1)
            self.register_with_server()
        else:
            logger.error(f"Connection Failed: rc={rc}")

    def on_message(self, client, userdata, msg):
        try:
            # [S6]
            if len(msg.payload) > MAX_PAYLOAD_BYTES:
                logger.warning(f"⚠️ Payload terlalu besar: {len(msg.payload)} bytes")
                return
            if "instruction" in msg.topic:
                self.handle_instruction(msg.payload)
            elif "model" in msg.topic:
                self.handle_global_model(msg.payload)
        except Exception as e:
            logger.error(f"Msg Error: {e}")

    def register_with_server(self):
        msg = {'client_id': self.client_id, 'status': 'online', 'timestamp': time.time()}
        self.mqtt_client.publish(f"{self.topic_prefix}/client/{self.client_id}/register", json.dumps(msg), qos=1)
        logger.info("📡 Registered.")
        time.sleep(1)
        self.mqtt_client.publish(f"{self.topic_prefix}/client/{self.client_id}/ready", json.dumps(msg), qos=1)

    def handle_instruction(self, payload):
        """
        [S2] Verifikasi tanda-tangan server sebelum menjalankan instruksi.
        [S3] Cek timestamp + nonce satu-kali-pakai.
        """
        try:
            msg = json.loads(payload.decode())
        except Exception:
            logger.error("✗ Instruksi tidak dapat di-parse"); return

        # [S2] Ekstrak dan verifikasi signature
        signature = msg.pop('signature', None)
        if signature is None:
            logger.critical("🚨 INSTRUKSI TANPA SIGNATURE — DITOLAK!")
            return

        # Rekonstruksi bytes yang ditanda-tangani (sort_keys=True harus sama dengan server)
        msg_bytes = json.dumps(msg, sort_keys=True).encode()
        if not self.signcryption.verify_signature(msg_bytes, signature, self.server_public_key):
            logger.critical("🚨 SIGNATURE INSTRUKSI TIDAK VALID — DITOLAK!")
            return

        # [S3] Cek timestamp
        ts    = msg.get('timestamp', 0)
        nonce = msg.get('nonce', '')
        if abs(time.time() - ts) > REPLAY_WINDOW_SEC:
            logger.warning(f"⚠️ Instruksi kedaluwarsa (age={time.time()-ts:.1f}s) — DITOLAK")
            return
        if nonce in self._used_instruction_nonces:
            logger.warning("⚠️ Instruksi dengan nonce yang sudah dipakai — DITOLAK")
            return
        self._used_instruction_nonces.add(nonce)

        action = msg.get('action')
        if action == 'train' and not self.is_training:
            round_num = msg.get('round')
            epochs    = msg.get('epochs', 1)
            logger.info(f"\n✓ Instruksi terverifikasi: TRAIN Round {round_num} ({epochs} epochs)")
            self.current_round = round_num
            self.train_local_model(epochs)
        elif action in ('stop', 'complete'):
            logger.info("✓ Instruksi terverifikasi: STOP/COMPLETE")
            self.mqtt_client.disconnect()
        else:
            logger.warning(f"Instruksi tidak dikenal: {action}")

    def handle_global_model(self, payload):
        """[S1][S4][S7] Unsigncrypt, validasi round, load model."""
        try:
            package = json.loads(payload.decode())
            pb = self.signcryption.unsigncrypt(
                package=package,
                receiver_private_key=self.client_private_key,
                sender_public_key=self.server_public_key
            )
            inner       = json.loads(pb.decode())
            round_num   = inner.get('round', '?')
            weights_b64 = inner['weights_b64']

            # [S4] Validasi round
            if isinstance(round_num, int) and round_num < self.current_round:
                logger.warning(f"⚠️ Global model stale (round={round_num} < current={self.current_round}) — DITOLAK")
                return

            # [S7]
            buf = io.BytesIO(base64.b64decode(weights_b64))
            self.model.load_state_dict(torch.load(buf, map_location='cpu', weights_only=True))
            logger.info(f"📥 Global Model Updated (Round {round_num}) ✓")
        except InvalidSignature:
            logger.critical("🚨 GLOBAL MODEL SIGNATURE TIDAK VALID — DITOLAK!")
        except Exception as e:
            logger.error(f"Error global model: {e}")

    # ==================== Training ====================
    def train_local_model(self, epochs):
        self.is_training = True
        self.model.train()
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=self.lr, weight_decay=self.weight_decay)

        for epoch in range(epochs):
            total_loss, correct, total = 0, 0, 0
            for Xb, yb in self.train_loader:
                Xb, yb = Xb.to(self.device), yb.to(self.device)
                optimizer.zero_grad()
                out  = self.model(Xb)
                loss = criterion(out, yb)
                loss.backward(); optimizer.step()
                total_loss += loss.item()
                _, pred = out.max(1)
                total += yb.size(0); correct += pred.eq(yb).sum().item()
            logger.info(f"  Epoch {epoch+1}/{epochs}: loss={total_loss/len(self.train_loader):.4f} acc={100*correct/total:.2f}%")

        test_loss, test_acc, prec, rec, f1, per_class_f1, cm = self.evaluate()
        self.send_model_update()
        self.send_metrics(test_loss, test_acc, prec, rec, f1, per_class_f1, cm)
        self.is_training = False
        logger.info(">>> Round Complete. Waiting... <<<")

    def evaluate(self):
        self.model.eval()
        criterion = nn.CrossEntropyLoss()
        total_loss, correct, total = 0, 0, 0
        all_pred, all_lbl = [], []
        with torch.no_grad():
            for Xb, yb in self.test_loader:
                Xb, yb = Xb.to(self.device), yb.to(self.device)
                out  = self.model(Xb); loss = criterion(out, yb)
                total_loss += loss.item()
                _, pred = out.max(1)
                total += yb.size(0); correct += pred.eq(yb).sum().item()
                all_pred.extend(pred.cpu().numpy()); all_lbl.extend(yb.cpu().numpy())

        avg_loss = total_loss / len(self.test_loader)
        avg_acc  = 100. * correct / total
        prec = precision_score(all_lbl, all_pred, average='weighted', zero_division=0) * 100
        rec  = recall_score(all_lbl,    all_pred, average='weighted', zero_division=0) * 100
        f1   = f1_score(all_lbl,        all_pred, average='weighted', zero_division=0) * 100

        labels = list(range(self.output_dim))
        per_class_f1 = f1_score(all_lbl, all_pred, average=None,
                                labels=labels, zero_division=0).tolist()
        cm = confusion_matrix(all_lbl, all_pred, labels=labels).tolist()
        return avg_loss, avg_acc, prec, rec, f1, per_class_f1, cm

    def send_model_update(self):
        """[S1][S3][S8] Signcrypt model dengan nonce di dalam payload terenkripsi."""
        buf = io.BytesIO()
        torch.save(self.model.state_dict(), buf)
        inner = {
            'weights_b64': base64.b64encode(buf.getvalue()).decode(),
            'timestamp':   time.time(),
            'nonce':       base64.b64encode(os.urandom(16)).decode(),  # [S3]
            'round':       self.current_round,
            'num_samples': self.num_train_samples,
            'client_id':   self.client_id
        }
        package = self.signcryption.signcrypt(
            json.dumps(inner).encode(),
            sender_private_key=self.client_private_key,
            receiver_public_key=self.server_public_key
        )
        self.mqtt_client.publish(
            f"{self.topic_prefix}/client/{self.client_id}/model",
            json.dumps(package), qos=1
        )
        logger.info("📤 Model Update Sent ✓ (Signcrypted + nonce)")

    def send_metrics(self, loss, acc, prec=0, rec=0, f1=0, per_class_f1=None, cm=None):
        """[S1] Metrics terenkripsi + ditandatangani."""
        msg = {
            'round': self.current_round, 'test_loss': float(loss),
            'test_acc': float(acc), 'precision': float(prec),
            'recall': float(rec), 'f1_score': float(f1),
            'per_class_f1': per_class_f1 or [],
            'confusion_matrix': cm or [],
            'num_samples': self.num_train_samples,
            'timestamp': time.time()
        }
        package = self.signcryption.signcrypt(
            json.dumps(msg).encode(),
            sender_private_key=self.client_private_key,
            receiver_public_key=self.server_public_key
        )
        self.mqtt_client.publish(
            f"{self.topic_prefix}/client/{self.client_id}/metrics",
            json.dumps(package), qos=1
        )

    # ==================== Telemetry ====================
    def _read_cpu_temp(self):
        """Read CPU temperature (Linux: /sys/class/thermal)."""
        try:
            with open("/sys/class/thermal/thermal_zone0/temp") as f:
                return float(f.read().strip()) / 1000.0
        except Exception:
            pass
        if _PSUTIL_OK:
            try:
                temps = psutil.sensors_temperatures()
                for key in ("cpu_thermal", "cpu-thermal", "coretemp"):
                    if key in temps and temps[key]:
                        return temps[key][0].current
            except Exception:
                pass
        return None

    def _telemetry_loop(self, interval=30):
        """Background thread: publish CPU/RAM/Temp to MQTT every `interval` seconds."""
        import threading
        while not self._telemetry_stop:
            try:
                data = {"client_id": self.client_id, "timestamp": time.time()}
                if _PSUTIL_OK:
                    data["cpu"]  = psutil.cpu_percent(interval=1)
                    mem = psutil.virtual_memory()
                    data["ram"]  = mem.percent
                    data["ram_used_mb"]  = round(mem.used  / 1024 / 1024)
                    data["ram_total_mb"] = round(mem.total / 1024 / 1024)
                temp = self._read_cpu_temp()
                if temp is not None:
                    data["temp"] = round(temp, 1)
                self.mqtt_client.publish(
                    f"{self.topic_prefix}/client/{self.client_id}/telemetry",
                    json.dumps(data), qos=0
                )
            except Exception as e:
                logger.debug(f"Telemetry error: {e}")
            for _ in range(interval):
                if self._telemetry_stop:
                    break
                time.sleep(1)

    def run(self):
        import threading
        try:
            self.load_data()
            logger.info("\n[2/3] Connecting MQTT...")
            if self.use_tls:
                self.mqtt_client.tls_set(ca_certs=self.ca_cert, tls_version=ssl.PROTOCOL_TLS_CLIENT)
            self.mqtt_client.connect(self.mqtt_host, self.mqtt_port, self.mqtt_keepalive)
            # Start telemetry in background
            t = threading.Thread(target=self._telemetry_loop, args=(30,), daemon=True)
            t.start()
            self.mqtt_client.loop_forever()
        except KeyboardInterrupt:
            logger.info("Stopped by user.")
        finally:
            self._telemetry_stop = True
            self.mqtt_client.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--client_id', required=True)
    parser.add_argument('--config', default='./fedml_config.yaml')
    args = parser.parse_args()
    FedMLClient(args.client_id, args.config).run()
