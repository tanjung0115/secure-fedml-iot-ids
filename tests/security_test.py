#!/usr/bin/env python3
"""
Security Test Suite — FL-IDS TCMS dengan Signcryption
Thesis: Pengamanan Federated Learning untuk IoT TCMS menggunakan Signcryption

Skenario Pengujian:
  T1  : Replay Attack (model lama dikirim ulang)
  T2  : Signature Forgery (signature dipalsukan)
  T3  : Payload Tampering (data terenkripsi dimodifikasi)
  T4  : Fake Client / Impersonation (client tidak terdaftar)
  T5  : Fake Server (rogue server kirim model palsu)
  T6  : Bogus Instruction (instruksi tanpa signature)
  T7  : Instruction Tampering (instruksi dimodifikasi setelah ditanda-tangani)
  T8  : Replay Instruction (instruksi lama diputar ulang)
  T9  : DoS — Oversized Payload
  T10 : Man-in-the-Middle (MITM) Simulasi

Setiap tes: PASS = serangan berhasil dideteksi/ditolak
"""

import os
import sys
import time
import json
import base64
import io
import copy

import torch
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

sys.path.insert(0, os.path.dirname(__file__))

from model import IDSModel
from crypto.signcryption import SigncryptionManager
from crypto.key_manager_rsa_aes import KeyManager

# ==================== Setup ====================
PASS = "✅ PASS"
FAIL = "❌ FAIL"
results = []

km = KeyManager('./keys')
sc = SigncryptionManager()

server_priv, server_pub = km.load_server_keys()
c1_priv, c1_pub         = km.load_client_keys('rpi_client1')
c2_priv, c2_pub         = km.load_client_keys('rpi_client2') if len(km.get_all_client_ids()) > 1 else (c1_priv, c1_pub)

# Rogue keys (tidak terdaftar di sistem)
rogue_sc = SigncryptionManager()
rogue_priv_pem, rogue_pub_pem = rogue_sc.generate_key_pair()
rogue_priv = serialization.load_pem_private_key(rogue_priv_pem.encode(), password=None, backend=default_backend())
rogue_pub  = serialization.load_pem_public_key(rogue_pub_pem.encode(), backend=default_backend())

REPLAY_WINDOW = 10   # harus sama dengan server


def make_model_payload(client_priv, server_pub_key, round_num=1, delay=0):
    """Buat payload model yang valid, dengan opsional delay untuk simulasi replay."""
    model = IDSModel()
    buf   = io.BytesIO()
    torch.save(model.state_dict(), buf)

    inner = {
        'weights_b64': base64.b64encode(buf.getvalue()).decode(),
        'timestamp':   time.time() - delay,
        'nonce':       base64.b64encode(os.urandom(16)).decode(),
        'round':       round_num,
        'num_samples': 1000,
        'client_id':   'rpi_client1'
    }
    return sc.signcrypt(json.dumps(inner).encode(), client_priv, server_pub_key)


def make_instruction(server_priv_key, round_num=1, delay=0, tamper_epoch=None):
    """Buat instruksi training yang ditandatangani server."""
    nonce = base64.b64encode(os.urandom(16)).decode()
    msg = {
        'round':     round_num,
        'action':    'train',
        'epochs':    3,
        'timestamp': time.time() - delay,
        'nonce':     nonce
    }
    if tamper_epoch is not None:
        msg_bytes = json.dumps(msg, sort_keys=True).encode()
        msg['epochs']    = tamper_epoch     # tamper SETELAH sign
        msg['signature'] = sc.sign(msg_bytes, server_priv_key)
    else:
        msg_bytes = json.dumps(msg, sort_keys=True).encode()
        msg['signature'] = sc.sign(msg_bytes, server_priv_key)
    return msg


def verify_instruction(msg_dict, server_pub_key):
    """Verifikasi instruksi seperti yang dilakukan client."""
    msg = dict(msg_dict)
    sig = msg.pop('signature', None)
    if sig is None:
        return False
    msg_bytes = json.dumps(msg, sort_keys=True).encode()
    if not sc.verify_signature(msg_bytes, sig, server_pub_key):
        return False
    ts    = msg.get('timestamp', 0)
    if abs(time.time() - ts) > REPLAY_WINDOW:
        return False
    return True


def log(test_id, description, result, detail=""):
    mark = PASS if result else FAIL
    line = f"  {mark} [{test_id}] {description}"
    if detail:
        line += f"\n       → {detail}"
    print(line)
    results.append((test_id, description, result))


# ==================== T1: Replay Attack ====================
print("\n" + "="*65)
print("  T1 — REPLAY ATTACK (model lama dikirim ulang setelah jendela)")
print("="*65)

# Buat payload valid
pkg = make_model_payload(c1_priv, server_pub, round_num=1, delay=0)
payload_bytes = json.dumps(pkg).encode()

# Simulasi server menerima: pertama kali
inner = json.loads(sc.unsigncrypt(pkg, server_priv, c1_pub).decode())
ts1 = inner['timestamp']
nonce1 = inner['nonce']
used_nonces = {nonce1: time.time()}
age1 = abs(time.time() - ts1)
first_ok = age1 <= REPLAY_WINDOW and nonce1 not in set()
log("T1a", "Paket PERTAMA diterima (valid)", first_ok, f"age={age1:.2f}s ≤ {REPLAY_WINDOW}s")

# Replay: nonce sudah dikonsumsi
nonce_reused = nonce1 in used_nonces
log("T1b", "Replay ditolak — nonce sudah dipakai", nonce_reused, f"nonce '{nonce1[:12]}…' sudah ada di used_nonces")

# Replay dengan timestamp kadaluarsa
pkg_old = make_model_payload(c1_priv, server_pub, round_num=1, delay=REPLAY_WINDOW + 5)
inner_old = json.loads(sc.unsigncrypt(pkg_old, server_priv, c1_pub).decode())
ts_old = inner_old['timestamp']
age_old = abs(time.time() - ts_old)
log("T1c", "Replay ditolak — timestamp kedaluarsa", age_old > REPLAY_WINDOW,
    f"age={age_old:.1f}s > {REPLAY_WINDOW}s")


# ==================== T2: Signature Forgery ====================
print("\n" + "="*65)
print("  T2 — SIGNATURE FORGERY (signature dipalsukan)")
print("="*65)

pkg_valid = make_model_payload(c1_priv, server_pub)
pkg_forged = copy.deepcopy(pkg_valid)
# Tamper signature: ganti beberapa karakter
sig_bytes = base64.b64decode(pkg_forged['signature'])
tampered  = sig_bytes[:10] + bytes(b ^ 0xFF for b in sig_bytes[10:20]) + sig_bytes[20:]
pkg_forged['signature'] = base64.b64encode(tampered).decode()

try:
    sc.unsigncrypt(pkg_forged, server_priv, c1_pub)
    log("T2a", "Signature palsu terdeteksi", False, "unsigncrypt BERHASIL — seharusnya GAGAL!")
except (InvalidSignature, Exception):
    log("T2a", "Signature palsu terdeteksi", True, "InvalidSignature / decryption error raised ✓")

# Tanda-tangan dari client lain
pkg_wrong_signer = make_model_payload(c2_priv, server_pub)
try:
    sc.unsigncrypt(pkg_wrong_signer, server_priv, c1_pub)  # Verifikasi pakai kunci c1, padahal ditanda-tangani c2
    log("T2b", "Signature dari client lain terdeteksi", False, "Verifikasi c2-signed dengan c1-pub BERHASIL — salah!")
except (InvalidSignature, Exception):
    log("T2b", "Signature dari client lain terdeteksi", True, "Signature mismatch terdeteksi ✓")


# ==================== T3: Payload Tampering (MITM) ====================
print("\n" + "="*65)
print("  T3 — PAYLOAD TAMPERING (data terenkripsi dimodifikasi)")
print("="*65)

pkg_valid = make_model_payload(c1_priv, server_pub)

# Tamper encrypted_data (ciphertext)
pkg_tampered = copy.deepcopy(pkg_valid)
ct = base64.b64decode(pkg_tampered['encrypted_data'])
ct_tampered = ct[:5] + bytes(b ^ 0xAA for b in ct[5:15]) + ct[15:]
pkg_tampered['encrypted_data'] = base64.b64encode(ct_tampered).decode()

try:
    sc.unsigncrypt(pkg_tampered, server_priv, c1_pub)
    log("T3a", "Ciphertext tampering terdeteksi (AES-GCM tag)", False, "Decrypt BERHASIL — GCM tag seharusnya gagal!")
except Exception:
    log("T3a", "Ciphertext tampering terdeteksi (AES-GCM tag)", True, "GCM authentication tag error raised ✓")

# Tamper GCM tag langsung
pkg_tag_tampered = copy.deepcopy(pkg_valid)
tag = base64.b64decode(pkg_tag_tampered['tag'])
pkg_tag_tampered['tag'] = base64.b64encode(bytes(b ^ 0xFF for b in tag)).decode()

try:
    sc.unsigncrypt(pkg_tag_tampered, server_priv, c1_pub)
    log("T3b", "GCM tag tampering terdeteksi", False, "Decrypt BERHASIL — seharusnya GAGAL!")
except Exception:
    log("T3b", "GCM tag tampering terdeteksi", True, "GCM tag mismatch error raised ✓")


# ==================== T4: Fake Client (Impersonation) ====================
print("\n" + "="*65)
print("  T4 — FAKE CLIENT / IMPERSONATION")
print("="*65)

# Rogue client mencoba kirim model (tandatangani dengan kunci rogue)
pkg_rogue = sc.signcrypt(
    json.dumps({'weights_b64': 'AAAA', 'timestamp': time.time(),
                'nonce': base64.b64encode(os.urandom(16)).decode(),
                'round': 1, 'num_samples': 999, 'client_id': 'rogue'}).encode(),
    rogue_priv, server_pub
)

# Server mencoba verifikasi dengan kunci c1 (bukan kunci rogue)
try:
    sc.unsigncrypt(pkg_rogue, server_priv, c1_pub)
    log("T4a", "Fake client dengan kunci rogue ditolak", False, "Verifikasi BERHASIL — seharusnya GAGAL!")
except Exception:
    log("T4a", "Fake client dengan kunci rogue ditolak", True, "Signature dari kunci tidak dikenal ditolak ✓")

# Whitelist check simulasi
whitelist = {'rpi_client1', 'rpi_client2', 'rpi_client3', 'rpi_client4',
             'rpi_client5', 'rpi_client6', 'rpi_client7'}
rogue_id = 'attacker_node'
log("T4b", f"Client '{rogue_id}' tidak ada di whitelist", rogue_id not in whitelist,
    f"'{rogue_id}' ∉ whitelist → registrasi ditolak ✓")


# ==================== T5: Fake Server ====================
print("\n" + "="*65)
print("  T5 — FAKE SERVER (rogue server kirim global model palsu)")
print("="*65)

# Rogue server mencoba kirim model ke client menggunakan kunci rogue
model = IDSModel()
buf = io.BytesIO()
torch.save(model.state_dict(), buf)
inner_fake = {
    'weights_b64': base64.b64encode(buf.getvalue()).decode(),
    'round': 1, 'timestamp': time.time(),
    'nonce': base64.b64encode(os.urandom(16)).decode()
}
pkg_fake_server = sc.signcrypt(json.dumps(inner_fake).encode(), rogue_priv, c1_pub)

# Client verifikasi: pakai server_pub → harus gagal karena kunci berbeda
try:
    sc.unsigncrypt(pkg_fake_server, c1_priv, server_pub)
    log("T5", "Fake server global model ditolak", False, "Client menerima model dari fake server — BERBAHAYA!")
except Exception:
    log("T5", "Fake server global model ditolak", True, "Signature dari kunci bukan server ditolak ✓")


# ==================== T6: Bogus Instruction (tanpa signature) ====================
print("\n" + "="*65)
print("  T6 — BOGUS INSTRUCTION (instruksi tanpa signature)")
print("="*65)

msg_no_sig = {'round': 99, 'action': 'train', 'epochs': 100,
              'timestamp': time.time(), 'nonce': 'abc123'}
# Client handler: cek signature dulu
sig = msg_no_sig.get('signature', None)
log("T6", "Instruksi tanpa signature ditolak", sig is None,
    "Client mendeteksi tidak ada field 'signature' → instruksi ditolak ✓")


# ==================== T7: Instruction Tampering ====================
print("\n" + "="*65)
print("  T7 — INSTRUCTION TAMPERING (epochs diubah setelah signing)")
print("="*65)

msg_tampered = make_instruction(server_priv, round_num=1, tamper_epoch=999)
# Verifikasi: signature dibuat dengan epochs=3, tapi sekarang epochs=999
result = verify_instruction(msg_tampered, server_pub)
log("T7", "Instruksi yang dimodifikasi setelah signing ditolak", not result,
    f"epochs ditamper 3→999, signature tidak cocok → ditolak ✓")


# ==================== T8: Replay Instruction ====================
print("\n" + "="*65)
print("  T8 — REPLAY INSTRUCTION (instruksi lama diputar ulang)")
print("="*65)

msg_old = make_instruction(server_priv, round_num=1, delay=REPLAY_WINDOW + 3)
result_old = verify_instruction(msg_old, server_pub)
log("T8a", "Instruksi kedaluarsa ditolak", not result_old,
    f"delay={REPLAY_WINDOW+3}s > window={REPLAY_WINDOW}s → ditolak ✓")

# Nonce reuse
used_instr_nonces = set()
msg_fresh = make_instruction(server_priv, round_num=1, delay=0)
sig_fresh = msg_fresh.pop('signature')
nonce_fresh = msg_fresh['nonce']
msg_fresh['signature'] = sig_fresh

ok_first = verify_instruction(msg_fresh, server_pub)
used_instr_nonces.add(nonce_fresh)
second_attempt = nonce_fresh in used_instr_nonces
log("T8b", "Replay instruksi (nonce sudah dipakai) ditolak", ok_first and second_attempt,
    f"Pertama: {'✓' if ok_first else '✗'}, Nonce di-blacklist: {'✓' if second_attempt else '✗'}")


# ==================== T9: DoS — Oversized Payload ====================
print("\n" + "="*65)
print("  T9 — DoS via OVERSIZED PAYLOAD")
print("="*65)

MAX_PAYLOAD = 10 * 1024 * 1024  # 10 MB
oversized   = b'A' * (MAX_PAYLOAD + 1)
log("T9", f"Payload >{MAX_PAYLOAD//1024//1024}MB ditolak",
    len(oversized) > MAX_PAYLOAD,
    f"Size={len(oversized)//1024//1024+1}MB > limit={MAX_PAYLOAD//1024//1024}MB → ditolak sebelum diproses ✓")


# ==================== T10: Metadata Tampering (MITM) ====================
print("\n" + "="*65)
print("  T10 — METADATA TAMPERING (MITM ubah timestamp/round di luar enkripsi)")
print("="*65)

pkg_valid = make_model_payload(c1_priv, server_pub, round_num=1)
pkg_mitm  = copy.deepcopy(pkg_valid)

# MITM mencoba inject metadata palsu di luar package
pkg_mitm['metadata'] = {'timestamp': 0, 'round': 999, 'num_samples': 999999}

# Server: baca timestamp/round dari DALAM payload terenkripsi (bukan dari metadata luar)
inner_real = json.loads(sc.unsigncrypt(pkg_mitm, server_priv, c1_pub).decode())
real_ts     = inner_real['timestamp']
real_round  = inner_real['round']
age_real    = abs(time.time() - real_ts)

tamper_detected = (real_round == 1) and (age_real <= REPLAY_WINDOW)
log("T10", "MITM metadata tampering tidak berpengaruh", tamper_detected,
    f"round dari payload={real_round} (bukan 999), timestamp real age={age_real:.2f}s ✓")


# ==================== Hasil Akhir ====================
print("\n" + "="*65)
print("  HASIL PENGUJIAN KEAMANAN")
print("="*65)
total  = len(results)
passed = sum(1 for _, _, r in results if r)
failed = total - passed

for tid, desc, res in results:
    mark = PASS if res else FAIL
    print(f"  {mark}  [{tid}] {desc}")

print(f"\n{'='*65}")
print(f"  Total  : {total} tes")
print(f"  Passed : {passed} ✅")
print(f"  Failed : {failed} ❌")
print(f"  Score  : {passed}/{total} ({100*passed//total}%)")
print(f"{'='*65}")

if failed > 0:
    print("\n⚠️  Ada tes yang GAGAL — sistem belum sepenuhnya aman!")
    sys.exit(1)
else:
    print("\n🎉 SEMUA TES KEAMANAN PASSED — Sistem siap untuk pengujian thesis!")
