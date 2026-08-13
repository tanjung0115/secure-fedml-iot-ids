#!/usr/bin/env python3
"""
Test Alur Kerja Signcryption Penuh
Menyimulasikan komunikasi aman antara Klien dan Server
"""

import sys
import logging
from crypto.signcryption import SigncryptionManager
from cryptography.exceptions import InvalidSignature

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Inisialisasi SigncryptionManager
# Pastikan ini sama dengan yang di-hardcode di skrip Anda (AES-2048)
# Jika AES-2048 adalah kesalahan ketik dan seharusnya 256, ubah di sini.
# Berdasarkan output Anda: "Signcryption initialized: RSA-2048, AES-2048"
# Ini sepertinya salah ketik di log Anda, AES-256 (32 byte) adalah standar.
# Mari kita asumsikan default modul (256 bit) sudah benar.
try:
    manager = SigncryptionManager() # Menggunakan default (RSA-2048, AES-256)
except Exception as e:
    logger.error(f"Error di log Anda. 'AES-2048' tidak valid. Harusnya 'AES-256'.")
    logger.error(f"Menggunakan default SigncryptionManager (AES-256). Error: {e}")
    # Jika log Anda benar AES-2048, ganti '2048' di line atas menjadi 256
    # manager = SigncryptionManager(aes_key_size=256) 
    pass

# --- Path Kunci ---
# Path ini relatif dari root folder fl-fedml-mqtt/
SERVER_PRIV_KEY = "keys/server/server_private.pem"
SERVER_PUB_KEY = "keys/server/server_public.pem"
CLIENT1_PRIV_KEY = "keys/clients/rpi_client1/rpi_client1_private.pem"
CLIENT1_PUB_KEY = "keys/clients/rpi_client1/rpi_client1_public.pem"

def run_test():
    try:
        logger.info("Memulai Tes Alur Kerja Crypto...")

        # --- 1. Muat Semua Kunci ---
        logger.info("Memuat kunci dari file...")
        server_priv = manager.load_private_key(SERVER_PRIV_KEY)
        server_pub = manager.load_public_key(SERVER_PUB_KEY)
        client1_priv = manager.load_private_key(CLIENT1_PRIV_KEY)
        client1_pub = manager.load_public_key(CLIENT1_PUB_KEY)
        logger.info("✓ Semua 4 kunci berhasil dimuat.")

        # --- 2. Tes Skenario: Klien -> Server (Mengirim Model Update) ---
        print("\n" + "="*50)
        logger.info("TES 1: Klien (rpi_client1) mengirim ke Server")
        print("="*50)
        
        data_dari_klien = b"Ini adalah data model rahasia dari rpi_client1"
        logger.info(f"Data Asli: {data_dari_klien.decode('utf-8')}")

        # Klien mengenkripsi dengan kunci publik server
        # dan menandatangani dengan kunci privatnya sendiri
        paket_terenkripsi = manager.signcrypt(
            data=data_dari_klien,
            sender_private_key=client1_priv,
            receiver_public_key=server_pub
        )
        logger.info(f"Data ter-Signcrypt. Ukuran paket: {sys.getsizeof(str(paket_terenkripsi))} bytes")
        
        # Server mendekripsi dengan kunci privatnya sendiri
        # dan memverifikasi tanda tangan dengan kunci publik klien
        data_terbuka = manager.unsigncrypt(
            package=paket_terenkripsi,
            receiver_private_key=server_priv,
            sender_public_key=client1_pub
        )
        logger.info(f"Data ter-Unsigncrypt: {data_terbuka.decode('utf-8')}")
        
        # Verifikasi
        assert data_dari_klien == data_terbuka
        logger.info("✓ VERIFIKASI BERHASIL: Data Klien -> Server cocok!")

        # --- 3. Tes Skenario: Server -> Klien (Mengirim Global Model) ---
        print("\n" + "="*50)
        logger.info("TES 2: Server mengirim ke Klien (rpi_client1)")
        print("="*50)
        
        data_dari_server = b"Ini adalah Global Model baru dari Server"
        logger.info(f"Data Asli: {data_dari_server.decode('utf-8')}")

        # Server mengenkripsi dengan kunci publik klien
        # dan menandatangani dengan kunci privatnya sendiri
        paket_terenkripsi_server = manager.signcrypt(
            data=data_dari_server,
            sender_private_key=server_priv,
            receiver_public_key=client1_pub
        )
        logger.info(f"Data ter-Signcrypt. Ukuran paket: {sys.getsizeof(str(paket_terenkripsi_server))} bytes")

        # Klien mendekripsi dengan kunci privatnya sendiri
        # dan memverifikasi tanda tangan dengan kunci publik server
        data_terbuka_klien = manager.unsigncrypt(
            package=paket_terenkripsi_server,
            receiver_private_key=client1_priv,
            sender_public_key=server_pub
        )
        logger.info(f"Data ter-Unsigncrypt: {data_terbuka_klien.decode('utf-8')}")
        
        # Verifikasi
        assert data_dari_server == data_terbuka_klien
        logger.info("✓ VERIFIKASI BERHASIL: Data Server -> Klien cocok!")
        
        print("\n" + "="*50)
        logger.info("🎉 SEMUA TES ALUR KERJA CRYPTO BERHASIL! 🎉")
        print("="*50)

    except InvalidSignature:
        logger.error("✗ TES GAGAL: TANDA TANGAN TIDAK VALID!")
    except FileNotFoundError as e:
        logger.error(f"✗ TES GAGAL: File kunci tidak ditemukan! {e}")
    except Exception as e:
        logger.error(f"✗ TES GAGAL: Terjadi error! {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_test()
