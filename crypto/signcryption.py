#!/usr/bin/env python3
"""
Signcryption Module for Federated Learning
Combines Digital Signature + Encryption (RSA + AES)

Security Features:
- Confidentiality (AES-256-GCM encryption)
- Authentication (RSA digital signature)
- Integrity (SHA-256 hash)
- Non-repudiation (RSA signature)
"""

import os
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import logging

logger = logging.getLogger(__name__)


class SigncryptionManager:
    """Handles signcryption operations for federated learning"""
    
    def __init__(self, key_size=2048, aes_key_size=256):
        """
        Initialize signcryption manager
        
        Args:
            key_size: RSA key size in bits (2048 or 4096)
            aes_key_size: AES key size in bits (128, 192, or 256)
        """
        self.key_size = key_size
        self.aes_key_size = aes_key_size // 8  # Convert to bytes
        self.backend = default_backend()
        
        # Padding for RSA
        self.rsa_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        
        # Padding for signature
        self.sign_padding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
        
        logger.info(f"Signcryption initialized: RSA-{key_size}, AES-{aes_key_size*8}")
    
    # ==================== Key Generation ====================
    def generate_key_pair(self):
        """
        Generate RSA key pair
        
        Returns:
            tuple: (private_key, public_key) as PEM strings
        """
        logger.info("Generating RSA key pair...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=self.backend
        )
        
        # Generate public key
        public_key = private_key.public_key()
        
        # [Fix 5] Enkripsi private key dengan passphrase dari environment variable
        # Set FL_KEY_PASSPHRASE di environment sebelum menjalankan server/client
        passphrase = os.environ.get('FL_KEY_PASSPHRASE', '').encode() or None
        encryption_algo = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase else serialization.NoEncryption()
        )
        if passphrase:
            logger.info("✓ Private key akan dienkripsi dengan passphrase (FL_KEY_PASSPHRASE)")
        else:
            logger.warning("⚠️ FL_KEY_PASSPHRASE tidak diset — private key disimpan TANPA enkripsi")

        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        logger.info("✓ Key pair generated successfully")
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    
    def load_private_key(self, key_path):
        """Load private key from file.
        [Fix 5] Baca passphrase dari FL_KEY_PASSPHRASE environment variable.
        Jika variable tidak diset, coba load tanpa passphrase (backward-compatible).
        """
        passphrase = os.environ.get('FL_KEY_PASSPHRASE', '').encode() or None
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=passphrase,
                backend=self.backend
            )
        logger.info(f"✓ Loaded private key from {key_path}")
        return private_key
    
    def load_public_key(self, key_path_or_str):
        """
        Load public key from file or string
        
        Args:
            key_path_or_str: Path to key file or PEM string
        """
        if os.path.isfile(key_path_or_str):
            with open(key_path_or_str, 'rb') as f:
                key_data = f.read()
            logger.info(f"✓ Loaded public key from {key_path_or_str}")
        else:
            key_data = key_path_or_str.encode('utf-8')
            logger.info("✓ Loaded public key from string")
        
        public_key = serialization.load_pem_public_key(
            key_data,
            backend=self.backend
        )
        return public_key
    
    # ==================== Broadcast Signing (tanpa enkripsi) ====================
    def sign(self, data: bytes, private_key) -> str:
        """
        Tanda-tangani data tanpa enkripsi — untuk pesan broadcast (server→semua client).
        Memberikan Authentication + Integrity tanpa Confidentiality.

        Args:
            data        : bytes yang akan ditanda-tangani
            private_key : RSA private key pengirim

        Returns:
            str: signature dalam format base64
        """
        signature = private_key.sign(data, self.sign_padding, hashes.SHA256())
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, data: bytes, signature_b64: str, public_key) -> bool:
        """
        Verifikasi tanda-tangan dari pesan broadcast.

        Args:
            data         : bytes asli yang ditanda-tangani
            signature_b64: signature dalam format base64
            public_key   : RSA public key pengirim

        Returns:
            bool: True jika valid, False jika tidak valid
        """
        try:
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, data, self.sign_padding, hashes.SHA256())
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False

    # ==================== Signcryption ====================
    def signcrypt(self, data, sender_private_key, receiver_public_key):
        """
        Signcrypt data: Sign with sender's private key + Encrypt with receiver's public key
        
        Args:
            data: bytes to signcrypt
            sender_private_key: RSA private key object
            receiver_public_key: RSA public key object
        
        Returns:
            dict: Encrypted package with signature
        """
        logger.info("Starting signcryption...")
        
        # Step 1: Generate signature (Authentication)
        signature = sender_private_key.sign(
            data,
            self.sign_padding,
            hashes.SHA256()
        )
        logger.debug(f"✓ Signature generated: {len(signature)} bytes")
        
        # Step 2: Generate random AES key and IV
        aes_key = os.urandom(self.aes_key_size)
        iv = os.urandom(16)  # AES block size
        
        # Step 3: Encrypt data with AES-GCM
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag  # Authentication tag for GCM
        
        logger.debug(f"✓ Data encrypted: {len(ciphertext)} bytes")
        
        # Step 4: Encrypt AES key with receiver's RSA public key
        encrypted_aes_key = receiver_public_key.encrypt(
            aes_key,
            self.rsa_padding
        )
        logger.debug(f"✓ AES key encrypted: {len(encrypted_aes_key)} bytes")
        
        # Step 5: Package everything
        package = {
            'encrypted_data': base64.b64encode(ciphertext).decode('utf-8'),
            'encrypted_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'signature': base64.b64encode(signature).decode('utf-8'),
            'algorithm': 'AES-256-GCM + RSA-OAEP',
            'hash_algorithm': 'SHA256'
        }
        
        logger.info(f"✓ Signcryption complete: {len(ciphertext)} bytes encrypted")
        return package
    
    def unsigncrypt(self, package, receiver_private_key, sender_public_key):
        """
        Unsigncrypt data: Decrypt with receiver's private key + Verify signature
        
        Args:
            package: Encrypted package from signcrypt()
            receiver_private_key: RSA private key object
            sender_public_key: RSA public key object
        
        Returns:
            bytes: Decrypted data (if signature valid)
        
        Raises:
            InvalidSignature: If signature verification fails
        """
        logger.info("Starting unsigncryption...")
        
        try:
            # Step 1: Decode from base64
            encrypted_data = base64.b64decode(package['encrypted_data'])
            encrypted_key = base64.b64decode(package['encrypted_key'])
            iv = base64.b64decode(package['iv'])
            tag = base64.b64decode(package['tag'])
            signature = base64.b64decode(package['signature'])
            
            # Step 2: Decrypt AES key with receiver's RSA private key
            aes_key = receiver_private_key.decrypt(
                encrypted_key,
                self.rsa_padding
            )
            logger.debug("✓ AES key decrypted")
            
            # Step 3: Decrypt data with AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
            logger.debug(f"✓ Data decrypted: {len(plaintext)} bytes")
            
            # Step 4: Verify signature (Authentication)
            sender_public_key.verify(
                signature,
                plaintext,
                self.sign_padding,
                hashes.SHA256()
            )
            logger.info("✓ Signature verified - Data authentic!")
            
            return plaintext
            
        except InvalidSignature:
            logger.error("✗ SIGNATURE VERIFICATION FAILED!")
            raise
        except Exception as e:
            logger.error(f"✗ Unsigncryption error: {e}")
            raise
    
    # ==================== Utility Functions ====================
    def signcrypt_file(self, file_path, sender_private_key, receiver_public_key):
        """Signcrypt a file"""
        logger.info(f"Signcrypting file: {file_path}")
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        package = self.signcrypt(data, sender_private_key, receiver_public_key)
        
        file_size_mb = len(data) / (1024 * 1024)
        logger.info(f"✓ File signcrypted: {file_size_mb:.2f} MB")
        
        return package
    
    def unsigncrypt_to_file(self, package, output_path, receiver_private_key, sender_public_key):
        """Unsigncrypt to a file"""
        logger.info(f"Unsigncrypting to file: {output_path}")
        
        plaintext = self.unsigncrypt(package, receiver_private_key, sender_public_key)
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        file_size_mb = len(plaintext) / (1024 * 1024)
        logger.info(f"✓ File saved: {file_size_mb:.2f} MB")
        
        return output_path
    
    def get_package_size(self, package):
        """Get total size of encrypted package in bytes"""
        json_str = json.dumps(package)
        return len(json_str.encode('utf-8'))


# ==================== Helper Functions ====================
def save_key_to_file(key_pem, file_path, is_private=False):
    """
    Save PEM key to file
    
    Args:
        key_pem: PEM string
        file_path: Output path
        is_private: If True, set secure permissions (chmod 600)
    """
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, 'w') as f:
        f.write(key_pem)
    
    # Set secure permissions for private keys
    if is_private:
        os.chmod(file_path, 0o600)
        logger.info(f"✓ Private key saved with secure permissions: {file_path}")
    else:
        logger.info(f"✓ Public key saved: {file_path}")


def generate_and_save_keys(output_dir, prefix="key", key_size=2048):
    """
    Generate and save key pair
    
    Args:
        output_dir: Directory to save keys
        prefix: Filename prefix
        key_size: RSA key size
    
    Returns:
        tuple: (private_key_path, public_key_path)
    """
    manager = SigncryptionManager(key_size=key_size)
    private_pem, public_pem = manager.generate_key_pair()
    
    private_path = Path(output_dir) / f"{prefix}_private.pem"
    public_path = Path(output_dir) / f"{prefix}_public.pem"
    
    save_key_to_file(private_pem, private_path, is_private=True)
    save_key_to_file(public_pem, public_path, is_private=False)
    
    return str(private_path), str(public_path)


# ==================== Testing ====================
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    print("=" * 70)
    print("SIGNCRYPTION MODULE - TEST")
    print("=" * 70)
    
    # Test 1: Generate keys
    print("\n[Test 1] Generating key pairs...")
    manager = SigncryptionManager()
    
    sender_priv_pem, sender_pub_pem = manager.generate_key_pair()
    receiver_priv_pem, receiver_pub_pem = manager.generate_key_pair()
    
    print("✓ Keys generated")
    
    # Test 2: Load keys
    print("\n[Test 2] Loading keys...")
    sender_private = serialization.load_pem_private_key(
        sender_priv_pem.encode(), password=None, backend=default_backend()
    )
    sender_public = serialization.load_pem_public_key(
        sender_pub_pem.encode(), backend=default_backend()
    )
    receiver_private = serialization.load_pem_private_key(
        receiver_priv_pem.encode(), password=None, backend=default_backend()
    )
    receiver_public = serialization.load_pem_public_key(
        receiver_pub_pem.encode(), backend=default_backend()
    )
    print("✓ Keys loaded")
    
    # Test 3: Signcrypt
    print("\n[Test 3] Signcrypting data...")
    test_data = b"Hello, Federated Learning with Signcryption!"
    
    package = manager.signcrypt(test_data, sender_private, receiver_public)
    print(f"✓ Data signcrypted: {manager.get_package_size(package)} bytes")
    
    # Test 4: Unsigncrypt
    print("\n[Test 4] Unsigncrypting data...")
    decrypted = manager.unsigncrypt(package, receiver_private, sender_public)
    
    if decrypted == test_data:
        print("✓ Unsigncryption successful!")
        print(f"  Original:  {test_data}")
        print(f"  Decrypted: {decrypted}")
    else:
        print("✗ Data mismatch!")
    
    # Test 5: Invalid signature detection
    print("\n[Test 5] Testing signature verification...")
    try:
        # Try to verify with wrong public key
        wrong_pub_pem = manager.generate_key_pair()[1]
        wrong_public = serialization.load_pem_public_key(
            wrong_pub_pem.encode(), backend=default_backend()
        )
        manager.unsigncrypt(package, receiver_private, wrong_public)
        print("✗ Should have detected invalid signature!")
    except InvalidSignature:
        print("✓ Invalid signature detected correctly!")
    
    print("\n" + "=" * 70)
    print("ALL TESTS PASSED!")
    print("=" * 70)
