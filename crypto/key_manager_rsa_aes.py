#!/usr/bin/env python3
"""
Key Manager for Federated Learning
Handles key rotation, backup, and lifecycle management
"""

import os
import json
import shutil
from pathlib import Path
from datetime import datetime
import logging

from crypto.signcryption import SigncryptionManager, save_key_to_file

logger = logging.getLogger(__name__)


class KeyManager:
    """Manages cryptographic keys and rotation for FL"""
    
    def __init__(self, base_dir="./keys", key_size=2048):
        """
        Initialize key manager
        
        Args:
            base_dir: Base directory for storing keys
            key_size: RSA key size in bits
        """
        self.base_dir = Path(base_dir)
        self.key_size = key_size
        self.signcryption = SigncryptionManager(key_size=key_size)
        
        # Create directory structure
        self.server_dir = self.base_dir / "server"
        self.clients_dir = self.base_dir / "clients"
        self.backup_dir = self.base_dir / "backups"
        
        for directory in [self.server_dir, self.clients_dir, self.backup_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Rotation history
        self.rotation_history_file = self.base_dir / "rotation_history.json"
        self.rotation_history = self.load_rotation_history()
        
        logger.info(f"KeyManager initialized: {self.base_dir}")
    
    # ==================== History Management ====================
    def load_rotation_history(self):
        """Load key rotation history"""
        if self.rotation_history_file.exists():
            with open(self.rotation_history_file, 'r') as f:
                return json.load(f)
        return {"rotations": [], "current_version": 1}
    
    def save_rotation_history(self):
        """Save key rotation history"""
        with open(self.rotation_history_file, 'w') as f:
            json.dump(self.rotation_history, f, indent=2)
        logger.info("✓ Rotation history saved")
    
    def add_rotation_record(self, entity, round_num, reason="scheduled"):
        """Add rotation record to history"""
        record = {
            "entity": entity,
            "round": round_num,
            "timestamp": datetime.now().isoformat(),
            "reason": reason,
            "version": self.rotation_history["current_version"]
        }
        
        self.rotation_history["rotations"].append(record)
        self.rotation_history["current_version"] += 1
        self.save_rotation_history()
        
        logger.info(f"✓ Rotation recorded: {entity} at round {round_num}")
    
    # ==================== Server Keys ====================
    def generate_server_keys(self, force=False):
        """
        Generate server key pair
        
        Args:
            force: If True, overwrite existing keys
        
        Returns:
            tuple: (private_path, public_path)
        """
        private_path = self.server_dir / "server_private.pem"
        public_path = self.server_dir / "server_public.pem"
        
        if private_path.exists() and not force:
            logger.warning("Server keys already exist. Use force=True to overwrite.")
            return str(private_path), str(public_path)
        
        logger.info("Generating server keys...")
        private_pem, public_pem = self.signcryption.generate_key_pair()
        
        save_key_to_file(private_pem, private_path, is_private=True)
        save_key_to_file(public_pem, public_path, is_private=False)
        
        logger.info("✓ Server keys generated")
        return str(private_path), str(public_path)
    
    def load_server_keys(self):
        """
        Load server keys
        
        Returns:
            tuple: (private_key_object, public_key_object)
        """
        private_path = self.server_dir / "server_private.pem"
        public_path = self.server_dir / "server_public.pem"
        
        if not private_path.exists():
            raise FileNotFoundError(f"Server private key not found: {private_path}")
        
        private_key = self.signcryption.load_private_key(private_path)
        public_key = self.signcryption.load_public_key(public_path)
        
        logger.info("✓ Server keys loaded")
        return private_key, public_key
    
    def get_server_public_key_pem(self):
        """Get server public key as PEM string"""
        public_path = self.server_dir / "server_public.pem"
        with open(public_path, 'r') as f:
            return f.read()
    
    # ==================== Client Keys ====================
    def generate_client_keys(self, client_id, force=False):
        """
        Generate client key pair
        
        Args:
            client_id: Client identifier
            force: If True, overwrite existing keys
        
        Returns:
            tuple: (private_path, public_path)
        """
        client_dir = self.clients_dir / client_id
        client_dir.mkdir(exist_ok=True)
        
        private_path = client_dir / f"{client_id}_private.pem"
        public_path = client_dir / f"{client_id}_public.pem"
        
        if private_path.exists() and not force:
            logger.warning(f"Client {client_id} keys already exist. Use force=True to overwrite.")
            return str(private_path), str(public_path)
        
        logger.info(f"Generating keys for client {client_id}...")
        private_pem, public_pem = self.signcryption.generate_key_pair()
        
        save_key_to_file(private_pem, private_path, is_private=True)
        save_key_to_file(public_pem, public_path, is_private=False)
        
        logger.info(f"✓ Client {client_id} keys generated")
        return str(private_path), str(public_path)
    
    def load_client_keys(self, client_id):
        """
        Load client keys
        
        Returns:
            tuple: (private_key_object, public_key_object)
        """
        client_dir = self.clients_dir / client_id
        private_path = client_dir / f"{client_id}_private.pem"
        public_path = client_dir / f"{client_id}_public.pem"
        
        if not private_path.exists():
            raise FileNotFoundError(f"Client {client_id} private key not found")
        
        private_key = self.signcryption.load_private_key(private_path)
        public_key = self.signcryption.load_public_key(public_path)
        
        logger.info(f"✓ Client {client_id} keys loaded")
        return private_key, public_key
    
    def save_client_public_key(self, client_id, public_key_pem):
        """
        Save client's public key (received via MQTT)
        
        Args:
            client_id: Client identifier
            public_key_pem: PEM string of public key
        """
        client_dir = self.clients_dir / client_id
        client_dir.mkdir(exist_ok=True)
        
        public_path = client_dir / f"{client_id}_public.pem"
        save_key_to_file(public_key_pem, public_path, is_private=False)
        
        logger.info(f"✓ Saved public key for client {client_id}")
    
    def load_client_public_key(self, client_id):
        """Load client's public key"""
        public_path = self.clients_dir / client_id / f"{client_id}_public.pem"
        
        if not public_path.exists():
            raise FileNotFoundError(f"Client {client_id} public key not found")
        
        return self.signcryption.load_public_key(public_path)
    
    def get_all_client_ids(self):
        """Get list of all registered client IDs"""
        client_ids = []
        for client_dir in self.clients_dir.iterdir():
            if client_dir.is_dir():
                client_ids.append(client_dir.name)
        return sorted(client_ids)
    
    # ==================== Key Rotation ====================
    def backup_keys(self, entity, round_num):
        """
        Backup keys before rotation
        
        Args:
            entity: "server" or client_id
            round_num: Current round number
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{entity}_round{round_num}_{timestamp}"
        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(exist_ok=True)
        
        if entity == "server":
            source_dir = self.server_dir
        else:
            source_dir = self.clients_dir / entity
        
        # Copy all .pem files
        for pem_file in source_dir.glob("*.pem"):
            shutil.copy2(pem_file, backup_path)
        
        logger.info(f"✓ Backed up keys for {entity}: {backup_path}")
        return str(backup_path)
    
    def rotate_server_keys(self, round_num, reason="scheduled"):
        """
        Rotate server keys
        
        Args:
            round_num: Current round number
            reason: Reason for rotation
        
        Returns:
            str: New public key PEM
        """
        logger.info(f"Rotating server keys at round {round_num}")
        
        # Backup old keys
        self.backup_keys("server", round_num)
        
        # Generate new keys
        self.generate_server_keys(force=True)
        
        # Record rotation
        self.add_rotation_record("server", round_num, reason)
        
        # Return new public key
        return self.get_server_public_key_pem()
    
    def rotate_client_keys(self, client_id, round_num, reason="scheduled"):
        """
        Rotate client keys
        
        Args:
            client_id: Client identifier
            round_num: Current round number
            reason: Reason for rotation
        
        Returns:
            str: New public key PEM
        """
        logger.info(f"Rotating keys for client {client_id} at round {round_num}")
        
        # Backup old keys
        self.backup_keys(client_id, round_num)
        
        # Generate new keys
        private_path, public_path = self.generate_client_keys(client_id, force=True)
        
        # Record rotation
        self.add_rotation_record(client_id, round_num, reason)
        
        # Return new public key
        with open(public_path, 'r') as f:
            return f.read()
    
    def should_rotate_keys(self, current_round, rotation_interval):
        """
        Check if keys should be rotated
        
        Args:
            current_round: Current round number
            rotation_interval: Rotate every N rounds
        
        Returns:
            bool: True if should rotate
        """
        if rotation_interval <= 0:
            return False
        
        return current_round > 0 and current_round % rotation_interval == 0
    
    # ==================== Utility ====================
    def get_rotation_stats(self):
        """Get key rotation statistics"""
        stats = {
            "total_rotations": len(self.rotation_history["rotations"]),
            "current_version": self.rotation_history["current_version"],
            "entities_rotated": set(),
            "last_rotation": None
        }
        
        for record in self.rotation_history["rotations"]:
            stats["entities_rotated"].add(record["entity"])
        
        stats["entities_rotated"] = list(stats["entities_rotated"])
        
        if self.rotation_history["rotations"]:
            stats["last_rotation"] = self.rotation_history["rotations"][-1]
        
        return stats
    
    def verify_key_integrity(self, entity):
        """
        Verify that keys exist and are readable
        
        Args:
            entity: "server" or client_id
        
        Returns:
            bool: True if keys are valid
        """
        try:
            if entity == "server":
                self.load_server_keys()
            else:
                self.load_client_keys(entity)
            return True
        except Exception as e:
            logger.error(f"Key integrity check failed for {entity}: {e}")
            return False


# ==================== Testing ====================
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    print("=" * 70)
    print("KEY MANAGER - TEST")
    print("=" * 70)
    
    # Create test directory
    test_dir = Path("./test_keys")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    
    # Initialize manager
    manager = KeyManager(base_dir=test_dir)
    
    # Test 1: Generate server keys
    print("\n[Test 1] Generating server keys...")
    manager.generate_server_keys()
    server_priv, server_pub = manager.load_server_keys()
    print("✓ Server keys OK")
    
    # Test 2: Generate client keys
    print("\n[Test 2] Generating client keys...")
    manager.generate_client_keys("client1")
    manager.generate_client_keys("client2")
    print(f"✓ Clients: {manager.get_all_client_ids()}")
    
    # Test 3: Key rotation
    print("\n[Test 3] Testing key rotation...")
    manager.rotate_server_keys(round_num=50, reason="testing")
    manager.rotate_client_keys("client1", round_num=50, reason="testing")
    print("✓ Keys rotated")
    
    # Test 4: Stats
    print("\n[Test 4] Rotation statistics...")
    stats = manager.get_rotation_stats()
    print(f"  Total rotations: {stats['total_rotations']}")
    print(f"  Entities rotated: {stats['entities_rotated']}")
    print(f"  Current version: {stats['current_version']}")
    
    # Test 5: Verify integrity
    print("\n[Test 5] Verifying key integrity...")
    assert manager.verify_key_integrity("server"), "Server keys invalid"
    assert manager.verify_key_integrity("client1"), "Client1 keys invalid"
    print("✓ All keys valid")
    
    # Cleanup
    shutil.rmtree(test_dir)
    
    print("\n" + "=" * 70)
    print("ALL TESTS PASSED!")
    print("=" * 70)
