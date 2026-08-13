#!/usr/bin/env python3
"""
Key Generation Utility for Federated Learning
Generate and setup cryptographic keys for server and clients
"""

import sys
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto.key_manager_rsa_aes import KeyManager
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_server_keys(key_manager, force=False):
    """Setup server keys"""
    print("\n" + "=" * 70)
    print("SETTING UP SERVER KEYS")
    print("=" * 70)
    
    private_path, public_path = key_manager.generate_server_keys(force=force)
    
    print(f"\n✓ Server keys generated:")
    print(f"  Private key: {private_path} (SECRET - chmod 600)")
    print(f"  Public key:  {public_path}")
    
    # Display public key
    public_key_pem = key_manager.get_server_public_key_pem()
    print(f"\n📋 Server Public Key (share with clients):")
    print("-" * 70)
    print(public_key_pem)
    print("-" * 70)
    
    return private_path, public_path


def setup_client_keys(key_manager, client_ids, force=False):
    """Setup client keys"""
    print("\n" + "=" * 70)
    print(f"SETTING UP CLIENT KEYS ({len(client_ids)} clients)")
    print("=" * 70)
    
    for client_id in client_ids:
        print(f"\n[{client_id}]")
        private_path, public_path = key_manager.generate_client_keys(client_id, force=force)
        
        print(f"  ✓ Keys generated:")
        print(f"    Private: {private_path}")
        print(f"    Public:  {public_path}")


def setup_all_keys(num_clients=2, force=False):
    """Setup keys for server and all clients"""
    print("\n" + "=" * 70)
    print("FEDERATED LEARNING - KEY SETUP")
    print("=" * 70)
    print(f"  Clients: {num_clients}")
    print(f"  Force overwrite: {force}")
    print("=" * 70)
    
    # Initialize key manager
    key_manager = KeyManager(base_dir="./keys", key_size=2048)
    
    # Setup server
    setup_server_keys(key_manager, force=force)
    
    # Setup clients
    client_ids = [f"rpi_client{i+1}" for i in range(num_clients)]
    setup_client_keys(key_manager, client_ids, force=force)
    
    # Summary
    print("\n" + "=" * 70)
    print("SETUP COMPLETE!")
    print("=" * 70)
    print(f"\n✓ All keys generated in: ./keys/")
    print(f"  - Server keys: ./keys/server/")
    print(f"  - Client keys: ./keys/clients/")
    print(f"\n📋 Key Distribution:")
    print(f"  1. Copy ./keys/server/server_public.pem → to each client")
    print(f"  2. Each client sends their public key → to server via MQTT")
    print(f"\n⚠️  SECURITY:")
    print(f"  - Keep *_private.pem files SECRET")
    print(f"  - Never commit private keys to git")
    print(f"  - Use secure channels for key exchange")
    print("=" * 70)


def display_key_info(key_manager):
    """Display information about existing keys"""
    print("\n" + "=" * 70)
    print("EXISTING KEYS INFORMATION")
    print("=" * 70)
    
    # Server keys
    print("\n[SERVER]")
    if key_manager.verify_key_integrity("server"):
        print("  ✓ Server keys exist and are valid")
        public_key = key_manager.get_server_public_key_pem()
        print(f"  Public key preview: {public_key[:50]}...")
    else:
        print("  ✗ Server keys not found or invalid")
    
    # Client keys
    print("\n[CLIENTS]")
    client_ids = key_manager.get_all_client_ids()
    
    if client_ids:
        for client_id in client_ids:
            if key_manager.verify_key_integrity(client_id):
                print(f"  ✓ {client_id}: Valid")
            else:
                print(f"  ✗ {client_id}: Invalid")
    else:
        print("  No client keys found")
    
    # Rotation history
    print("\n[ROTATION HISTORY]")
    stats = key_manager.get_rotation_stats()
    print(f"  Total rotations: {stats['total_rotations']}")
    print(f"  Current version: {stats['current_version']}")
    
    if stats['last_rotation']:
        last = stats['last_rotation']
        print(f"  Last rotation:")
        print(f"    Entity: {last['entity']}")
        print(f"    Round: {last['round']}")
        print(f"    Time: {last['timestamp']}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate cryptographic keys for Federated Learning'
    )
    
    parser.add_argument(
        '--mode',
        choices=['setup', 'info', 'server-only', 'client'],
        default='setup',
        help='Operation mode'
    )
    
    parser.add_argument(
        '--num-clients',
        type=int,
        default=2,
        help='Number of clients (default: 2)'
    )
    
    parser.add_argument(
        '--client-id',
        type=str,
        help='Client ID for client-only mode'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force overwrite existing keys'
    )
    
    args = parser.parse_args()
    
    # Initialize key manager
    key_manager = KeyManager(base_dir="./keys", key_size=2048)
    
    # Execute based on mode
    if args.mode == 'setup':
        setup_all_keys(num_clients=args.num_clients, force=args.force)
    
    elif args.mode == 'info':
        display_key_info(key_manager)
    
    elif args.mode == 'server-only':
        setup_server_keys(key_manager, force=args.force)
    
    elif args.mode == 'client':
        if not args.client_id:
            print("Error: --client-id required for client mode")
            sys.exit(1)
        setup_client_keys(key_manager, [args.client_id], force=args.force)
    
    print()


if __name__ == "__main__":
    main()
