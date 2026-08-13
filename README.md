# Secure Federated Learning for IoT Intrusion Detection

This repository contains the implementation of a Raspberry Pi-based Federated Learning environment for IoT intrusion detection using CICIoT2023. Model updates exchanged between clients and the federated server are protected using RSA-AES signcryption.

## Scope

- Federated Learning for IoT intrusion detection
- CICIoT2023-based classification pipeline
- MQTT communication between clients and server
- RSA-2048 + AES-256-GCM signcryption for model-update protection
- RSA-PSS signatures for authenticated control messages
- Replay protection using timestamps and nonces
- Payload-size and model-round validation
- PyTorch local training on CPU

## Repository structure

```text
.
├── fedml_client_rsa_aes.py      # Federated client
├── fedml_server_rsa_aes.py      # Federated server and aggregation
├── model.py                     # Shared DNN/CNN/MLP definitions
├── fedml_config.yaml            # FL/model/training configuration
├── mqtt_config.yaml             # MQTT configuration template
├── crypto/
│   ├── signcryption.py          # RSA-AES signcryption
│   └── key_manager_rsa_aes.py   # RSA key management
├── scripts/
│   ├── generate_keys.py
│   ├── generate_certs.sh
│   ├── run_server.sh
│   ├── run_client.sh
│   └── ...
├── tests/
│   ├── test_crypto_workflow.py
│   ├── security_test.py
│   └── test_local.py
└── utils/
    └── split_data.py
```

## Model

The main DNN model uses 11 input features and 9 output classes. The default DNN architecture is:

`11 → 128 → 64 → 32 → 9`

with ReLU activations, dropout, and LogSoftmax output.

## Security

Model updates are signcrypted using a hybrid RSA-AES construction:

1. The model-update payload is signed with RSA-PSS/SHA-256.
2. A random AES-256 key encrypts the payload using AES-GCM.
3. The AES session key is encrypted using RSA-OAEP/SHA-256.
4. The receiver decrypts the session key and verifies the signature before accepting the update.

The implementation also checks timestamps, nonces, round numbers, client membership, payload size, and model-state keys.

## Data

The dataset itself is intentionally **not included** in this repository. Prepare the required client-side files under the configured data directory before running the experiment.

Do not commit private keys, credentials, raw network traffic, packet captures, model checkpoints, or logs.

## Configuration

Before running the system, review `fedml_config.yaml` and `mqtt_config.yaml`. The repository uses `localhost` as the public-safe default broker address; replace it with the address of your own MQTT broker in your local environment.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows:

```powershell
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
```

## Keys

Generate a fresh key set locally. Never copy the original project private keys into this repository.

```bash
python scripts/generate_keys.py
```

If TLS is enabled for MQTT, generate and configure certificates separately.

## Running

Start the federated server:

```bash
python fedml_server_rsa_aes.py
```

Start a client:

```bash
python fedml_client_rsa_aes.py --client_id rpi_client1
```

The exact client IDs, data paths, and MQTT broker settings must match your local deployment.

## Reproducibility note

This repository is a cleaned recovery of the implementation files stored in the original project archive. The original archive also contained historical experiments, datasets, logs, checkpoints, PQC code, and private keys; those artifacts are deliberately excluded from this public repository.

Before publishing experimental claims, verify the final experiment configuration against the camera-ready paper, particularly the number of active clients and the exact aggregation implementation used for each reported result.
