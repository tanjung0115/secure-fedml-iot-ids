# Reconstruction Notes

This repository was reconstructed from the project archive available in the user's uploaded files.

## Verified from the recovered source

- Main secured client: `fedml_client_rsa_aes.py`
- Main secured server: `fedml_server_rsa_aes.py`
- Main model definitions: `model.py`
- RSA-AES signcryption: `crypto/signcryption.py`
- RSA key management: `crypto/key_manager_rsa_aes.py`
- MQTT transport configuration: `mqtt_config.yaml`

## Important verification items before public release

1. The recovered `fedml_config.yaml` currently specifies `client_num_in_total: 6` and `client_num_per_round: 6`, while the accepted paper reports seven Raspberry Pi clients. This must be reconciled against the exact final experiment configuration before the repository is described as reproducing the paper.
2. The recovered `fedml_server_rsa_aes.py` contains a sample-weighted FedAvg aggregation implementation. No HAAA or FedProx aggregation implementation was found in this recovered archive. Do not claim that this repository implements HAAA/FedProx until the final experiment code is recovered or added from the actual source used for the paper.
3. The archive contained RSA private keys, PQC private keys, datasets, checkpoints, logs, packet captures, and other generated artifacts. These are intentionally excluded from this public repository.
4. The original MQTT configuration contained a deployment-specific broker address. The public-safe template uses `localhost`; configure the actual broker locally.

These notes are intentionally kept with the reconstruction so that the GitHub repository does not make claims that cannot be verified from the recovered source.
