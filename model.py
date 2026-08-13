#!/usr/bin/env python3
"""
Shared Model Definitions for Federated Learning IDS
CICIoT2023 Dataset - 11 features, 9 attack classes

Arsitektur yang tersedia:
  - IDSModel   : Funnel DNN (128-64-32-9)  — ~12,169 params  [model_type="dnn"]
  - CNNModel   : 1D-CNN (Conv1d x2 + FC)   — ~33,801 params  [model_type="cnn"]
  - MLPModel   : MLP sederhana (64→9)       —  ~1,353 params  [model_type="mlp"]

Diimpor oleh fedml_server_rsa_aes.py dan fedml_client_rsa_aes.py
untuk memastikan arsitektur model IDENTIK di server dan semua client.
"""

import torch
import torch.nn as nn


class IDSModel(nn.Module):
    """
    Funnel DNN — Arsitektur utama penelitian.

    Architecture:
        Input (11) → FC(128) → ReLU → Dropout(0.2) →
        FC(64) → ReLU → FC(32) → ReLU → FC(9) → LogSoftmax

    Total params: ~12,169
    """

    def __init__(self, input_dim: int = 11, hidden_dim: int = 128, output_dim: int = 9):
        super(IDSModel, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, 64)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, output_dim)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.2)
        self.softmax = nn.LogSoftmax(dim=1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.relu(self.fc2(x))
        x = self.relu(self.fc3(x))
        x = self.fc4(x)
        return self.softmax(x)


class CNNModel(nn.Module):
    """
    1D-CNN untuk klasifikasi traffic IoT.

    Architecture:
        Input (B,11) → unsqueeze → (B,1,11)
        → Conv1d(1→64, k=3, pad=1) → ReLU    : (B,64,11)
        → Conv1d(64→128, k=3, pad=1) → ReLU  : (B,128,11)
        → AdaptiveAvgPool1d(1)                : (B,128,1)
        → squeeze → FC(128→64) → ReLU → FC(64→9) → LogSoftmax

    Total params: ~33,801
    """

    def __init__(self, input_dim: int = 11, output_dim: int = 9):
        super(CNNModel, self).__init__()
        self.features = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1),
        )
        self.classifier = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, output_dim),
            nn.LogSoftmax(dim=1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x.unsqueeze(1)          # (B,11) → (B,1,11)
        x = self.features(x)
        x = x.squeeze(-1)           # (B,128,1) → (B,128)
        return self.classifier(x)


class MLPModel(nn.Module):
    """
    MLP sederhana — 1 hidden layer sebagai baseline.

    Architecture:
        Input (11) → FC(64) → ReLU → FC(9) → LogSoftmax

    Total params: ~1,353
    """

    def __init__(self, input_dim: int = 11, output_dim: int = 9):
        super(MLPModel, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, output_dim),
            nn.LogSoftmax(dim=1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def get_model(model_type: str, input_dim: int = 11,
              hidden_dim: int = 128, output_dim: int = 9) -> nn.Module:
    """
    Factory function — kembalikan instance model sesuai model_type.

    Args:
        model_type : "dnn" | "cnn" | "mlp"
        input_dim  : jumlah fitur input (default 11)
        hidden_dim : ukuran hidden layer pertama untuk DNN (default 128)
        output_dim : jumlah kelas output (default 9)
    """
    mt = model_type.lower().strip()
    if mt == "cnn":
        return CNNModel(input_dim=input_dim, output_dim=output_dim)
    elif mt == "mlp":
        return MLPModel(input_dim=input_dim, output_dim=output_dim)
    else:
        return IDSModel(input_dim=input_dim, hidden_dim=hidden_dim, output_dim=output_dim)


if __name__ == "__main__":
    for mt in ("dnn", "cnn", "mlp"):
        m = get_model(mt)
        n = sum(p.numel() for p in m.parameters())
        print(f"[{mt.upper():3s}] {m.__class__.__name__:12s} — {n:>7,} params")
