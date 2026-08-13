#!/usr/bin/env python3
"""
Skrip utilitas untuk membagi KDDTrain+.txt menjadi 2 partisi
untuk simulasi Federated Learning.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
import os
from pathlib import Path	

# Path ke file asli
DATA_DIR = Path("../data")
TRAIN_FILE_IN = DATA_DIR / "KDDTrain+.txt"

# Path untuk file output
PARTITION_DIR = DATA_DIR / "partitions"
TRAIN_FILE_OUT_1 = PARTITION_DIR / "KDDTrain+1.txt"
TRAIN_FILE_OUT_2 = PARTITION_DIR / "KDDTrain+2.txt"

# Buat direktori jika belum ada
PARTITION_DIR.mkdir(exist_ok=True)

print(f"Memuat dataset asli dari: {TRAIN_FILE_IN}...")
try:
    # Muat dataset (tanpa header)
    df = pd.read_csv(TRAIN_FILE_IN, header=None)
except FileNotFoundError:
    print(f"ERROR: File tidak ditemukan. Pastikan {TRAIN_FILE_IN} ada.")
    exit(1)

print(f"Total {len(df)} baris data training dimuat.")

# Membagi data menjadi 2 bagian (50/50)
# 'shuffle=True' penting agar kedua klien dapat data yang teracak
df_client1, df_client2 = train_test_split(df, test_size=0.5, shuffle=True, random_state=42)

print(f"Membagi data:")
print(f"  - Klien 1: {len(df_client1)} baris")
print(f"  - Klien 2: {len(df_client2)} baris")

# Simpan ke file .txt baru tanpa header dan tanpa index
df_client1.to_csv(TRAIN_FILE_OUT_1, header=False, index=False)
df_client2.to_csv(TRAIN_FILE_OUT_2, header=False, index=False)

print(f"\nBERHASIL!")
print(f"Partisi 1 disimpan ke: {TRAIN_FILE_OUT_1}")
print(f"Partisi 2 disimpan ke: {TRAIN_FILE_OUT_2}")
