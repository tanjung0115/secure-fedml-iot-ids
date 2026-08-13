import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import os
import json

# --- CONFIG ---
master_path = "/home/kraken/fedml-rsa-aes/master_cleaned.csv"
output_dir = "/home/kraken/fedml-rsa-aes/final_data"
num_nodes = 7

print("🚀 Memulai Proses Scaling & Pemisahan (IID + REAL Non-IID)...")

df = pd.read_csv(master_path)

# 1. Encoding & Scaling (Sama seperti sebelumnya)
labels = sorted(df['label'].unique())
label_to_id = {label: i for i, label in enumerate(labels)}
df['label'] = df['label'].map(label_to_id)
features = [c for c in df.columns if c != 'label']
scaler = StandardScaler()
df[features] = scaler.fit_transform(df[features])

# --- PROSES IID (Merata) ---
print("📦 Menghasilkan Skenario IID...")
iid_df = df.sample(frac=1, random_state=42)
iid_chunks = np.array_split(iid_df, num_nodes)

# --- PROSES NON-IID (Real Label Skew) ---
print("📦 Menghasilkan Skenario Non-IID (Label Skew 80/20)...")
non_iid_chunks = [pd.DataFrame() for _ in range(num_nodes)]

for label_id in range(len(labels)):
    label_data = df[df['label'] == label_id].sample(frac=1, random_state=42)
    if label_data.empty: continue
    
    # Tentukan Node Utama untuk label ini (Specialist Node)
    main_node = label_id % num_nodes
    
    # Berikan 80% data label ini ke node utama
    # Sisanya 20% dibagi ke node-node lain agar tetap ada data penguji
    split_idx = int(len(label_data) * 0.8)
    main_part = label_data.iloc[:split_idx]
    other_parts = np.array_split(label_data.iloc[split_idx:], num_nodes)
    
    for i in range(num_nodes):
        if i == main_node:
            # Node utama dapat porsi besar + porsi kecilnya
            non_iid_chunks[i] = pd.concat([non_iid_chunks[i], main_part, other_parts[i]])
        else:
            # Node lain cuma dapat porsi remahan (kecil)
            non_iid_chunks[i] = pd.concat([non_iid_chunks[i], other_parts[i]])

# --- PENYIMPANAN ---
for i in range(num_nodes):
    node_path = os.path.join(output_dir, f"node{i+1}")
    os.makedirs(node_path, exist_ok=True)
    
    # IID
    iid_chunks[i].sample(frac=0.8).to_csv(f"{node_path}/iid_train.csv", index=False)
    iid_chunks[i].sample(frac=0.2).to_csv(f"{node_path}/iid_test.csv", index=False)
    
    # Non-IID
    non_iid_chunks[i].sample(frac=0.8).to_csv(f"{node_path}/non_iid_train.csv", index=False)
    non_iid_chunks[i].sample(frac=0.2).to_csv(f"{node_path}/non_iid_test.csv", index=False)
    
    # CEK JUJUR: Tampilkan ukuran tiap node
    print(f"✅ Node {i+1} Beres - Non-IID Rows: {len(non_iid_chunks[i])}")

print("\n🔥 SELESAI! Sekarang ukuran file pasti akan beda-beda tiap node.")