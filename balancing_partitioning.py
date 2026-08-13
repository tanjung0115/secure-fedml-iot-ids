import pandas as pd
import os
import numpy as np

# 1. Konfigurasi
input_file = "merged/ciciot2023_merged_11features.csv"
output_dir = "partitioned_data"
SAMPLES_PER_NODE = 20000  # Target jumlah data per node

# Buat folder output jika belum ada
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# ---------------------------------------------------------
# FUNGSI GROUPING
# ---------------------------------------------------------
def get_node_group(label):
    label = str(label)
    if 'DDoS' in label: return 1        
    elif 'DoS' in label: return 2       
    elif 'Mirai' in label: return 3     
    elif 'Benign' in label: return 4    
    elif 'Recon' in label or 'Vulnerability' in label or 'Port' in label or 'Ping' in label or 'OS' in label: 
        return 5                        
    elif 'Brute' in label or 'Injection' in label or 'XSS' in label or 'Sql' in label: 
        return 6                        
    else: 
        return 7                        # Node 7: Malware

# ---------------------------------------------------------
# TAHAP 2: STREAMING & FILTERING (Hemat RAM)
# ---------------------------------------------------------
print("🚀 Memulai proses Streaming (Chunking)...")

# Kita siapkan wadah sementara (List) untuk menampung sampel
collected_chunks = []

# Baca file sedikit demi sedikit (misal per 100.000 baris)
chunk_size = 100000
total_processed = 0

# Loop membaca file
for chunk in pd.read_csv(input_file, chunksize=chunk_size, dtype={'label': str}):
    
    # 1. Tentukan Group untuk chunk ini
    chunk['Group'] = chunk['label'].apply(get_node_group)
    
    # 2. STRATEGI HEMAT RAM:
    # - Untuk Node 7 (Malware): AMBIL SEMUA (Karena datanya langka)
    # - Untuk Node 1-6 (Data Raksasa): AMBIL 5% SAJA secara acak dari chunk ini.
    #   (5% dari 46 juta = 2,3 juta. Masih cukup untuk nanti dipilih 20.000 terbaik, tapi RAM aman)
    
    # Pisahkan Malware dan Non-Malware
    df_malware = chunk[chunk['Group'] == 7]
    df_others  = chunk[chunk['Group'] != 7]
    
    # Ambil sampel kecil dari data raksasa (5% chance)
    df_others_sample = df_others.sample(frac=0.05, random_state=42)
    
    # Gabungkan dan simpan ke wadah sementara
    collected_chunks.append(df_malware)
    collected_chunks.append(df_others_sample)
    
    total_processed += len(chunk)
    print(f"   -> Memproses baris ke-{total_processed}...", end='\r')

print("\n✅ Selesai membaca file! Menggabungkan sampel...")

# Gabungkan semua potongan kecil tadi jadi satu DataFrame yang RAM-friendly
# Ukurannya sekarang mungkin hanya sekitar 2-3 juta baris (bukan 46 juta lagi)
df_reduced = pd.concat(collected_chunks, ignore_index=True)
print(f"Dataset dikompresi menjadi: {len(df_reduced)} baris.")

# ---------------------------------------------------------
# TAHAP 3: FINAL BALANCING (Pas 20.000)
# ---------------------------------------------------------
print("\n⚖️ Melakukan Final Balancing (Target: 20.000/node)...")

node_dataframes = {}

for i in range(1, 8):
    df_temp = df_reduced[df_reduced['Group'] == i]
    count_awal = len(df_temp)
    
    print(f"   -> Node {i} (Kandidat Tersedia): {count_awal} baris")
    
    if count_awal == 0:
        print(f"⚠️ PERINGATAN: Tidak ada data untuk Node {i}!")
        continue

    if count_awal > SAMPLES_PER_NODE:
        # Undersampling Final
        df_resampled = df_temp.sample(n=SAMPLES_PER_NODE, replace=False, random_state=42)
    else:
        # Oversampling Final (Duplikasi)
        df_resampled = df_temp.sample(n=SAMPLES_PER_NODE, replace=True, random_state=42)
    
    node_dataframes[i] = df_resampled

# ---------------------------------------------------------
# TAHAP 4: SAVING (IID & NON-IID)
# ---------------------------------------------------------

# === SKENARIO A: NON-IID ===
print("\n💾 Menyimpan File NON-IID...")
for i, df_node in node_dataframes.items():
    save_df = df_node.drop(columns=['Group'])
    filename = f"{output_dir}/node{i}_noniid.csv"
    save_df.to_csv(filename, index=False)
    print(f"   Saved: {filename}")

# === SKENARIO B: IID ===
print("\n🔄 Memproses Skenario IID...")
all_balanced_data = pd.concat(node_dataframes.values())
# Shuffle Total
all_balanced_data = all_balanced_data.sample(frac=1, random_state=42).reset_index(drop=True)
# Bagi 7
iid_chunks = np.array_split(all_balanced_data, 7)

print("💾 Menyimpan File IID...")
for i, chunk in enumerate(iid_chunks):
    node_id = i + 1
    save_df = chunk.drop(columns=['Group'])
    filename = f"{output_dir}/node{node_id}_iid.csv"
    save_df.to_csv(filename, index=False)
    print(f"   Saved: {filename}")

print("\n🎉 SEMUA BERHASIL! Silakan cek folder 'partitioned_data'.")
