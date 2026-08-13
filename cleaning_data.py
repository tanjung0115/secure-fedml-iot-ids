import pandas as pd
import os
import gc  # Garbage Collector untuk manajemen memori manual

# --- KONFIGURASI PATH ---
# Pastikan path ini sesuai dengan struktur folder di laptop Bos
base_path = "/home/kraken/fedml-rsa-aes/"
input_file = os.path.join(base_path, "merged/ciciot2023_merged_11features.csv")
output_folder = os.path.join(base_path, "cleaned/")
output_file = os.path.join(output_folder, "ciciot2023_cleaned_10percent.csv")

# Buat folder output jika belum ada
os.makedirs(output_folder, exist_ok=True)

# Ukuran per "suapan" (1 Juta baris).
# Ini trik agar RAM tidak meledak saat baca file 46 juta baris.
CHUNK_SIZE = 1_000_000 

print("========================================================")
print("   PIPELINE DATA CLEANING & SAMPLING (RAM-SAFE MODE)    ")
print("========================================================")
print(f"[INPUT]  {input_file}")
print(f"[OUTPUT] {output_file}")
print("--------------------------------------------------------")

sampled_chunks = []
total_raw_rows = 0

try:
    # ---------------------------------------------------------
    # TAHAP 1: BACA FILE & LANGSUNG SAMPLING (METODE CHUNKING)
    # ---------------------------------------------------------
    print("\n[STEP 1] Membaca file dan mengambil sample 10% per bagian...")
    
    # Membaca file secara streaming (sedikit demi sedikit)
    with pd.read_csv(input_file, chunksize=CHUNK_SIZE) as reader:
        for i, chunk in enumerate(reader):
            # Hitung total baris mentah
            total_raw_rows += len(chunk)
            
            # Sesuai Paper: "sampled to 10% using a simple random sampling method" 
            # random_state=42 menjamin hasil acak yang konsisten (reproducible)
            chunk_sample = chunk.sample(frac=0.1, random_state=42)
            
            # Simpan potongan sample ke list
            sampled_chunks.append(chunk_sample)
            
            # Print progress setiap 5 juta baris
            if (i+1) % 5 == 0:
                print(f"   -> Progress: {total_raw_rows:,} baris mentah telah diproses...")

    print(f"[INFO] Total Data Mentah Terbaca: {total_raw_rows:,} baris")
    print(f"[INFO] Total Potongan Sample: {len(sampled_chunks)} chunks")

    # ---------------------------------------------------------
    # TAHAP 2: PENGGABUNGAN SAMPLE (MERGING)
    # ---------------------------------------------------------
    print("\n[STEP 2] Menggabungkan hasil sample ke dalam RAM...")
    df_final = pd.concat(sampled_chunks, ignore_index=True)
    
    # Hapus list chunk dari memori agar lega
    del sampled_chunks
    gc.collect()
    
    print(f"[INFO] Ukuran Dataset Sample Sementara: {df_final.shape[0]:,} baris")

    # ---------------------------------------------------------
    # TAHAP 3: PEMBERSIHAN (CLEANING)
    # ---------------------------------------------------------
    print("\n[STEP 3] Membersihkan Data (Missing Values & Duplikat)...")
    
    initial_rows = df_final.shape[0]
    
    # 1. Cek Missing Values
    if df_final.isnull().sum().sum() > 0:
        df_final.dropna(inplace=True)
        print("   -> Found & Removed Missing Values (NaN).")
    
    # 2. Hapus Duplikat
    # Sesuai Paper: "Duplicate values found were then removed to avoid bias" [cite: 206]
    df_final.drop_duplicates(inplace=True)
    
    final_rows = df_final.shape[0]
    removed_rows = initial_rows - final_rows
    
    print(f"   -> Duplikat/NaN Dihapus : {removed_rows:,} baris")
    print(f"   -> TOTAL DATA BERSIH    : {final_rows:,} baris")

    # ---------------------------------------------------------
    # TAHAP 4: VALIDASI & PENYIMPANAN
    # ---------------------------------------------------------
    print("\n[STEP 4] Menyimpan Hasil Akhir...")
    
    # Cek sekilas isinya
    print("\n--- Distribusi Label (Top 5) ---")
    print(df_final['label'].value_counts().head(5))
    
    # Simpan ke CSV
    df_final.to_csv(output_file, index=False)
    
    print("--------------------------------------------------------")
    print("SUKSES! Script berjalan sempurna.")
    print(f"File siap pakai ada di: {output_file}")
    print("========================================================")

except FileNotFoundError:
    print("\n[ERROR] File input tidak ditemukan!")
    print("Pastikan Anda sudah menjalankan script 'merging_data.py' sebelumnya.")
    print(f"Cek path: {input_file}")

except Exception as e:
    print(f"\n[CRITICAL ERROR] Terjadi kesalahan: {e}")
