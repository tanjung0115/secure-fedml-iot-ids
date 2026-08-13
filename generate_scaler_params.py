import pandas as pd
import json
import os
from sklearn.preprocessing import StandardScaler

# --- CONFIG ---
base_path = "/home/kraken/fedml-rsa-aes/"
# Kita ambil dari file bersih sebelum dipecah (Cleaned 10%)
# Ini mewakili statistik global yang paling akurat
input_file = os.path.join(base_path, "cleaned/ciciot2023_cleaned_10percent.csv")
output_json = os.path.join(base_path, "partitioned_data/scaler_params.json")

print("==================================================")
print("   CALCULATE GLOBAL SCALER PARAMETERS")
print("==================================================")

# 1. Load Data (Kita cuma butuh fitur, buang label)
print("[LOAD] Membaca data untuk menghitung statistik global...")
# Tips: Kita load semua karena RAM 32GB Bos kuat untuk 4.6 juta baris.
# Kalau mau hemat RAM, bisa pakai chunking, tapi StandardScaler butuh 
# melihat semua data untuk hasil presisi (atau pakai partial_fit).
# Untuk akurasi S1, load all is best.
df = pd.read_csv(input_file)

# Pisahkan Fitur dan Label
# Kita hanya menormalisasi 11 fitur input, Label JANGAN dinormalisasi.
# Pastikan nama kolom 'label' sesuai dengan yang ada di CSV
if 'label' in df.columns:
    X = df.drop(columns=['label']) 
else:
    print("[WARNING] Kolom 'label' tidak ditemukan, menggunakan semua kolom.")
    X = df

columns = X.columns.tolist()
print(f"[INFO] Menghitung Mean & Std Dev untuk {len(columns)} fitur...")
print(f"       Fitur: {columns}")

# 2. Fit StandardScaler
scaler = StandardScaler()
scaler.fit(X)

# 3. Ambil Parameternya
# mean_: Rata-rata global
# scale_: Standar deviasi global (pembagi)
scaler_params = {
    "mean": scaler.mean_.tolist(),
    "scale": scaler.scale_.tolist(),
    "var": scaler.var_.tolist(), # Varian, jaga-jaga kalau butuh
    "columns": columns
}

# 4. Simpan ke JSON
print("\n--- HASIL PARAMETER GLOBAL (PREVIEW) ---")
print(f"{'Fitur':<15} | {'Mean':<10} | {'Scale':<10}")
print("-" * 45)
for i, col in enumerate(columns):
    print(f"{col:<15} | {scaler.mean_[i]:.4f}     | {scaler.scale_[i]:.4f}")

with open(output_json, 'w') as f:
    json.dump(scaler_params, f, indent=4)

print("--------------------------------------------------")
print(f"[SUCCESS] Parameter tersimpan di: {output_json}")
print("WAJIB: Kirim file ini ke semua Raspberry Pi bersamaan dengan label_map.json!")
print("==================================================")
