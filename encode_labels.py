import pandas as pd
import os
import json
import glob

# --- KONFIGURASI PATH (WAJIB SESUAI FINAL_DATA) ---
base_path = "/home/kraken/fedml-rsa-aes/"
data_dir = os.path.join(base_path, "final_data") # <--- Arahkan ke final_data

print("========================================================")
print("   FIXED LABEL ENCODING PIPELINE (TARGET: 9 CLASSES)    ")
print("========================================================")

# 1. Kumpulkan semua file di node1 sampai node7
files_to_process = glob.glob(os.path.join(data_dir, "node*", "*.csv"))

if not files_to_process:
    print("[ERROR] Tidak ada file CSV di final_data/node*! Cek path folder kamu.")
    exit(1)

# 2. Scanning Label (Harusnya cuma ketemu 9 label teks)
unique_labels = set()
for f in files_to_process:
    df_temp = pd.read_csv(f, usecols=['label'])
    unique_labels.update(df_temp['label'].unique().tolist())

# Buat Mapping (Urutan alfabet agar konsisten)
sorted_labels = sorted(list(unique_labels))
label_map = {label: i for i, label in enumerate(sorted_labels)}

print(f"[INFO] Total Label Unik Ditemukan: {len(label_map)}")
for label, idx in label_map.items():
    print(f"   {idx} -> {label}")

# 3. Simpan Mapping ke JSON (Gunakan native int agar tidak error int64)
try:
    with open("label_map.json", "w") as jf:
        json.dump(label_map, jf, indent=4)
    print("\n✅ label_map.json berhasil disimpan!")
except Exception as e:
    print(f"\n❌ Gagal menyimpan JSON: {e}")

# 4. In-place Encoding
for f in files_to_process:
    print(f"📦 Encoding {os.path.basename(os.path.dirname(f))}/{os.path.basename(f)}...", end=" ")
    df = pd.read_csv(f)
    df['label'] = df['label'].map(label_map)
    df.to_csv(f, index=False)
    print("DONE.")

print("========================================================")
print("🔥 SELESAI! Sekarang data di final_data sudah 100% murni angka (0-8).")
print("========================================================")