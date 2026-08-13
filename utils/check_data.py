import pandas as pd
import glob
import os

# Ambil semua file csv di folder hasil
files = sorted(glob.glob("partitioned_data/*.csv"))

print("=== LAPORAN VALIDASI DATASET ===")

for f in files:
    # Baca file
    df = pd.read_csv(f)
    
    # Ambil nama file biar rapi
    filename = os.path.basename(f)
    
    print(f"\n📂 File: {filename}")
    print(f"   ✅ Jumlah Baris: {len(df)}")
    print(f"   📊 Isi Label (Top 3 Terbanyak):")
    print(df['label'].value_counts().head(3).to_string())
    print("-" * 30)
