import pandas as pd
import glob
import os

# 1. Konfigurasi
input_dir = "partitioned_data"
output_base_dir = "final_data"
TRAIN_RATIO = 0.8  # 80% Training, sisanya 20% Testing

# Buat folder utama jika belum ada
if not os.path.exists(output_base_dir):
    os.makedirs(output_base_dir)

# Ambil semua file CSV hasil partisi kemarin
files = glob.glob(os.path.join(input_dir, "*.csv"))
files.sort()

print(f"🚀 Memulai Splitting untuk {len(files)} file...")

for f in files:
    # Contoh nama file: partitioned_data/node1_iid.csv
    filename = os.path.basename(f)  # node1_iid.csv
    
    # Parsing nama file untuk dapat Node ID dan Tipe (IID/NonIID)
    # format: nodeX_type.csv
    name_parts = filename.replace('.csv', '').split('_')
    node_name = name_parts[0]  # node1
    data_type = name_parts[1]  # iid atau noniid
    
    # Buat folder khusus per Node (biar rapi saat dikirim ke Pi)
    # Contoh: final_data/node1/
    node_dir = os.path.join(output_base_dir, node_name)
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    
    # Baca Data
    df = pd.read_csv(f)
    total_rows = len(df)
    
    # Lakukan Splitting 80:20
    # Kita acak dulu (sample frac=1) biar urutannya tidak bias
    train_df = df.sample(frac=TRAIN_RATIO, random_state=42)
    test_df = df.drop(train_df.index)  # Sisanya masuk ke Test
    
    # Simpan file Train dan Test
    # Nama file: iid_train.csv / noniid_test.csv
    train_file = os.path.join(node_dir, f"{data_type}_train.csv")
    test_file = os.path.join(node_dir, f"{data_type}_test.csv")
    
    train_df.to_csv(train_file, index=False)
    test_df.to_csv(test_file, index=False)
    
    print(f"✅ {node_name} [{data_type}]: Total {total_rows} -> Train {len(train_df)} | Test {len(test_df)}")

print("\n🎉 SELESAI! Struktur folder 'final_data' sudah siap dikirim ke Raspberry Pi.")
print("Struktur: final_data/nodeX/ [iid_train.csv, iid_test.csv, ...]")
