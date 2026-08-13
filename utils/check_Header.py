import pandas as pd

# Lokasi File (Ganti path sesuai server Bos)
path_base = "/home/kraken/fedml-rsa-aes/cic-iot-2023/"

# 1. File yang ERROR tadi (part-00007)
file_error = path_base + "part-00007-363d1ba3-8ab5-4f96-bc25-4d5862db7cb9-c000.csv"

# 2. File yang (kemungkinan) SUKSES (part-00000)
file_sukses = path_base + "part-00000-363d1ba3-8ab5-4f96-bc25-4d5862db7cb9-c000.csv"

def cek_kolom(path, label):
    try:
        # Baca cuma 1 baris header aja
        df = pd.read_csv(path, nrows=0)
        print(f"\n--- HEADER FILE {label} ---")
        # Print kolom yang mengandung kata kunci bermasalah
        cols = df.columns.tolist()
        check_list = ['rst', 'urg', 'fin', 'IAT']
        
        found = []
        for c in cols:
            for k in check_list:
                if k in c:
                    found.append(c)
        print(f"Kolom ditemukan: {found}")
        
    except Exception as e:
        print(f"Gagal baca {label}: {e}")

cek_kolom(file_sukses, "SUKSES (Part 00)")
cek_kolom(file_error, "ERROR (Part 07)")
