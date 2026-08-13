import pandas as pd
import glob
import os

# --- PATH DATASET ---
path_dataset = "/home/kraken/fedml-rsa-aes/cic-iot-2023/"
output_filename = "/home/kraken/fedml-rsa-aes/merged/ciciot2023_merged_11features.csv"

# Pastikan folder output ada
os.makedirs(os.path.dirname(output_filename), exist_ok=True)

all_files = glob.glob(os.path.join(path_dataset, "*.csv"))
all_files.sort() # Urutkan biar rapi part-00 s/d part-168
print(f"Total file ditemukan: {len(all_files)} part.")

# --- TARGET KOLOM (SESUAI PAPER) ---
target_columns = [
    'IAT', 'Weight', 'Min', 'rst count', 'AVG', 'Number',
    'urg count', 'Variance', 'Protocol Type', 'ICMP', 'fin count',
    'label'
]

# --- KAMUS ALIAS (PENERJEMAH) ---
# Kiri: Nama yang kita mau (Paper)
# Kanan: Nama yang mungkin ada di CSV (Underscore/Spasi)
column_aliases = {
    'rst count': ['rst_count', 'rst count'],
    'urg count': ['urg_count', 'urg count'],
    'fin count': ['fin_count', 'fin count'],
    'Protocol Type': ['Protocol Type', 'Protocol', 'Protocol_Type'],
    'IAT': ['IAT', 'iat'],
    'Weight': ['Weight', 'weight'],
    'Min': ['Min', 'min'],
    'AVG': ['AVG', 'avg'],
    'Number': ['Number', 'number'],
    'Variance': ['Variance', 'variance'],
    'ICMP': ['ICMP', 'icmp'],
    'label': ['label', 'class']
}

print("Mulai Smart Merging...")
first_file = True
sukses_count = 0
error_count = 0

for i, filename in enumerate(all_files):
    try:
        # 1. Intip Header dulu
        header_df = pd.read_csv(filename, nrows=0)
        file_cols = header_df.columns.tolist()
        
        # 2. Cocokkan target dengan alias yang ada di file
        current_usecols = []
        rename_map = {} 
        
        for target in target_columns:
            found = False
            # Cek semua kemungkinan alias untuk target ini
            possible_names = column_aliases.get(target, [target])
            
            for alias in possible_names:
                if alias in file_cols:
                    current_usecols.append(alias)
                    # Kalau namanya beda (misal rst_count), catat buat direname jadi rst count
                    if alias != target:
                        rename_map[alias] = target
                    found = True
                    break # Dah ketemu satu, lanjut ke target berikutnya
            
            if not found:
                # Kolom wajib gak ketemu? Skip file ini atau biarkan (nanti diisi NaN/Error)
                pass

        # 3. Load data
        if len(current_usecols) > 0:
            df = pd.read_csv(filename, usecols=current_usecols)
            
            # 4. Standardisasi Nama Kolom (Underscore -> Spasi)
            if rename_map:
                df.rename(columns=rename_map, inplace=True)
                
            # Pastikan urutan kolom rapi sesuai target
            # (Hanya kolom yang berhasil ditemukan)
            final_cols = [c for c in target_columns if c in df.columns]
            df = df[final_cols]

            # 5. Simpan ke Disk
            if first_file:
                df.to_csv(output_filename, mode='w', index=False, header=True)
                first_file = False
            else:
                df.to_csv(output_filename, mode='a', index=False, header=False)
            
            sukses_count += 1
        
        if (i+1) % 20 == 0:
            print(f"Progress: {i+1}/{len(all_files)} files processed.")

    except Exception as e:
        print(f"Gagal di file {os.path.basename(filename)}: {e}")
        error_count += 1

print("------------------------------------------------")
print(f"SELESAI! Sukses: {sukses_count}, Gagal: {error_count}")
print(f"Output tersimpan di: {output_filename}")
