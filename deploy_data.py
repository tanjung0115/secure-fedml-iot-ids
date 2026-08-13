import os
import subprocess

# === KONFIGURASI TARGET (ISI BAGIAN INI BOS!) ===
# Format: { "folder_node": ("username_raspi", "ip_tailscale_raspi") }
# Pastikan username di raspi benar (biasanya 'pi', 'flids', atau lainnya)

nodes_map = {
    "node1": ("flids", "100.111.205.59"),   # Ganti user/IP node-a
    "node2": ("lalalala", "100.102.74.45"),   # Ganti user/IP node-b
    "node3": ("node-a", "100.109.203.47"),     # Ganti user/IP node-c
    "node4": ("node-b", "100.99.171.118"),     # Ganti user/IP node-d
    "node5": ("node-c",  "100.108.7.12"),   # Ganti user/IP flids
    "node6": ("node-d", "100.95.90.42"),  # Ganti user/IP lalalala
    "node7": ("node-e", "100.77.10.67"),  
}

# Folder tujuan di Raspberry Pi (Nanti data akan masuk ke folder ini)
remote_dest_dir = "~/fedml-rsa-aes/data"

# =================================================
print("🚀 Memulai Pengiriman Data ke Pasukan Raspi...")

for node_name, (user, ip) in nodes_map.items():
    local_path = f"final_data/{node_name}"
    
    print(f"\n📦 Mengirim {node_name} -> {user}@{ip}...")
    
    # 1. Buat folder dulu di sana (biar aman)
    cmd_mkdir = f"ssh -o StrictHostKeyChecking=no {user}@{ip} 'mkdir -p {remote_dest_dir}'"
    os.system(cmd_mkdir)
    
    # 2. Kirim isinya pakai SCP
    # -r = rekursif (satu folder)
    cmd_scp = f"scp -r {local_path}/* {user}@{ip}:{remote_dest_dir}"
    
    exit_code = os.system(cmd_scp)
    
    if exit_code == 0:
        print(f"   ✅ Sukses terkirim ke {ip}!")
    else:
        print(f"   ❌ Gagal kirim ke {ip}. Cek koneksi/username!")

print("\n🏁 Selesai!")
