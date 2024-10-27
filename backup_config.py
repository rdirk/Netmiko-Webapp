from netmiko import ConnectHandler
from datetime import datetime
import os
import shutil
import mysql.connector

# Fungsi untuk membuat direktori jika belum ada
def buat_direktori(path):
    if not os.path.exists(path):
        os.makedirs(path)
        # os.chmod(path, 0o777)

# Membuat direktori hasil-backup jika belum ada
backup_dir = 'backup'
buat_direktori(backup_dir)

def daftar_file_dan_direktori():
    direktori = 'backup'  # Sesuaikan dengan lokasi direktori output Anda
    daftar = []
    try:
        for item in os.listdir(direktori):
            full_path = os.path.join(direktori, item)
            if os.path.isfile(full_path):
                daftar.append(('file', item))
            elif os.path.isdir(full_path):
                daftar.append(('dir', item))
        return daftar
    except FileNotFoundError:
        return []

# Fungsi untuk mengambil kredensial dari database MySQL
def ambil_kredensial_dari_db():
    try:
        # Menghubungkan ke database
        conn = mysql.connector.connect(
            host="localhost",  # atau alamat IP server MySQL Anda
            user="root",  # ganti dengan username database Anda
            password="",  # ganti dengan password database Anda
            database="h2py"  # ganti dengan nama database Anda
        )
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT perangkat.device_type, perangkat.ip, perangkat.username, perangkat.password, perangkat.location, commands.command
        FROM perangkat
        JOIN commands ON perangkat.device_type = commands.device_type
        """
        cursor.execute(query)
        kredensial_list = cursor.fetchall()
        cursor.close()
        conn.close()
        return kredensial_list
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return []

# Mengganti bagian ini dengan fungsi ambil_kredensial_dari_db
kredensial_list = ambil_kredensial_dari_db()

# Debug: Cetak isi dari kredensial_dict
# print("Isi kredensial_dict:", kredensial_dict)

# Membuat list perangkat dari kredensial yang diambil
perangkat = []
for kred in kredensial_list:
    perangkat.append({
        'device_type': kred['device_type'],
        'host': kred['ip'],
        'username': kred['username'],
        'password': kred['password'],
        'port': 22,
        'command': kred.get('command', ''),
        'location': kred.get('location', '')
    })

# Debug: Cetak isi dari perangkat
# print("Isi perangkat:", perangkat)

# Fungsi untuk backup konfigurasi perangkat
def backup_konfigurasi(perangkat):
    for p in perangkat:
        if isinstance(p, dict):
            try:
                koneksi_args = {
                    'device_type': p['device_type'],
                    'host': p['host'],
                    'username': p['username'],
                    'password': p['password'],
                    'port': p['port'],
                    # 'disabled_algorithms': { "pubkeys": ["rsa-sha2-256","rsa-sha2-512"]}
                }
                print(f"Connecting to {p['host']} | {p['device_type']}")
                koneksi = ConnectHandler(**koneksi_args, timeout=60)
                hostname = koneksi.find_prompt().strip('<').strip('>')
                
                command = p.get('command', '')
                if not command:
                    print(f"Command not found {p['host']}.")
                    continue
                
                print(f"Send command to {p['host']}: {command}")
                output = koneksi.send_command_timing(command, delay_factor=2)
                
                # Debug: Cetak output yang diterima
                # print(f"Output dari {p['host']}:\n{output}")
                
                device_dir = f"{backup_dir}/{p['location']}/{get_current_date_format()}"
                buat_direktori(device_dir)
                
                nama_file = f"{device_dir}/{hostname}.txt"
                with open(nama_file, 'w') as file:
                    file.write(output)
                
                koneksi.disconnect()
                print(f"Backup {p['device_type']} Success {nama_file}")
            except Exception as e:
                print(f"Error Backup {p['host']}: {e}")
        else:
            print("Error: Invalid Format")

# Fungsi untuk mendapatkan tanggal saat ini dalam format yang diinginkan
def get_current_date_format():
    return datetime.now().strftime("%d %B %Y")

if __name__ == "__main__":
    # Melakukan backup untuk masing-masing perangkat
    backup_konfigurasi(perangkat)
