import os
import sys

# Add the app directory to the path so we can import from app.core
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.encryption import encrypt_data, decrypt_data

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

PCAP_MAGIC_NUMBERS = [
    b'\xa1\xb2\xc3\xd4',
    b'\xd4\xc3\xb2\xa1',
    b'\n\r\r\n',
    b'\xa1\xb2\x3c\x4d',
    b'\x4d\x3c\xb2\xa1'
]

def is_plaintext_pcap(data: bytes) -> bool:
    if len(data) < 4:
        return False
    magic = data[:4]
    return any(magic == m for m in PCAP_MAGIC_NUMBERS)

def migrate():
    print("Starting PCAP encryption migration...")
    if not os.path.exists(UPLOAD_DIR):
        print(f"Upload directory {UPLOAD_DIR} does not exist.")
        return

    files = os.listdir(UPLOAD_DIR)
    migrated_count = 0
    
    for filename in files:
        if filename.lower().endswith(('.pcap', '.pcapng', '.cap')):
            filepath = os.path.join(UPLOAD_DIR, filename)
            with open(filepath, 'rb') as f:
                data = f.read()

            if is_plaintext_pcap(data):
                print(f"Encrypting {filename}...")
                try:
                    encrypted_data = encrypt_data(data)
                    with open(filepath, 'wb') as f:
                        f.write(encrypted_data)
                    print(f"Successfully encrypted {filename}.")
                    migrated_count += 1
                except Exception as e:
                    print(f"Failed to encrypt {filename}: {e}")
            else:
                try:
                    decrypt_data(data)
                    print(f"File {filename} is already encrypted.")
                except Exception:
                    print(f"File {filename} is neither a plaintext PCAP nor a valid encrypted file. Skipping.")

    print(f"Migration complete. Encrypted {migrated_count} files.")

if __name__ == "__main__":
    migrate()
