import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def get_encryption_key() -> bytes:
    """Retrieve the AES-256 key from environment or generate for dev."""
    key_b64 = os.getenv("PCAP_ENCRYPTION_KEY")
    if not key_b64:
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env == "production":
            raise ValueError("PCAP_ENCRYPTION_KEY environment variable is required in production environment.")
        else:
            # Generate a 256-bit key for development
            key = AESGCM.generate_key(bit_length=256)
            os.environ["PCAP_ENCRYPTION_KEY"] = base64.b64encode(key).decode('utf-8')
            print("WARNING: Auto-generated PCAP_ENCRYPTION_KEY for development environment.")
            return key
    else:
        return base64.b64decode(key_b64)

def encrypt_data(data: bytes) -> bytes:
    """Encrypts bytes using AES-256-GCM."""
    key = get_encryption_key()
    aesgcm = AESGCM(key)
    # GCM typically uses a 96-bit (12 bytes) nonce
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_data(data: bytes) -> bytes:
    """Decrypts bytes using AES-256-GCM."""
    key = get_encryption_key()
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)
