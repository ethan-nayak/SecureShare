from cryptography.fernet import Fernet
import os

KEY_FILE = "data/secret.key"

def get_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def encrypt_file(data: bytes) -> bytes:
    key = get_or_create_key()
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_file(data: bytes) -> bytes:
    key = get_or_create_key()
    f = Fernet(key)
    return f.decrypt(data)