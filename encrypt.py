# encrypt.py
import os
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

KEY = b'This is a key123'  # 16 bytes

def encrypt_file_bytes(data):
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted, hashlib.sha256(iv + encrypted).hexdigest()

def decrypt_file_bytes(data):
    iv = data[:16]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(data[16:]), AES.block_size)
    return decrypted
