from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

BLOCK_SIZE = 16  # AES-128

def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def encrypt(plaintext: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode()))
    result = cipher.iv + ciphertext
    return base64.b64encode(result).decode()

def decrypt(ciphertext_b64: str, key: bytes) -> str:
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:BLOCK_SIZE]
    ciphertext = raw[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext.decode()

def generate_key() -> bytes:
    return get_random_bytes(16)  # 128 bit
