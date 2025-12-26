def s_box(byte: int) -> int:
    # basit ve deterministic bir S-box
    return (byte * 7 + 3) % 256

def xor_round(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def substitute(data: bytes) -> bytes:
    return bytes([s_box(b) for b in data])

def encrypt(plaintext: str, key: bytes, rounds: int = 3) -> bytes:
    data = plaintext.encode()

    for _ in range(rounds):
        data = xor_round(data, key)
        data = substitute(data)

    return data

def decrypt(ciphertext: bytes, key: bytes, rounds: int = 3) -> str:
    data = ciphertext

    for _ in range(rounds):
        # inverse substitute (bruteforce since simple)
        data = bytes([next(x for x in range(256) if s_box(x) == b) for b in data])
        data = xor_round(data, key)

    return data.decode()
