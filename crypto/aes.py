from .base import Cipher
import base64
import os
from typing import Optional

try:
    from Crypto.Cipher import AES as PyCryptoAES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class AES(Cipher):
    """
    AES-128 şifreleme (kütüphaneli ve manuel mod)
    """
    name = "aes"

    # Manuel AES için S-box (Rijndael S-box)
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    # Inverse S-box
    INV_S_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    # Rcon tablosu (round constants)
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def _generate_key(self, key_input: Optional[object] = None) -> bytes:
        """16 byte anahtar üret (str veya bytes kabul eder)"""
        if key_input is None:
            return os.urandom(16)

        if isinstance(key_input, bytes):
            key_bytes = key_input[:16]
            if len(key_bytes) < 16:
                key_bytes = key_bytes.ljust(16, b'\0')
            return key_bytes

        # Kullanıcı anahtarından 16 byte üret (string)
        key_bytes = str(key_input).encode('utf-8')[:16]
        if len(key_bytes) < 16:
            key_bytes = key_bytes.ljust(16, b'\0')
        return key_bytes[:16]

    def _key_expansion(self, key: bytes) -> list:
        """AES key expansion (128-bit için 10 round)"""
        w = []
        for i in range(4):
            w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
        
        for i in range(4, 44):
            temp = w[i-1][:]
            if i % 4 == 0:
                # RotWord
                temp = [temp[1], temp[2], temp[3], temp[0]]
                # SubWord
                temp = [self.S_BOX[b] for b in temp]
                # XOR with Rcon
                temp[0] ^= self.RCON[i//4 - 1]
            w.append([w[i-4][j] ^ temp[j] for j in range(4)])
        
        return w

    def _sub_bytes(self, state: list):
        """SubBytes dönüşümü"""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.S_BOX[state[i][j]]

    def _inv_sub_bytes(self, state: list):
        """Inverse SubBytes"""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.INV_S_BOX[state[i][j]]

    def _shift_rows(self, state: list):
        """ShiftRows dönüşümü"""
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]

    def _inv_shift_rows(self, state: list):
        """Inverse ShiftRows"""
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]

    def _gf_multiply(self, a: int, b: int) -> int:
        """Galois Field çarpımı"""
        result = 0
        for i in range(8):
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b
            b >>= 1
        return result & 0xff

    def _mix_columns(self, state: list):
        """MixColumns dönüşümü"""
        for j in range(4):
            s0 = state[0][j]
            s1 = state[1][j]
            s2 = state[2][j]
            s3 = state[3][j]
            state[0][j] = self._gf_multiply(2, s0) ^ self._gf_multiply(3, s1) ^ s2 ^ s3
            state[1][j] = s0 ^ self._gf_multiply(2, s1) ^ self._gf_multiply(3, s2) ^ s3
            state[2][j] = s0 ^ s1 ^ self._gf_multiply(2, s2) ^ self._gf_multiply(3, s3)
            state[3][j] = self._gf_multiply(3, s0) ^ s1 ^ s2 ^ self._gf_multiply(2, s3)

    def _inv_mix_columns(self, state: list):
        """Inverse MixColumns"""
        for j in range(4):
            s0 = state[0][j]
            s1 = state[1][j]
            s2 = state[2][j]
            s3 = state[3][j]
            state[0][j] = self._gf_multiply(0x0e, s0) ^ self._gf_multiply(0x0b, s1) ^ self._gf_multiply(0x0d, s2) ^ self._gf_multiply(0x09, s3)
            state[1][j] = self._gf_multiply(0x09, s0) ^ self._gf_multiply(0x0e, s1) ^ self._gf_multiply(0x0b, s2) ^ self._gf_multiply(0x0d, s3)
            state[2][j] = self._gf_multiply(0x0d, s0) ^ self._gf_multiply(0x09, s1) ^ self._gf_multiply(0x0e, s2) ^ self._gf_multiply(0x0b, s3)
            state[3][j] = self._gf_multiply(0x0b, s0) ^ self._gf_multiply(0x0d, s1) ^ self._gf_multiply(0x09, s2) ^ self._gf_multiply(0x0e, s3)

    def _add_round_key(self, state: list, round_key: list):
        """AddRoundKey"""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i*4 + j]

    def _bytes_to_state(self, data: bytes) -> list:
        """16 byte'ı 4x4 state matrisine çevir"""
        state = [[0]*4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = data[i + 4*j]
        return state

    def _state_to_bytes(self, state: list) -> bytes:
        """4x4 state matrisini 16 byte'a çevir"""
        data = bytearray(16)
        for i in range(4):
            for j in range(4):
                data[i + 4*j] = state[i][j]
        return bytes(data)

    def _manual_encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        """Manuel AES-128 şifreleme (tek blok)"""
        state = self._bytes_to_state(plaintext)
        round_keys = self._key_expansion(key)
        
        # Initial round key
        key_schedule = []
        for i in range(11):
            key_schedule.append([round_keys[j][k] for j in range(i*4, (i+1)*4) for k in range(4)])
        
        # AddRoundKey (initial)
        self._add_round_key(state, key_schedule[0])
        
        # 9 round
        for round_num in range(1, 10):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, key_schedule[round_num])
        
        # Final round (MixColumns yok)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, key_schedule[10])
        
        return self._state_to_bytes(state)

    def _manual_decrypt_block(self, ciphertext: bytes, key: bytes) -> bytes:
        """Manuel AES-128 çözme (tek blok)"""
        state = self._bytes_to_state(ciphertext)
        round_keys = self._key_expansion(key)
        
        key_schedule = []
        for i in range(11):
            key_schedule.append([round_keys[j][k] for j in range(i*4, (i+1)*4) for k in range(4)])
        
        # Initial round key
        self._add_round_key(state, key_schedule[10])
        
        # 9 round (ters sırada)
        for round_num in range(9, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, key_schedule[round_num])
            self._inv_mix_columns(state)
        
        # Final round
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, key_schedule[0])
        
        return self._state_to_bytes(state)

    def _manual_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Manuel AES-128 şifreleme (CBC modu basitleştirilmiş)"""
        # Basit ECB modu (öğrenme amaçlı)
        padded = plaintext
        if len(padded) % 16 != 0:
            padding = 16 - (len(padded) % 16)
            padded += bytes([padding] * padding)
        
        ciphertext = bytearray()
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            encrypted_block = self._manual_encrypt_block(block, key)
            ciphertext.extend(encrypted_block)
        
        return bytes(ciphertext)

    def _manual_decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Manuel AES-128 çözme"""
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = self._manual_decrypt_block(block, key)
            plaintext.extend(decrypted_block)
        
        # Padding kaldır
        if len(plaintext) > 0:
            padding_len = plaintext[-1]
            if padding_len <= 16:
                plaintext = plaintext[:-padding_len]
        
        return bytes(plaintext)

    def encrypt(self, text: str, **kw) -> str:
        """Metni AES ile şifrele"""
        use_library = kw.get("use_library", True)
        key_input = kw.get("key", None)
        
        key = self._generate_key(key_input)
        plaintext_bytes = text.encode('utf-8')
        
        if use_library and CRYPTO_AVAILABLE:
            # Kütüphane kullanarak
            cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_CBC)
            iv = cipher.iv
            padded = pad(plaintext_bytes, PyCryptoAES.block_size)
            ciphertext = cipher.encrypt(padded)
            # IV + ciphertext'i base64 ile kodla
            result = base64.b64encode(iv + ciphertext).decode('utf-8')
        else:
            # Manuel implementasyon
            ciphertext = self._manual_encrypt(plaintext_bytes, key)
            result = base64.b64encode(ciphertext).decode('utf-8')
        
        return result

    def decrypt(self, text: str, **kw) -> str:
        """AES ile şifrelenmiş metni çöz"""
        use_library = kw.get("use_library", True)
        key_input = kw.get("key", None)
        
        key = self._generate_key(key_input)
        
        try:
            ciphertext_bytes = base64.b64decode(text)
        except:
            raise ValueError("Geçersiz base64 formatı")
        
        if use_library and CRYPTO_AVAILABLE:
            # Kütüphane kullanarak
            iv = ciphertext_bytes[:16]
            ciphertext = ciphertext_bytes[16:]
            cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_CBC, iv)
            padded = cipher.decrypt(ciphertext)
            plaintext_bytes = unpad(padded, PyCryptoAES.block_size)
        else:
            # Manuel implementasyon
            plaintext_bytes = self._manual_decrypt(ciphertext_bytes, key)
        
        return plaintext_bytes.decode('utf-8', errors='ignore')

