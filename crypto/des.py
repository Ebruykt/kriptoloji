from .base import Cipher
import base64
import os
from typing import Optional

try:
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class DES_Cipher(Cipher):
    """
    DES şifreleme (kütüphaneli ve manuel mod)
    """
    name = "des"

    # Initial Permutation (IP)
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Inverse Initial Permutation (IP^-1)
    IP_INV = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]

    # Expansion Permutation (E)
    E = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    ]

    # Permutation (P)
    P = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    ]

    # PC-1 (Key Permutation)
    PC1 = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    ]

    # PC-2 (Key Compression)
    PC2 = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ]

    # Left shifts for key schedule
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # S-boxes
    S_BOXES = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    def _generate_key(self, key_input: Optional[str] = None) -> bytes:
        """8 byte anahtar üret"""
        if key_input:
            key_bytes = key_input.encode('utf-8')[:8]
            if len(key_bytes) < 8:
                key_bytes = key_bytes.ljust(8, b'\0')
            return key_bytes[:8]
        else:
            return os.urandom(8)

    def _permute(self, bits: list, table: list) -> list:
        """Permütasyon uygula"""
        return [bits[i-1] for i in table]

    def _left_shift(self, bits: list, n: int) -> list:
        """Sola kaydır"""
        return bits[n:] + bits[:n]

    def _key_schedule(self, key: bytes) -> list:
        """DES anahtar zamanlaması (16 round key)"""
        # 64-bit anahtarı bit listesine çevir
        key_bits = []
        for byte in key:
            for i in range(7, -1, -1):
                key_bits.append((byte >> i) & 1)
        
        # PC-1 permütasyonu (56 bit)
        key_56 = self._permute(key_bits, self.PC1)
        
        # C0 ve D0'ı ayır
        C = key_56[:28]
        D = key_56[28:]
        
        round_keys = []
        for i in range(16):
            # Shift
            C = self._left_shift(C, self.SHIFTS[i])
            D = self._left_shift(D, self.SHIFTS[i])
            
            # PC-2 permütasyonu (48 bit)
            CD = C + D
            round_key = self._permute(CD, self.PC2)
            round_keys.append(round_key)
        
        return round_keys

    def _s_box_substitution(self, bits: list) -> list:
        """S-box yerine koyma"""
        output = []
        for i in range(8):
            # 6 bit al
            chunk = bits[i*6:(i+1)*6]
            row = chunk[0] * 2 + chunk[5]
            col = chunk[1] * 8 + chunk[2] * 4 + chunk[3] * 2 + chunk[4]
            value = self.S_BOXES[i][row][col]
            # 4 bit'e çevir
            for j in range(3, -1, -1):
                output.append((value >> j) & 1)
        return output

    def _f_function(self, R: list, round_key: list) -> list:
        """Feistel fonksiyonu"""
        # Expansion (32 -> 48)
        expanded = self._permute(R, self.E)
        
        # XOR with round key
        xor_result = [expanded[i] ^ round_key[i] for i in range(48)]
        
        # S-box substitution (48 -> 32)
        s_output = self._s_box_substitution(xor_result)
        
        # Permutation P (32 -> 32)
        result = self._permute(s_output, self.P)
        
        return result

    def _des_round(self, L: list, R: list, round_key: list) -> tuple:
        """DES tek round"""
        f_result = self._f_function(R, round_key)
        new_R = [L[i] ^ f_result[i] for i in range(32)]
        return R, new_R

    def _bytes_to_bits(self, data: bytes) -> list:
        """Byte'ları bit listesine çevir"""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    def _bits_to_bytes(self, bits: list) -> bytes:
        """Bit listesini byte'lara çevir"""
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte = (byte << 1) | bits[i + j]
            bytes_list.append(byte)
        return bytes(bytes_list)

    def _manual_encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        """Manuel DES şifreleme (tek blok)"""
        round_keys = self._key_schedule(key)
        
        # 64-bit bloğu bit listesine çevir
        bits = self._bytes_to_bits(plaintext)
        
        # Initial Permutation
        permuted = self._permute(bits, self.IP)
        
        # L0 ve R0'ı ayır
        L = permuted[:32]
        R = permuted[32:]
        
        # 16 round
        for i in range(16):
            L, R = self._des_round(L, R, round_keys[i])
        
        # Final swap
        L, R = R, L
        
        # Inverse Initial Permutation
        final_bits = self._permute(L + R, self.IP_INV)
        
        return self._bits_to_bytes(final_bits)

    def _manual_decrypt_block(self, ciphertext: bytes, key: bytes) -> bytes:
        """Manuel DES çözme (tek blok)"""
        round_keys = self._key_schedule(key)
        
        bits = self._bytes_to_bits(ciphertext)
        permuted = self._permute(bits, self.IP)
        
        L = permuted[:32]
        R = permuted[32:]
        
        # 16 round (ters sırada)
        for i in range(15, -1, -1):
            L, R = self._des_round(L, R, round_keys[i])
        
        L, R = R, L
        final_bits = self._permute(L + R, self.IP_INV)
        
        return self._bits_to_bytes(final_bits)

    def _manual_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Manuel DES şifreleme"""
        padded = plaintext
        if len(padded) % 8 != 0:
            padding = 8 - (len(padded) % 8)
            padded += bytes([padding] * padding)
        
        ciphertext = bytearray()
        for i in range(0, len(padded), 8):
            block = padded[i:i+8]
            if len(block) < 8:
                block = block.ljust(8, b'\0')
            encrypted_block = self._manual_encrypt_block(block, key)
            ciphertext.extend(encrypted_block)
        
        return bytes(ciphertext)

    def _manual_decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Manuel DES çözme"""
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            decrypted_block = self._manual_decrypt_block(block, key)
            plaintext.extend(decrypted_block)
        
        # Padding kaldır
        if len(plaintext) > 0:
            padding_len = plaintext[-1]
            if padding_len <= 8:
                plaintext = plaintext[:-padding_len]
        
        return bytes(plaintext)

    def encrypt(self, text: str, **kw) -> str:
        """Metni DES ile şifrele"""
        use_library = kw.get("use_library", True)
        key_input = kw.get("key", None)
        
        key = self._generate_key(key_input)
        plaintext_bytes = text.encode('utf-8')
        
        if use_library and CRYPTO_AVAILABLE:
            cipher = DES.new(key, DES.MODE_CBC)
            iv = cipher.iv
            padded = pad(plaintext_bytes, DES.block_size)
            ciphertext = cipher.encrypt(padded)
            result = base64.b64encode(iv + ciphertext).decode('utf-8')
        else:
            ciphertext = self._manual_encrypt(plaintext_bytes, key)
            result = base64.b64encode(ciphertext).decode('utf-8')
        
        return result

    def decrypt(self, text: str, **kw) -> str:
        """DES ile şifrelenmiş metni çöz"""
        use_library = kw.get("use_library", True)
        key_input = kw.get("key", None)
        
        key = self._generate_key(key_input)
        
        try:
            ciphertext_bytes = base64.b64decode(text)
        except:
            raise ValueError("Geçersiz base64 formatı")
        
        if use_library and CRYPTO_AVAILABLE:
            iv = ciphertext_bytes[:8]
            ciphertext = ciphertext_bytes[8:]
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded = cipher.decrypt(ciphertext)
            plaintext_bytes = unpad(padded, DES.block_size)
        else:
            plaintext_bytes = self._manual_decrypt(ciphertext_bytes, key)
        
        return plaintext_bytes.decode('utf-8', errors='ignore')

