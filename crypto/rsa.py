from .base import Cipher
import base64
import os
import math
from typing import Optional, Tuple

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class RSA_Cipher(Cipher):
    """
    RSA şifreleme (kütüphaneli)
    RSA anahtar dağıtımı için kullanılır
    """
    name = "rsa"

    def _generate_keypair(self, key_size: int = 2048) -> Tuple[object, object]:
        """RSA anahtar çifti üret"""
        if CRYPTO_AVAILABLE:
            key = RSA.generate(key_size)
            return key.publickey(), key
        else:
            raise ValueError("RSA için pycryptodome kütüphanesi gerekli")

    def _is_prime(self, n: int) -> bool:
        """Basit asal sayı kontrolü (küçük sayılar için)"""
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        for i in range(3, int(math.sqrt(n)) + 1, 2):
            if n % i == 0:
                return False
        return True

    def _gcd(self, a: int, b: int) -> int:
        """Euclidean algoritması"""
        while b:
            a, b = b, a % b
        return a

    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """Genişletilmiş Euclidean algoritması"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def _mod_inverse(self, a: int, m: int) -> int:
        """Modüler ters"""
        gcd, x, _ = self._extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modüler ters yok")
        return (x % m + m) % m

    def encrypt(self, text: str, **kw) -> str:
        """Metni RSA ile şifrele"""
        public_key_pem = kw.get("public_key", None)
        key_size = int(kw.get("key_size", 2048))
        
        if not CRYPTO_AVAILABLE:
            raise ValueError("RSA için pycryptodome kütüphanesi gerekli")
        
        plaintext_bytes = text.encode('utf-8')
        
        if public_key_pem:
            # Public key'i yükle
            try:
                public_key = RSA.import_key(public_key_pem)
            except:
                raise ValueError("Geçersiz public key formatı")
        else:
            # Yeni anahtar çifti üret (sadece gösterim için)
            public_key, _ = self._generate_keypair(key_size)
        
        # PKCS1_OAEP ile şifreleme
        cipher = PKCS1_OAEP.new(public_key)
        
        # RSA sınırlaması: küçük mesajlar için
        max_length = (public_key.size_in_bits() // 8) - 42  # OAEP padding için
        if len(plaintext_bytes) > max_length:
            raise ValueError(f"Mesaj çok uzun. Maksimum {max_length} byte")
        
        ciphertext = cipher.encrypt(plaintext_bytes)
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, text: str, **kw) -> str:
        """RSA ile şifrelenmiş metni çöz"""
        private_key_pem = kw.get("private_key", None)
        
        if not CRYPTO_AVAILABLE:
            raise ValueError("RSA için pycryptodome kütüphanesi gerekli")
        
        try:
            ciphertext_bytes = base64.b64decode(text)
        except:
            raise ValueError("Geçersiz base64 formatı")
        
        if not private_key_pem:
            raise ValueError("RSA çözme için private key gerekli")
        
        try:
            private_key = RSA.import_key(private_key_pem)
        except:
            raise ValueError("Geçersiz private key formatı")
        
        cipher = PKCS1_OAEP.new(private_key)
        plaintext_bytes = cipher.decrypt(ciphertext_bytes)
        
        return plaintext_bytes.decode('utf-8')

    @staticmethod
    def generate_keypair(key_size: int = 2048) -> Tuple[str, str]:
        """RSA anahtar çifti üret ve PEM formatında döndür"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("RSA için pycryptodome kütüphanesi gerekli")
        
        key = RSA.generate(key_size)
        private_key_pem = key.export_key().decode('utf-8')
        public_key_pem = key.publickey().export_key().decode('utf-8')
        
        return public_key_pem, private_key_pem

