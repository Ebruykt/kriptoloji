"""
Anahtar yönetimi modülü
AES, DES ve RSA anahtarlarını üretir ve yönetir
"""
import os
import json
from typing import Optional, Tuple
from pathlib import Path

try:
    from Crypto.PublicKey import RSA
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class KeyManager:
    """Anahtar yönetimi sınıfı"""
    
    def __init__(self, key_file: str = "keys.json"):
        self.key_file = Path(key_file)
        self.keys = self._load_keys()
    
    def _load_keys(self) -> dict:
        """Anahtarları dosyadan yükle"""
        if self.key_file.exists():
            try:
                with open(self.key_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_keys(self):
        """Anahtarları dosyaya kaydet"""
        with open(self.key_file, 'w') as f:
            json.dump(self.keys, f, indent=2)
    
    def generate_aes_key(self, key_id: str = "default") -> bytes:
        """AES-128 anahtarı üret (16 byte)"""
        key = os.urandom(16)
        self.keys[f"aes_{key_id}"] = key.hex()
        self._save_keys()
        return key
    
    def get_aes_key(self, key_id: str = "default") -> Optional[bytes]:
        """AES anahtarını al"""
        key_hex = self.keys.get(f"aes_{key_id}")
        if key_hex:
            return bytes.fromhex(key_hex)
        return None
    
    def generate_des_key(self, key_id: str = "default") -> bytes:
        """DES anahtarı üret (8 byte)"""
        key = os.urandom(8)
        self.keys[f"des_{key_id}"] = key.hex()
        self._save_keys()
        return key
    
    def get_des_key(self, key_id: str = "default") -> Optional[bytes]:
        """DES anahtarını al"""
        key_hex = self.keys.get(f"des_{key_id}")
        if key_hex:
            return bytes.fromhex(key_hex)
        return None
    
    def generate_rsa_keypair(self, key_id: str = "default", key_size: int = 2048) -> Tuple[str, str]:
        """RSA anahtar çifti üret"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("RSA için pycryptodome kütüphanesi gerekli")
        
        key = RSA.generate(key_size)
        private_key_pem = key.export_key().decode('utf-8')
        public_key_pem = key.publickey().export_key().decode('utf-8')
        
        self.keys[f"rsa_{key_id}_public"] = public_key_pem
        self.keys[f"rsa_{key_id}_private"] = private_key_pem
        self._save_keys()
        
        return public_key_pem, private_key_pem
    
    def get_rsa_public_key(self, key_id: str = "default") -> Optional[str]:
        """RSA public key'i al"""
        return self.keys.get(f"rsa_{key_id}_public")
    
    def get_rsa_private_key(self, key_id: str = "default") -> Optional[str]:
        """RSA private key'i al"""
        return self.keys.get(f"rsa_{key_id}_private")
    
    def set_aes_key(self, key_id: str, key: bytes):
        """AES anahtarını ayarla"""
        self.keys[f"aes_{key_id}"] = key.hex()
        self._save_keys()
    
    def set_des_key(self, key_id: str, key: bytes):
        """DES anahtarını ayarla"""
        self.keys[f"des_{key_id}"] = key.hex()
        self._save_keys()
    
    def set_rsa_keypair(self, key_id: str, public_key: str, private_key: str):
        """RSA anahtar çiftini ayarla"""
        self.keys[f"rsa_{key_id}_public"] = public_key
        self.keys[f"rsa_{key_id}_private"] = private_key
        self._save_keys()

