"""
Şifreli İstemci-Sunucu Haberleşme Sistemi - İstemci
AES, DES ve RSA algoritmalarını destekler
"""
import socket
import json
import os
import base64
from crypto.aes import AES
from crypto.des import DES_Cipher
from crypto.rsa import RSA_Cipher
from crypto.key_manager import KeyManager

HOST = "127.0.0.1"
PORT = 12346

class CryptoClient:
    def __init__(self):
        self.aes = AES()
        self.des = DES_Cipher()
        self.rsa = RSA_Cipher()
        self.key_manager = KeyManager("client_keys.json")
        self.server_rsa_public_key = None
        self.socket = None
    
    def connect(self):
        """Sunucuya bağlan"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))
        
        # RSA public key'i al
        message = self._receive_message()
        if message and message.get("type") == "rsa_public_key":
            self.server_rsa_public_key = message.get("public_key")
            print("✓ Sunucudan RSA public key alındı")
        else:
            raise Exception("RSA public key alınamadı")
    
    def _receive_message(self) -> dict:
        """Mesajı al ve parse et"""
        length_data = self.socket.recv(4)
        if not length_data:
            return None
        length = int.from_bytes(length_data, 'big')
        
        data = b''
        while len(data) < length:
            chunk = self.socket.recv(min(4096, length - len(data)))
            if not chunk:
                return None
            data += chunk
        
        return json.loads(data.decode('utf-8'))
    
    def _send_message(self, message: dict):
        """Mesajı gönder"""
        data = json.dumps(message).encode('utf-8')
        length = len(data).to_bytes(4, 'big')
        self.socket.sendall(length + data)
    
    def _encrypt_message(self, algorithm: str, plaintext: str, use_library: bool = True, key=None) -> str:
        """Mesajı şifrele"""
        if algorithm == "aes":
            return self.aes.encrypt(plaintext, use_library=use_library, key=key)
        elif algorithm == "des":
            return self.des.encrypt(plaintext, use_library=use_library, key=key)
        elif algorithm == "rsa":
            if not self.server_rsa_public_key:
                raise ValueError("RSA public key bulunamadı")
            return self.rsa.encrypt(plaintext, public_key=self.server_rsa_public_key)
        else:
            raise ValueError(f"Bilinmeyen algoritma: {algorithm}")
    
    def _decrypt_response(self, algorithm: str, encrypted_data: str, use_library: bool = True, key=None) -> str:
        """Yanıtı çöz"""
        if algorithm == "aes":
            return self.aes.decrypt(encrypted_data, use_library=use_library, key=key)
        elif algorithm == "des":
            return self.des.decrypt(encrypted_data, use_library=use_library, key=key)
        elif algorithm == "rsa":
            # RSA için private key gerekli (bu örnekte kullanılmıyor)
            raise ValueError("RSA çözme için private key gerekli")
        else:
            raise ValueError(f"Bilinmeyen algoritma: {algorithm}")
    
    def send_encrypted_message(self, message: str, algorithm: str = "aes", use_library: bool = True, key=None):
        """Şifreli mesaj gönder"""
        if not self.socket:
            raise Exception("Önce sunucuya bağlanın")
        
        print(f"\n[{algorithm.upper()}] Mesaj şifreleniyor...")
        print(f"Kütüphane kullanımı: {'Evet' if use_library else 'Hayır (Manuel)'}")

        encrypted_key = None
        key_for_cipher = key
        if algorithm in ["aes", "des"]:
            key_len = 16 if algorithm == "aes" else 8
            if not key:
                # Rastgele simetrik anahtar üret ve RSA ile şifreleyip gönder
                key_bytes = os.urandom(key_len)
                encrypted_key = self.rsa.encrypt_bytes(key_bytes, public_key=self.server_rsa_public_key)
                key_for_cipher = key_bytes
                printable_key = base64.b64encode(key_bytes).decode("ascii")
                print(f"Rastgele {key_len}-byte anahtar üretildi ve RSA ile korundu.")
                print(f"(İzleme için base64 anahtar): {printable_key}")
            else:
                key_for_cipher = key
        
        try:
            # Mesajı şifrele
            encrypted = self._encrypt_message(algorithm, message, use_library, key_for_cipher)
            
            print(f"Şifreli mesaj (base64): {encrypted[:100]}...")
            print(f"Şifreli mesaj boyutu: {len(encrypted)} byte")
            
            # Sunucuya gönder
            self._send_message({
                "type": "encrypted_message",
                "algorithm": algorithm,
                "data": encrypted,
                "use_library": use_library,
                "key": key if key else None,
                "encrypted_key": encrypted_key
            })
            
            # ACK al
            response = self._receive_message()
            if response and response.get("type") == "ack":
                encrypted_ack = response.get("data")
                ack_algorithm = response.get("algorithm")
                
                # ACK'yi çöz
                decrypted_ack = self._decrypt_response(ack_algorithm, encrypted_ack, use_library, key_for_cipher)
                print(f"\n✓ Sunucudan ACK: {decrypted_ack}")
            elif response and response.get("type") == "error":
                print(f"\n✗ Hata: {response.get('message')}")
            else:
                print("\n✗ Beklenmeyen yanıt")
        
        except Exception as e:
            print(f"\n✗ Hata: {e}")
    
    def disconnect(self):
        """Bağlantıyı kapat"""
        if self.socket:
            self._send_message({"type": "disconnect"})
            self.socket.close()
            self.socket = None
            print("\nBağlantı kapatıldı")

def main():
    """Ana fonksiyon"""
    client = CryptoClient()
    
    try:
        print("Sunucuya bağlanılıyor...")
        client.connect()
        
        print("\n" + "="*60)
        print("Şifreli İstemci-Sunucu Haberleşme Sistemi")
        print("="*60)
        print("\nKullanılabilir algoritmalar:")
        print("  1. AES-128")
        print("  2. DES")
        print("  3. RSA")
        print("\nMod seçimi:")
        print("  - Kütüphaneli: use_library=True")
        print("  - Manuel: use_library=False (sadece AES ve DES)")
        print("\nÇıkmak için 'quit' yazın")
        print("="*60)
        
        while True:
            print("\n--- Yeni Mesaj ---")
            algorithm = input("Algoritma (aes/des/rsa) [aes]: ").strip().lower() or "aes"
            
            if algorithm not in ["aes", "des", "rsa"]:
                print("Geçersiz algoritma!")
                continue
            
            use_lib_input = input("Kütüphane kullan? (e/h) [e]: ").strip().lower() or "e"
            use_library = use_lib_input == "e"
            
            if algorithm == "rsa" and not use_library:
                print("RSA için kütüphane kullanımı zorunludur!")
                continue
            
            key = None
            if algorithm in ["aes", "des"]:
                key_input = input("Anahtar (boş bırakırsanız rastgele üretilir): ").strip()
                if key_input:
                    key = key_input
            
            message = input("Mesaj: ").strip()
            
            if message.lower() == "quit":
                break
            
            if not message:
                print("Mesaj boş olamaz!")
                continue
            
            client.send_encrypted_message(message, algorithm, use_library, key)
    
    except KeyboardInterrupt:
        print("\n\nİptal edildi")
    except Exception as e:
        print(f"\nHata: {e}")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()

