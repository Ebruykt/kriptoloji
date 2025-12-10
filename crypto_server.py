"""
Şifreli İstemci-Sunucu Haberleşme Sistemi - Sunucu
AES, DES ve RSA algoritmalarını destekler
"""
import socket
import json
import base64
from crypto.aes import AES
from crypto.des import DES_Cipher
from crypto.rsa import RSA_Cipher
from crypto.key_manager import KeyManager

HOST = "127.0.0.1"
PORT = 12346

class CryptoServer:
    def __init__(self):
        self.aes = AES()
        self.des = DES_Cipher()
        self.rsa = RSA_Cipher()
        self.key_manager = KeyManager("server_keys.json")
        
        # RSA anahtar çifti oluştur (anahtar dağıtımı için)
        try:
            self.rsa_public, self.rsa_private = self.key_manager.get_rsa_public_key(), self.key_manager.get_rsa_private_key()
            if not self.rsa_public:
                self.rsa_public, self.rsa_private = self.key_manager.generate_rsa_keypair()
        except:
            self.rsa_public, self.rsa_private = self.key_manager.generate_rsa_keypair()
        
        print(f"RSA Public Key hazır (anahtar dağıtımı için)")
    
    def _receive_message(self, conn: socket.socket) -> dict:
        """Mesajı al ve parse et"""
        # Önce mesaj uzunluğunu al
        length_data = conn.recv(4)
        if not length_data:
            return None
        length = int.from_bytes(length_data, 'big')
        
        # Mesajı al
        data = b''
        while len(data) < length:
            chunk = conn.recv(min(4096, length - len(data)))
            if not chunk:
                return None
            data += chunk
        
        return json.loads(data.decode('utf-8'))
    
    def _send_message(self, conn: socket.socket, message: dict):
        """Mesajı gönder"""
        data = json.dumps(message).encode('utf-8')
        length = len(data).to_bytes(4, 'big')
        conn.sendall(length + data)

    def _resolve_key(self, algorithm: str, key: str = None, encrypted_key: str = None):
        """
        Simetrik algoritmalar için gönderilen anahtarı çözümler.
        - Eğer encrypted_key varsa RSA ile çözer.
        - Yoksa düz key değerini kullanır.
        """
        if algorithm in ["aes", "des"]:
            if encrypted_key:
                return self.rsa.decrypt_bytes(encrypted_key, private_key=self.rsa_private)
            return key
        return None
    
    def _decrypt_message(self, algorithm: str, encrypted_data: str, **kwargs) -> str:
        """Mesajı çöz"""
        if algorithm == "aes":
            use_library = kwargs.get("use_library", True)
            key = kwargs.get("key")
            return self.aes.decrypt(encrypted_data, use_library=use_library, key=key)
        elif algorithm == "des":
            use_library = kwargs.get("use_library", True)
            key = kwargs.get("key")
            return self.des.decrypt(encrypted_data, use_library=use_library, key=key)
        elif algorithm == "rsa":
            return self.rsa.decrypt(encrypted_data, private_key=self.rsa_private)
        else:
            raise ValueError(f"Bilinmeyen algoritma: {algorithm}")
    
    def _encrypt_response(self, algorithm: str, plaintext: str, **kwargs) -> str:
        """Yanıtı şifrele"""
        if algorithm == "aes":
            use_library = kwargs.get("use_library", True)
            key = kwargs.get("key")
            return self.aes.encrypt(plaintext, use_library=use_library, key=key)
        elif algorithm == "des":
            use_library = kwargs.get("use_library", True)
            key = kwargs.get("key")
            return self.des.encrypt(plaintext, use_library=use_library, key=key)
        elif algorithm == "rsa":
            return self.rsa.encrypt(plaintext, public_key=self.rsa_public)
        else:
            raise ValueError(f"Bilinmeyen algoritma: {algorithm}")
    
    def handle_client(self, conn: socket.socket, addr: tuple):
        """İstemciyi işle"""
        print(f"\n[{addr[0]}:{addr[1]}] Bağlandı")
        
        try:
            # RSA public key'i gönder (anahtar dağıtımı için)
            self._send_message(conn, {
                "type": "rsa_public_key",
                "public_key": self.rsa_public
            })
            
            while True:
                # Mesaj al
                message = self._receive_message(conn)
                if not message:
                    break
                
                msg_type = message.get("type")
                
                if msg_type == "encrypted_message":
                    algorithm = message.get("algorithm")
                    encrypted_data = message.get("data")
                    use_library = message.get("use_library", True)
                    key = message.get("key")
                    encrypted_key = message.get("encrypted_key")

                    resolved_key = self._resolve_key(algorithm, key, encrypted_key)
                    
                    print(f"[{addr[0]}:{addr[1]}] Algoritma: {algorithm.upper()}, Kütüphane: {'Evet' if use_library else 'Hayır (Manuel)'}")
                    
                    try:
                        # Mesajı çöz
                        decrypted = self._decrypt_message(
                            algorithm, 
                            encrypted_data,
                            use_library=use_library,
                            key=resolved_key
                        )
                        
                        print(f"[{addr[0]}:{addr[1]}] Çözülmüş mesaj: {decrypted}")
                        
                        # ACK gönder (şifreli)
                        ack_message = f"ACK: Mesaj alındı - '{decrypted[:50]}...'"
                        encrypted_ack = self._encrypt_response(
                            algorithm,
                            ack_message,
                            use_library=use_library,
                            key=resolved_key
                        )
                        
                        self._send_message(conn, {
                            "type": "ack",
                            "data": encrypted_ack,
                            "algorithm": algorithm
                        })
                        
                    except Exception as e:
                        print(f"[{addr[0]}:{addr[1]}] Hata: {e}")
                        self._send_message(conn, {
                            "type": "error",
                            "message": str(e)
                        })
                
                elif msg_type == "disconnect":
                    break
        
        except Exception as e:
            print(f"[{addr[0]}:{addr[1]}] Bağlantı hatası: {e}")
        finally:
            conn.close()
            print(f"[{addr[0]}:{addr[1]}] Bağlantı kapatıldı")
    
    def start(self):
        """Sunucuyu başlat"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        
        print(f"Sunucu {HOST}:{PORT} adresinde dinleniyor...")
        print("Çıkmak için Ctrl+C")
        
        try:
            while True:
                conn, addr = server_socket.accept()
                self.handle_client(conn, addr)
        except KeyboardInterrupt:
            print("\nSunucu kapatılıyor...")
        finally:
            server_socket.close()

if __name__ == "__main__":
    server = CryptoServer()
    server.start()

