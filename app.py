from flask import Flask, request, jsonify, send_from_directory
from crypto.caesar import Caesar
from crypto.vigenere import Vigenere
from crypto.substitution import Substitution
from crypto.affine import Affine
from crypto.playfair import Playfair
from crypto.aes import AES
from crypto.route import RouteCipher
from crypto.columnar import ColumnarCipher
from crypto.pigpen import PigpenCipher
from crypto.polybius import PolybiusCipher

# Modülleri direkt import et
import crypto.hill as hill_mod
import crypto.railfence as rf_mod
import base64
import crypto.aes as aes_lib
import crypto.aes_manual as aes_manual
import crypto.des as des_lib
import crypto.rsa as rsa_lib


app = Flask(__name__, static_folder="static")

class Hill:
    name = "hill"
    def encrypt(self, text, key=None, **kwargs):
        if not key:
            raise ValueError("Hill için 'key' zorunlu (4 veya 9 harf).")
        return hill_mod.encrypt(text, key)
    def decrypt(self, text, key=None, **kwargs):
        if not key:
            raise ValueError("Hill için 'key' zorunlu (4 veya 9 harf).")
        return hill_mod.decrypt(text, key)

class RailFence:
    name = "railfence"
    def encrypt(self, text, rails=2, **kwargs):
        rails = int(rails) if rails is not None and str(rails) != "" else 2
        return rf_mod.encrypt(text, rails)
    def decrypt(self, text, rails=2, **kwargs):
        rails = int(rails) if rails is not None and str(rails) != "" else 2
        return rf_mod.decrypt(text, rails)
    
# ✅ AES Kütüphaneli (aes_lib olarak değiştirildi)
class AESLibWrapper:
    name = "aes_lib"

    def encrypt(self, text, key=None, **kwargs):
        if not key:
            raise ValueError("AES için key zorunludur")

        if isinstance(key, str):
            key = key.encode()
        
        if len(key) not in [16, 24, 32]:
            if len(key) < 16:
                key = key + b'0' * (16 - len(key))
            else:
                key = key[:16]

        return aes_lib.encrypt(text, key)

    def decrypt(self, text, key=None, **kwargs):
        if not key:
            raise ValueError("AES için key zorunludur")

        if isinstance(key, str):
            key = key.encode()
        
        if len(key) not in [16, 24, 32]:
            if len(key) < 16:
                key = key + b'0' * (16 - len(key))
            else:
                key = key[:16]

        return aes_lib.decrypt(text, key)

# ✅ AES Kütüphanesiz (aes_manual olarak ayrı)
class AESManualWrapper:
    name = "aes_manual"

    def encrypt(self, text, key=None, **kwargs):
        if not key:
            raise ValueError("AES için key zorunludur")

        if isinstance(key, str):
            key = key.encode()
        
        if len(key) not in [16, 24, 32]:
            if len(key) < 16:
                key = key + b'0' * (16 - len(key))
            else:
                key = key[:16]

        encrypted = aes_manual.encrypt(text, key)
        return base64.b64encode(encrypted).decode()

    def decrypt(self, text, key=None, **kwargs):
        if not key:
            raise ValueError("AES için key zorunludur")

        if isinstance(key, str):
            key = key.encode()
        
        if len(key) not in [16, 24, 32]:
            if len(key) < 16:
                key = key + b'0' * (16 - len(key))
            else:
                key = key[:16]

        raw = base64.b64decode(text)
        return aes_manual.decrypt(raw, key)

        
class DESWrapper:
    name = "des"

    def encrypt(self, text, key=None, **kwargs):
        if not key:
            raise ValueError("DES için key zorunludur")

        if isinstance(key, str):
            key = key.encode()
        
        if len(key) != 8:
            if len(key) < 8:
                key = key + b'0' * (8 - len(key))
            else:
                key = key[:8]

        return des_lib.encrypt(text, key)

    def decrypt(self, text, key=None, **kwargs):
        if not key:
            raise ValueError("DES için key zorunludur")

        if isinstance(key, str):
            key = key.encode()
        
        if len(key) != 8:
            if len(key) < 8:
                key = key + b'0' * (8 - len(key))
            else:
                key = key[:8]

        return des_lib.decrypt(text, key)


class RSAWrapper:
    name = "rsa"

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        self.private_key, self.public_key = rsa_lib.generate_keypair()
        return {
            "private_key": self.private_key.decode(),
            "public_key": self.public_key.decode()
        }

    def encrypt(self, text, **kwargs):
        raise ValueError("RSA doğrudan mesaj şifrelemek için kullanılmaz")

    def decrypt(self, text, **kwargs):
        raise ValueError("RSA doğrudan mesaj çözmek için kullanılmaz")


rsa_instance = RSAWrapper()

# ✅ REGISTRY'ye her iki AES sürümü eklendi
REGISTRY = {
    Caesar.name: Caesar(),
    Vigenere.name: Vigenere(),
    Substitution.name: Substitution(),
    Affine.name: Affine(),
    Playfair.name: Playfair(),
    AESLibWrapper.name: AESLibWrapper(),        # ← aes_lib
    AESManualWrapper.name: AESManualWrapper(),  # ← aes_manual
    DESWrapper.name: DESWrapper(),
    Hill.name: Hill(),
    RailFence.name: RailFence(),
    RouteCipher.name: RouteCipher(),
    ColumnarCipher.name: ColumnarCipher(),
    PigpenCipher.name: PigpenCipher(),
    PolybiusCipher.name: PolybiusCipher(),
}

@app.get("/api/algorithms")
def algorithms():
    return jsonify(sorted(REGISTRY.keys()))

@app.post("/api/generate-rsa-key")
def generate_rsa_key():
    try:
        keys = rsa_instance.generate_keys()
        return jsonify(keys)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.post("/api/encrypt")
def encrypt():
    data = request.get_json(force=True)
    method = data.get("method")
    text   = data.get("text", "")
    opts   = data.get("options", {}) or {}
    if method not in REGISTRY:
        return jsonify({"error": "Unknown method"}), 400
    try:
        out = REGISTRY[method].encrypt(text, **opts)
        return jsonify({"result": out})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.post("/api/decrypt")
def decrypt():
    data = request.get_json(force=True)
    method = data.get("method")
    text   = data.get("text", "")
    opts   = data.get("options", {}) or {}
    if method not in REGISTRY:
        return jsonify({"error": "Unknown method"}), 400
    try:
        out = REGISTRY[method].decrypt(text, **opts)
        return jsonify({"result": out})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.get("/")
def index():
    return send_from_directory("static", "index.html")

if __name__ == "__main__":
    app.run(debug=True)