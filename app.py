from flask import Flask, request, jsonify, send_from_directory
from crypto.caesar import Caesar
from crypto.vigenere import Vigenere
from crypto.substitution import Substitution
from crypto.affine import Affine
from crypto.playfair import Playfair
from crypto.aes import AES
from crypto.des import DES_Cipher
from crypto.rsa import RSA_Cipher

# Yeni eklemeler: hill ve railfence wrapper'ları import edildi
import crypto.hill as hill_mod
import crypto.railfence as rf_mod

app = Flask(__name__, static_folder="static")

# Küçük wrapper sınıfları — REGISTRY ile uyumlu olacak şekilde
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

# Haftalar ilerledikçe buraya yeni algoritma nesneleri eklenecek
REGISTRY = {
    Caesar.name: Caesar(),
    Vigenere.name: Vigenere(),
    Substitution.name: Substitution(),
    Affine.name: Affine(),
    Playfair.name: Playfair(),
    # Modern şifreleme algoritmaları
    AES.name: AES(),
    DES_Cipher.name: DES_Cipher(),
    RSA_Cipher.name: RSA_Cipher(),
    # Yeni eklemeler
    Hill.name: Hill(),
    RailFence.name: RailFence(),
}

@app.get("/api/algorithms")
def algorithms():
    return jsonify(sorted(REGISTRY.keys()))

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
