from flask import Flask, request, jsonify, send_from_directory
from crypto.caesar import Caesar
from crypto.vigenere import Vigenere
from crypto.substitution import Substitution
from crypto.affine import Affine

app = Flask(__name__, static_folder="static")

# Haftalar ilerledikçe buraya yeni algoritma nesneleri eklenecek
REGISTRY = {
    Caesar.name: Caesar(),
    Vigenere.name: Vigenere(),
    Substitution.name: Substitution(),
    Affine.name: Affine(),
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
