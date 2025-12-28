from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256

def generate_keypair():
    key = ECC.generate(curve="P-256")
    private_key = key.export_key(format="PEM")
    public_key = key.public_key().export_key(format="PEM")
    return private_key, public_key

def derive_aes_key():
    """
    ECC tabanlı anahtardan AES-128 için 16 byte üretir
    """
    key = ECC.generate(curve="P-256")
    shared = SHA256.new(key.pointQ.export()).digest()
    return shared[:16]
