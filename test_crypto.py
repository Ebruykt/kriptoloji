"""
Kriptografi modüllerini test etmek için basit test scripti
"""
from crypto.aes import AES
from crypto.des import DES_Cipher
from crypto.rsa import RSA_Cipher

def test_aes():
    print("="*60)
    print("AES-128 Test")
    print("="*60)
    
    aes = AES()
    plaintext = "Merhaba Dünya! Bu bir test mesajıdır."
    test_key = "test_anahtar_16"  # 16 karakter
    
    # Kütüphaneli
    print("\n1. Kütüphaneli AES:")
    encrypted_lib = aes.encrypt(plaintext, use_library=True, key=test_key)
    print(f"   Şifreli: {encrypted_lib[:80]}...")
    decrypted_lib = aes.decrypt(encrypted_lib, use_library=True, key=test_key)
    print(f"   Çözülmüş: {decrypted_lib}")
    print(f"   Başarılı: {plaintext == decrypted_lib}")
    
    # Manuel
    print("\n2. Manuel AES:")
    encrypted_manual = aes.encrypt(plaintext, use_library=False, key=test_key)
    print(f"   Şifreli: {encrypted_manual[:80]}...")
    decrypted_manual = aes.decrypt(encrypted_manual, use_library=False, key=test_key)
    print(f"   Çözülmüş: {decrypted_manual}")
    print(f"   Başarılı: {plaintext == decrypted_manual}")

def test_des():
    print("\n" + "="*60)
    print("DES Test")
    print("="*60)
    
    des = DES_Cipher()
    plaintext = "Merhaba Dünya! Bu bir test mesajıdır."
    test_key = "test_key8"  # 8 karakter
    
    # Kütüphaneli
    print("\n1. Kütüphaneli DES:")
    encrypted_lib = des.encrypt(plaintext, use_library=True, key=test_key)
    print(f"   Şifreli: {encrypted_lib[:80]}...")
    decrypted_lib = des.decrypt(encrypted_lib, use_library=True, key=test_key)
    print(f"   Çözülmüş: {decrypted_lib}")
    print(f"   Başarılı: {plaintext == decrypted_lib}")
    
    # Manuel
    print("\n2. Manuel DES:")
    encrypted_manual = des.encrypt(plaintext, use_library=False, key=test_key)
    print(f"   Şifreli: {encrypted_manual[:80]}...")
    decrypted_manual = des.decrypt(encrypted_manual, use_library=False, key=test_key)
    print(f"   Çözülmüş: {decrypted_manual}")
    print(f"   Başarılı: {plaintext == decrypted_manual}")

def test_rsa():
    print("\n" + "="*60)
    print("RSA Test")
    print("="*60)
    
    rsa = RSA_Cipher()
    plaintext = "Merhaba Dünya!"
    
    # Anahtar çifti üret
    print("\n1. RSA Anahtar Çifti Üretiliyor...")
    public_key, private_key = RSA_Cipher.generate_keypair(2048)
    print(f"   Public Key: {public_key[:100]}...")
    print(f"   Private Key: {private_key[:100]}...")
    
    # Şifreleme
    print("\n2. RSA Şifreleme:")
    encrypted = rsa.encrypt(plaintext, public_key=public_key)
    print(f"   Şifreli: {encrypted[:80]}...")
    print(f"   Şifreli boyut: {len(encrypted)} byte")
    
    # Çözme
    print("\n3. RSA Çözme:")
    decrypted = rsa.decrypt(encrypted, private_key=private_key)
    print(f"   Çözülmüş: {decrypted}")
    print(f"   Başarılı: {plaintext == decrypted}")

if __name__ == "__main__":
    try:
        test_aes()
        test_des()
        test_rsa()
        print("\n" + "="*60)
        print("Tüm testler tamamlandı!")
        print("="*60)
    except Exception as e:
        print(f"\nHata: {e}")
        import traceback
        traceback.print_exc()

