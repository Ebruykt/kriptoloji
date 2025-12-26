import base64
import crypto.aes as aes_lib
import crypto.aes_manual as aes_manual
import crypto.des as des_lib

class AESCipher:
    def encrypt(self, text, key, use_library=True):
        if use_library:
            return aes_lib.encrypt(text, key)
        else:
            encrypted = aes_manual.encrypt(text, key)
            return base64.b64encode(encrypted).decode()

    def decrypt(self, text, key, use_library=True):
        if use_library:
            return aes_lib.decrypt(text, key)
        else:
            raw = base64.b64decode(text)
            return aes_manual.decrypt(raw, key)

class DESCipher:
    def encrypt(self, text, key, **kwargs):
        return des_lib.encrypt(text, key)

    def decrypt(self, text, key, **kwargs):
        return des_lib.decrypt(text, key)
