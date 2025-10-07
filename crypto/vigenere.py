from .base import Cipher

class Vigenere(Cipher):
    name = "vigenere"

    def _process(self, text: str, key: str, enc=True):
        key = "".join([c.lower() for c in key if c.isalpha()])
        if not key:
            raise ValueError("Vigenere için alfabetik bir anahtar gerekli.")
        out, j = [], 0
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                k = ord(key[j % len(key)]) - ord('a')
                if not enc:
                    k = -k
                idx = (ord(ch) - base + k) % 26
                out.append(chr(base + idx))
                j += 1
            else:
                out.append(ch)
        return "".join(out)

    def encrypt(self, text: str, **kw) -> str:
        return self._process(text, kw.get("key", "key"), enc=True)

    def decrypt(self, text: str, **kw) -> str:
        return self._process(text, kw.get("key", "key"), enc=False)
