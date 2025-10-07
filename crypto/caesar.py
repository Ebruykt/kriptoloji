from .base import Cipher

class Caesar(Cipher):
    name = "caesar"

    def _shift(self, text: str, k: int):
        out = []
        k %= 26
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                idx = (ord(ch) - base + k) % 26
                out.append(chr(base + idx))
            else:
                out.append(ch)
        return "".join(out)

    def encrypt(self, text: str, **kw) -> str:
        return self._shift(text, int(kw.get("k", 3)))

    def decrypt(self, text: str, **kw) -> str:
        return self._shift(text, -int(kw.get("k", 3)))
