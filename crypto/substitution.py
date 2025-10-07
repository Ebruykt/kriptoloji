from .base import Cipher
import string

class Substitution(Cipher):
    """
    Monoalfabetik yerine koyma. 'mapping' 26 harfin permütasyonu olmalı.
    Ör: mapping="qwertyuiopasdfghjklzxcvbnm"
    """
    name = "substitution"

    def _validate(self, mapping: str):
        m = (mapping or "").lower()
        if len(m) != 26 or set(m) != set(string.ascii_lowercase):
            raise ValueError("mapping 26 harfin bir permütasyonu olmalı.")

    def encrypt(self, text: str, **kw) -> str:
        mapping = kw.get("mapping")
        self._validate(mapping)
        table_lower = {a:b for a,b in zip(string.ascii_lowercase, mapping.lower())}
        table_upper = {a.upper():b.upper() for a,b in table_lower.items()}
        out=[]
        for ch in text:
            if ch in table_lower: out.append(table_lower[ch])
            elif ch in table_upper: out.append(table_upper[ch])
            else: out.append(ch)
        return "".join(out)

    def decrypt(self, text: str, **kw) -> str:
        mapping = kw.get("mapping")
        self._validate(mapping)
        inv_lower = {b:a for a,b in zip(string.ascii_lowercase, mapping.lower())}
        inv_upper = {a.upper():b.upper() for a,b in inv_lower.items()}
        out=[]
        for ch in text:
            if ch in inv_lower: out.append(inv_lower[ch])
            elif ch in inv_upper: out.append(inv_upper[ch])
            else: out.append(ch)
        return "".join(out)
