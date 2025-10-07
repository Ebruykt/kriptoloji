from .base import Cipher
import math

class Affine(Cipher):
    """
    E(x) = (a*x + b) mod 26 ; gcd(a,26)=1 olmalı.
    """
    name = "affine"

    def _modinv(self, a, m):
        # Genişletilmiş Öklid
        t, newt = 0, 1
        r, newr = m, a % m
        while newr != 0:
            q = r // newr
            t, newt = newt, t - q*newt
            r, newr = newr, r - q*newr
        if r > 1:
            raise ValueError("a ile 26 aralarında asal olmalı.")
        if t < 0:
            t += m
        return t

    def encrypt(self, text: str, **kw) -> str:
        a = int(kw.get("a", 5)); b = int(kw.get("b", 8))
        if math.gcd(a,26) != 1:
            raise ValueError("a ile 26 aralarında asal olmalı.")
        out=[]
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                x = ord(ch) - base
                y = (a*x + b) % 26
                out.append(chr(base + y))
            else:
                out.append(ch)
        return "".join(out)

    def decrypt(self, text: str, **kw) -> str:
        a = int(kw.get("a", 5)); b = int(kw.get("b", 8))
        if math.gcd(a,26) != 1:
            raise ValueError("a ile 26 aralarında asal olmalı.")
        a_inv = self._modinv(a, 26)
        out=[]
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                y = ord(ch) - base
                x = (a_inv*(y - b)) % 26
                out.append(chr(base + x))
            else:
                out.append(ch)
        return "".join(out)
