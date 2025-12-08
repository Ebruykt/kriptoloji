from .base import Cipher

class Playfair(Cipher):
    name = "playfair"

    def _prepare_key(self, key: str) -> str:
        """Anahtarı temizle ve tekrarları kaldır"""
        key = "".join([c.upper() for c in key if c.isalpha()])
        seen = set()
        result = []
        for ch in key:
            if ch not in seen:
                result.append(ch)
                seen.add(ch)
        return "".join(result)

    def _create_matrix(self, key: str) -> list:
        """5x5 Playfair matrisi oluştur"""
        # I ve J aynı hücrede (I kullanılır)
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J yok
        key_clean = self._prepare_key(key)
        
        # Anahtarı matrise ekle
        matrix = []
        used = set()
        
        # Anahtar harflerini ekle
        for ch in key_clean:
            if ch == 'J':
                ch = 'I'  # J'yi I'ya çevir
            if ch not in used:
                matrix.append(ch)
                used.add(ch)
        
        # Kalan harfleri ekle
        for ch in alphabet:
            if ch not in used:
                matrix.append(ch)
        
        # 5x5 matris olarak döndür
        return [matrix[i:i+5] for i in range(0, 25, 5)]

    def _find_position(self, matrix: list, char: str) -> tuple:
        """Bir harfin matristeki pozisyonunu bul"""
        if char == 'J':
            char = 'I'
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return (i, j)
        return None

    def _prepare_text(self, text: str, encrypt: bool = True) -> str:
        """Metni çiftlere ayırmak için hazırla"""
        text = "".join([c.upper() for c in text if c.isalpha()])
        if not text:
            return ""
        
        # J'yi I'ya çevir
        text = text.replace('J', 'I')
        
        pairs = []
        i = 0
        while i < len(text):
            if i + 1 < len(text):
                # İki harf var
                if text[i] == text[i + 1]:
                    # Aynı harf yan yana, X ekle (veya Q şifre çözme için)
                    if encrypt:
                        pairs.append(text[i] + 'X')
                        i += 1
                    else:
                        # Şifre çözme: Q ekle
                        pairs.append(text[i] + 'Q')
                        i += 1
                else:
                    pairs.append(text[i] + text[i + 1])
                    i += 2
            else:
                # Tek harf kaldı, X ekle
                pairs.append(text[i] + 'X')
                i += 1
        
        return pairs

    def _encrypt_pair(self, matrix: list, pair: str) -> str:
        """Bir çifti şifrele"""
        pos1 = self._find_position(matrix, pair[0])
        pos2 = self._find_position(matrix, pair[1])
        
        if not pos1 or not pos2:
            return pair
        
        r1, c1 = pos1
        r2, c2 = pos2
        
        # Aynı satırda
        if r1 == r2:
            return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        # Aynı sütunda
        elif c1 == c2:
            return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        # Dikdörtgen kuralı
        else:
            return matrix[r1][c2] + matrix[r2][c1]

    def _decrypt_pair(self, matrix: list, pair: str) -> str:
        """Bir çifti çöz"""
        pos1 = self._find_position(matrix, pair[0])
        pos2 = self._find_position(matrix, pair[1])
        
        if not pos1 or not pos2:
            return pair
        
        r1, c1 = pos1
        r2, c2 = pos2
        
        # Aynı satırda
        if r1 == r2:
            return matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]
        # Aynı sütunda
        elif c1 == c2:
            return matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]
        # Dikdörtgen kuralı
        else:
            return matrix[r1][c2] + matrix[r2][c1]

    def encrypt(self, text: str, **kw) -> str:
        """Metni Playfair ile şifrele"""
        key = kw.get("key", "PLAYFAIR")
        if not key or not any(c.isalpha() for c in key):
            raise ValueError("Playfair için alfabetik bir anahtar gerekli.")
        
        matrix = self._create_matrix(key)
        pairs = self._prepare_text(text, encrypt=True)
        
        result = []
        for pair in pairs:
            result.append(self._encrypt_pair(matrix, pair))
        
        return "".join(result)

    def decrypt(self, text: str, **kw) -> str:
        """Playfair ile şifrelenmiş metni çöz"""
        key = kw.get("key", "PLAYFAIR")
        if not key or not any(c.isalpha() for c in key):
            raise ValueError("Playfair için alfabetik bir anahtar gerekli.")
        
        matrix = self._create_matrix(key)
        pairs = self._prepare_text(text, encrypt=False)
        
        result = []
        for pair in pairs:
            result.append(self._decrypt_pair(matrix, pair))
        
        decrypted = "".join(result)
        # Son harf X ise ve gereksizse kaldır (basit kontrol)
        if len(decrypted) > 1 and decrypted[-1] == 'X':
            # Eğer son ikinci harf ile son harf aynı değilse, X muhtemelen padding
            if len(decrypted) >= 2 and decrypted[-2] != decrypted[-1]:
                decrypted = decrypted[:-1]
        
        return decrypted

