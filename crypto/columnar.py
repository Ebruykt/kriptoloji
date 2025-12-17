"""
Columnar Transposition Cipher (Sütunlu Transpozisyon Şifresi)
Metni sütunlara böler ve anahtar kelimeye göre sütunları yeniden düzenler
"""
from .base import Cipher

class ColumnarCipher(Cipher):
    name = "columnar"
    
    def __init__(self):
        pass
    
    def encrypt(self, text: str, key: str = "CRYPTO", **kwargs) -> str:
        """
        Columnar Transposition ile şifreleme
        
        Args:
            text: Şifrelenecek metin
            key: Anahtar kelime (sütunların sırasını belirler)
        
        Returns:
            Şifrelenmiş metin
        """
        # Boşlukları kaldır
        text = text.replace(" ", "")
        key = key.upper()
        
        # Anahtar uzunluğu = sütun sayısı
        num_cols = len(key)
        num_rows = (len(text) + num_cols - 1) // num_cols
        
        # Matrisi oluştur
        matrix = [['' for _ in range(num_cols)] for _ in range(num_rows)]
        
        # Metni satır satır yerleştir
        idx = 0
        for i in range(num_rows):
            for j in range(num_cols):
                if idx < len(text):
                    matrix[i][j] = text[idx]
                    idx += 1
                else:
                    matrix[i][j] = 'X'  # Dolgu karakteri
        
        # Anahtar sıralamasını bul
        # Her karaktere indeksini ver ve alfabetik sıraya göre düzenle
        key_indices = list(range(len(key)))
        key_indices.sort(key=lambda x: (key[x], x))  # Önce harfe göre, sonra orijinal pozisyona göre
        
        result = ""
        for col_idx in key_indices:
            for i in range(num_rows):
                result += matrix[i][col_idx]
        
        return result
    
    def decrypt(self, text: str, key: str = "CRYPTO", **kwargs) -> str:
        """
        Columnar Transposition ile şifre çözme
        
        Args:
            text: Şifreli metin
            key: Anahtar kelime
        
        Returns:
            Çözülmüş metin
        """
        key = key.upper()
        num_cols = len(key)
        num_rows = len(text) // num_cols
        
        # Anahtar sıralamasını bul
        key_indices = list(range(len(key)))
        key_indices.sort(key=lambda x: (key[x], x))  # Önce harfe göre, sonra orijinal pozisyona göre
        
        # Matrisi oluştur
        matrix = [['' for _ in range(num_cols)] for _ in range(num_rows)]
        
        # Şifreli metni sütunlara yerleştir (sıralamaya göre)
        idx = 0
        for col_idx in key_indices:
            for i in range(num_rows):
                if idx < len(text):
                    matrix[i][col_idx] = text[idx]
                    idx += 1
        
        # Satır satır oku
        result = ""
        for i in range(num_rows):
            for j in range(num_cols):
                if matrix[i][j]:
                    result += matrix[i][j]
        
        return result.rstrip('X')  # Dolgu karakterlerini kaldır

