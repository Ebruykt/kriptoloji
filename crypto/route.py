"""
Route Cipher (Rota Şifresi) - Klasik Transpozisyon Şifrelemesi
Metni bir matrise yerleştirir ve belirli bir rotada okuyarak şifreler
"""
from .base import Cipher

class RouteCipher(Cipher):
    name = "route"
    
    def __init__(self):
        pass
    
    def encrypt(self, text: str, rows: int = 3, route: str = "spiral_clockwise", **kwargs) -> str:
        """
        Route Cipher ile şifreleme
        
        Args:
            text: Şifrelenecek metin
            rows: Satır sayısı
            route: Rota tipi ("spiral_clockwise", "spiral_counterclockwise", "zigzag", "diagonal")
        
        Returns:
            Şifrelenmiş metin
        """
        # Boşlukları kaldır
        text = text.replace(" ", "")
        
        # Sütun sayısını hesapla
        cols = (len(text) + rows - 1) // rows
        
        # Matrisi oluştur ve doldur
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        # Metni matrise yerleştir (satır satır)
        idx = 0
        for i in range(rows):
            for j in range(cols):
                if idx < len(text):
                    matrix[i][j] = text[idx]
                    idx += 1
                else:
                    matrix[i][j] = 'X'  # Dolgu karakteri
        
        # Seçilen rotaya göre şifrele
        if route == "spiral_clockwise":
            return self._read_spiral_clockwise(matrix, rows, cols)
        elif route == "spiral_counterclockwise":
            return self._read_spiral_counterclockwise(matrix, rows, cols)
        elif route == "zigzag":
            return self._read_zigzag(matrix, rows, cols)
        elif route == "diagonal":
            return self._read_diagonal(matrix, rows, cols)
        else:
            # Varsayılan: sütun sütun oku
            return self._read_column_by_column(matrix, rows, cols)
    
    def decrypt(self, text: str, rows: int = 3, route: str = "spiral_clockwise", **kwargs) -> str:
        """
        Route Cipher ile şifre çözme
        
        Args:
            text: Şifreli metin
            rows: Satır sayısı
            route: Rota tipi
        
        Returns:
            Çözülmüş metin
        """
        cols = (len(text) + rows - 1) // rows
        
        # Matrisi oluştur
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        # Şifreli metni rotaya göre matrise yerleştir
        if route == "spiral_clockwise":
            matrix = self._write_spiral_clockwise(text, rows, cols)
        elif route == "spiral_counterclockwise":
            matrix = self._write_spiral_counterclockwise(text, rows, cols)
        elif route == "zigzag":
            matrix = self._write_zigzag(text, rows, cols)
        elif route == "diagonal":
            matrix = self._write_diagonal(text, rows, cols)
        else:
            matrix = self._write_column_by_column(text, rows, cols)
        
        # Satır satır oku
        result = ""
        for i in range(rows):
            for j in range(cols):
                if matrix[i][j]:
                    result += matrix[i][j]
        
        return result.rstrip('X')  # Dolgu karakterlerini kaldır
    
    def _read_spiral_clockwise(self, matrix, rows, cols):
        """Saat yönünde spiral okuma"""
        result = ""
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        
        while top <= bottom and left <= right:
            # Sağa git
            for i in range(left, right + 1):
                result += matrix[top][i]
            top += 1
            
            # Aşağı git
            for i in range(top, bottom + 1):
                result += matrix[i][right]
            right -= 1
            
            # Sola git
            if top <= bottom:
                for i in range(right, left - 1, -1):
                    result += matrix[bottom][i]
                bottom -= 1
            
            # Yukarı git
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    result += matrix[i][left]
                left += 1
        
        return result
    
    def _write_spiral_clockwise(self, text, rows, cols):
        """Saat yönünde spiral yazma"""
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        idx = 0
        
        while top <= bottom and left <= right and idx < len(text):
            for i in range(left, right + 1):
                if idx < len(text):
                    matrix[top][i] = text[idx]
                    idx += 1
            top += 1
            
            for i in range(top, bottom + 1):
                if idx < len(text):
                    matrix[i][right] = text[idx]
                    idx += 1
            right -= 1
            
            if top <= bottom:
                for i in range(right, left - 1, -1):
                    if idx < len(text):
                        matrix[bottom][i] = text[idx]
                        idx += 1
                bottom -= 1
            
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    if idx < len(text):
                        matrix[i][left] = text[idx]
                        idx += 1
                left += 1
        
        return matrix
    
    def _read_spiral_counterclockwise(self, matrix, rows, cols):
        """Saat yönünün tersine spiral okuma"""
        result = ""
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        
        while top <= bottom and left <= right:
            # Aşağı git
            for i in range(top, bottom + 1):
                result += matrix[i][left]
            left += 1
            
            # Sağa git
            if left <= right:
                for i in range(left, right + 1):
                    result += matrix[bottom][i]
                bottom -= 1
            
            # Yukarı git
            if top <= bottom:
                for i in range(bottom, top - 1, -1):
                    result += matrix[i][right]
                right -= 1
            
            # Sola git
            if left <= right:
                for i in range(right, left - 1, -1):
                    result += matrix[top][i]
                top += 1
        
        return result
    
    def _write_spiral_counterclockwise(self, text, rows, cols):
        """Saat yönünün tersine spiral yazma"""
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        idx = 0
        
        while top <= bottom and left <= right and idx < len(text):
            for i in range(top, bottom + 1):
                if idx < len(text):
                    matrix[i][left] = text[idx]
                    idx += 1
            left += 1
            
            if left <= right:
                for i in range(left, right + 1):
                    if idx < len(text):
                        matrix[bottom][i] = text[idx]
                        idx += 1
                bottom -= 1
            
            if top <= bottom:
                for i in range(bottom, top - 1, -1):
                    if idx < len(text):
                        matrix[i][right] = text[idx]
                        idx += 1
                right -= 1
            
            if left <= right:
                for i in range(right, left - 1, -1):
                    if idx < len(text):
                        matrix[top][i] = text[idx]
                        idx += 1
                top += 1
        
        return matrix
    
    def _read_zigzag(self, matrix, rows, cols):
        """Zigzag (yılan) okuma"""
        result = ""
        for i in range(rows):
            if i % 2 == 0:
                # Soldan sağa
                for j in range(cols):
                    result += matrix[i][j]
            else:
                # Sağdan sola
                for j in range(cols - 1, -1, -1):
                    result += matrix[i][j]
        return result
    
    def _write_zigzag(self, text, rows, cols):
        """Zigzag yazma"""
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        idx = 0
        
        for i in range(rows):
            if i % 2 == 0:
                for j in range(cols):
                    if idx < len(text):
                        matrix[i][j] = text[idx]
                        idx += 1
            else:
                for j in range(cols - 1, -1, -1):
                    if idx < len(text):
                        matrix[i][j] = text[idx]
                        idx += 1
        
        return matrix
    
    def _read_diagonal(self, matrix, rows, cols):
        """Çapraz okuma"""
        result = ""
        # Sol üstten sağ alta doğru çaprazlar
        for k in range(rows + cols - 1):
            if k < cols:
                i, j = 0, k
            else:
                i, j = k - cols + 1, cols - 1
            
            while i < rows and j >= 0:
                result += matrix[i][j]
                i += 1
                j -= 1
        
        return result
    
    def _write_diagonal(self, text, rows, cols):
        """Çapraz yazma"""
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        idx = 0
        
        for k in range(rows + cols - 1):
            if k < cols:
                i, j = 0, k
            else:
                i, j = k - cols + 1, cols - 1
            
            while i < rows and j >= 0 and idx < len(text):
                matrix[i][j] = text[idx]
                idx += 1
                i += 1
                j -= 1
        
        return matrix
    
    def _read_column_by_column(self, matrix, rows, cols):
        """Sütun sütun okuma"""
        result = ""
        for j in range(cols):
            for i in range(rows):
                result += matrix[i][j]
        return result
    
    def _write_column_by_column(self, text, rows, cols):
        """Sütun sütun yazma"""
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        idx = 0
        
        for j in range(cols):
            for i in range(rows):
                if idx < len(text):
                    matrix[i][j] = text[idx]
                    idx += 1
        
        return matrix

