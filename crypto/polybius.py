"""
Polybius Square Cipher (Polybius Karesi)
Harfleri 5x5 ızgarada koordinatlarla temsil eden şifreleme yöntemi
"""
from .base import Cipher

class PolybiusCipher(Cipher):
    name = "polybius"
    
    def __init__(self):
        # Klasik Polybius karesi (5x5 - I ve J birleşik)
        # Satırlar ve sütunlar 1-5 ile numaralandırılır
        self.square = [
            ['A', 'B', 'C', 'D', 'E'],
            ['F', 'G', 'H', 'I', 'J'],  # I ve J aynı hücrede
            ['K', 'L', 'M', 'N', 'O'],
            ['P', 'Q', 'R', 'S', 'T'],
            ['U', 'V', 'W', 'X', 'Y'],
            ['Z', ' ', ' ', ' ', ' ']   # Z için ekstra satır
        ]
        
        # Daha iyi organizasyon için harften koordinata harita
        self.letter_to_coord = {}
        for i, row in enumerate(self.square):
            for j, letter in enumerate(row):
                if letter and letter != ' ':
                    # Satır ve sütun 1'den başlar
                    self.letter_to_coord[letter] = (str(i + 1), str(j + 1))
        
        # J harfi I ile aynı
        self.letter_to_coord['J'] = self.letter_to_coord['I']
        
        # Koordinattan harfe harita
        self.coord_to_letter = {v: k for k, v in self.letter_to_coord.items()}
    
    def encrypt(self, text: str, use_numbers: bool = True, **kwargs) -> str:
        """
        Polybius Square ile şifreleme
        
        Args:
            text: Şifrelenecek metin
            use_numbers: True ise sayılar kullanır (11, 12...), False ise harfler (AA, AB...)
        
        Returns:
            Şifrelenmiş metin
        """
        text = text.upper().replace(" ", "")
        result = ""
        
        for char in text:
            if char in self.letter_to_coord:
                row, col = self.letter_to_coord[char]
                if use_numbers:
                    result += row + col + " "
                else:
                    # Harflerle gösterim (A=1, B=2, ...)
                    row_letter = chr(ord('A') + int(row) - 1)
                    col_letter = chr(ord('A') + int(col) - 1)
                    result += row_letter + col_letter + " "
            else:
                # Bilinmeyen karakteri olduğu gibi ekle
                result += char + " "
        
        return result.strip()
    
    def decrypt(self, text: str, use_numbers: bool = True, **kwargs) -> str:
        """
        Polybius Square ile şifre çözme
        
        Args:
            text: Şifreli metin
            use_numbers: True ise sayılar kullanır, False ise harfler
        
        Returns:
            Çözülmüş metin
        """
        result = ""
        
        if use_numbers:
            # Sayısal koordinatları çöz
            # Metin "11 23 34" formatında
            pairs = text.split()
            for pair in pairs:
                if len(pair) == 2 and pair.isdigit():
                    row, col = pair[0], pair[1]
                    if (row, col) in self.coord_to_letter:
                        result += self.coord_to_letter[(row, col)]
                    else:
                        result += pair
                else:
                    result += pair
        else:
            # Harfli koordinatları çöz
            # Metin "AA BC CD" formatında
            pairs = text.split()
            for pair in pairs:
                if len(pair) == 2 and pair.isalpha():
                    row = str(ord(pair[0]) - ord('A') + 1)
                    col = str(ord(pair[1]) - ord('A') + 1)
                    if (row, col) in self.coord_to_letter:
                        result += self.coord_to_letter[(row, col)]
                    else:
                        result += pair
                else:
                    result += pair
        
        return result
    
    def get_square(self) -> str:
        """
        Polybius karesini metin formatında döndürür
        """
        output = "Polybius Square:\n\n"
        output += "    1  2  3  4  5\n"
        output += "  ┌──┬──┬──┬──┬──┐\n"
        
        for i, row in enumerate(self.square):
            if i >= 5:  # Z için olan ekstra satır
                break
            output += f"{i+1} │"
            for letter in row[:5]:
                if letter and letter != ' ':
                    if letter == 'I':
                        output += "I/J│"
                    else:
                        output += f" {letter} │"
                else:
                    output += "   │"
            output += "\n"
            if i < 4:
                output += "  ├──┼──┼──┼──┼──┤\n"
            else:
                output += "  └──┴──┴──┴──┴──┘\n"
        
        # Z için özel not
        output += "\nNote: Z = 61 (özel durum)\n"
        output += "I ve J aynı koordinatı paylaşır (24)\n"
        
        return output
    
    def encrypt_with_bifid(self, text: str, period: int = 5, **kwargs) -> str:
        """
        Bifid Cipher varyasyonu - daha güçlü şifreleme
        Koordinatları periyotlara böler ve satır-sütun karışımı yapar
        
        Args:
            text: Şifrelenecek metin
            period: Periyot uzunluğu
        
        Returns:
            Şifrelenmiş metin
        """
        text = text.upper().replace(" ", "")
        
        # Koordinatları al
        rows = []
        cols = []
        for char in text:
            if char in self.letter_to_coord:
                row, col = self.letter_to_coord[char]
                rows.append(row)
                cols.append(col)
        
        # Satır ve sütunları birleştir
        combined = rows + cols
        
        # Periyotlara göre şifrele
        result = ""
        for i in range(0, len(combined), 2):
            if i + 1 < len(combined):
                row, col = combined[i], combined[i + 1]
                if (row, col) in self.coord_to_letter:
                    result += self.coord_to_letter[(row, col)]
        
        return result
    
    def decrypt_with_bifid(self, text: str, period: int = 5, **kwargs) -> str:
        """
        Bifid Cipher varyasyonu ile şifre çözme
        
        Args:
            text: Şifreli metin
            period: Periyot uzunluğu
        
        Returns:
            Çözülmüş metin
        """
        # Koordinatları al
        combined = []
        for char in text:
            if char in self.letter_to_coord:
                row, col = self.letter_to_coord[char]
                combined.extend([row, col])
        
        # Ortadan böl
        mid = len(combined) // 2
        rows = combined[:mid]
        cols = combined[mid:]
        
        # Orijinal metni geri oluştur
        result = ""
        for i in range(len(rows)):
            if i < len(cols):
                coord = (rows[i], cols[i])
                if coord in self.coord_to_letter:
                    result += self.coord_to_letter[coord]
        
        return result

