"""
Pigpen Cipher (Domuz Ahırı Şifresi / Freemason Cipher)
Her harf için özel semboller kullanan görsel bir şifreleme yöntemi
"""
from .base import Cipher

class PigpenCipher(Cipher):
    name = "pigpen"
    
    def __init__(self):
        # Pigpen şifreleme haritası (ASCII sanat ile temsil)
        # Grid 1: # şeklinde
        # A B C
        # D E F
        # G H I
        
        # Grid 2: X şeklinde
        # J K L M
        # N O P Q
        # R S T U
        # V W X Y Z
        
        # Her harf için sembol açıklaması (basitleştirilmiş versiyonu)
        self.pigpen_map = {
            'A': '⌈⌉', 'B': '[]', 'C': '⌊⌋',
            'D': '⌈_⌉', 'E': '[_]', 'F': '⌊_⌋',
            'G': '⎡⎤', 'H': '||', 'I': '⎣⎦',
            'J': '<>', 'K': '<.>', 'L': '/\\', 'M': '/.\\ ',
            'N': '<>', 'O': '<.>', 'P': '\\/', 'Q': '\\./',
            'R': '><', 'S': '>.<', 'T': 'V', 'U': 'V.',
            'V': '^', 'W': '^.', 'X': 'X', 'Y': 'X.', 'Z': '*'
        }
        
        # Alternatif: Sayısal gösterim (daha pratik)
        # Her harf için bir kod
        self.numeric_map = {
            'A': '11', 'B': '12', 'C': '13',
            'D': '14', 'E': '15', 'F': '16',
            'G': '17', 'H': '18', 'I': '19',
            'J': '21', 'K': '22', 'L': '23', 'M': '24',
            'N': '25', 'O': '26', 'P': '27', 'Q': '28',
            'R': '31', 'S': '32', 'T': '33', 'U': '34',
            'V': '35', 'W': '36', 'X': '37', 'Y': '38', 'Z': '39'
        }
        
        # Ters harita (decode için)
        self.reverse_numeric_map = {v: k for k, v in self.numeric_map.items()}
    
    def encrypt(self, text: str, use_numeric: bool = True, **kwargs) -> str:
        """
        Pigpen Cipher ile şifreleme
        
        Args:
            text: Şifrelenecek metin
            use_numeric: True ise sayısal gösterim, False ise sembol gösterimi kullanır
        
        Returns:
            Şifrelenmiş metin
        """
        text = text.upper().replace(" ", "")
        result = ""
        
        if use_numeric:
            for char in text:
                if char in self.numeric_map:
                    result += self.numeric_map[char] + " "
                else:
                    result += char + " "
        else:
            for char in text:
                if char in self.pigpen_map:
                    result += self.pigpen_map[char] + " "
                else:
                    result += char + " "
        
        return result.strip()
    
    def decrypt(self, text: str, use_numeric: bool = True, **kwargs) -> str:
        """
        Pigpen Cipher ile şifre çözme
        
        Args:
            text: Şifreli metin
            use_numeric: True ise sayısal gösterim, False ise sembol gösterimi kullanır
        
        Returns:
            Çözülmüş metin
        """
        result = ""
        
        if use_numeric:
            # Sayısal gösterimi çöz
            codes = text.split()
            for code in codes:
                if code in self.reverse_numeric_map:
                    result += self.reverse_numeric_map[code]
                else:
                    result += code
        else:
            # Sembol gösterimini çöz
            reverse_pigpen_map = {v: k for k, v in self.pigpen_map.items()}
            symbols = text.split()
            for symbol in symbols:
                if symbol in reverse_pigpen_map:
                    result += reverse_pigpen_map[symbol]
                else:
                    result += symbol
        
        return result
    
    def get_cipher_grid(self) -> str:
        """
        Pigpen şifre ızgarasını metin formatında döndürür
        """
        grid = """
        Pigpen Cipher Grid:
        
        Grid 1 (# şekli):     Grid 2 (X şekli):
        ┌─┬─┬─┐              ╲   ╱
        │A│B│C│               ╲J╱K
        ├─┼─┼─┤                ╳
        │D│E│F│               ╱L╲M
        ├─┼─┼─┤              ╱   ╲
        │G│H│I│
        └─┴─┴─┘              ╲   ╱
                              ╲N╱O
        Grid 3 (# noktalı):   ╳
        ┌─┬─┬─┐              ╱P╲Q
        │J│K│L│             ╱   ╲
        ├─┼─┼─┤
        │M│N│O│             ╲   ╱
        ├─┼─┼─┤              ╲R╱S
        │P│Q│R│               ╳
        └─┴─┴─┘              ╱T╲U
                            ╱   ╲
        Grid 4 (X noktalı):
                            ╲   ╱
                             ╲V╱W
                              ╳
                             ╱X╲Y
                            ╱   ╲
                            
                            Z = (nokta)
        """
        return grid

