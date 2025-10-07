from abc import ABC, abstractmethod

class Cipher(ABC):
    name: str  # örn: "caesar"

    @abstractmethod
    def encrypt(self, text: str, **kwargs) -> str: ...
    @abstractmethod
    def decrypt(self, text: str, **kwargs) -> str: ...
