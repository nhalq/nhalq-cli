import hashlib
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher_OLD:
    def __init__(self, password: str) -> None:
        self.block_size = AES.block_size
        self.key = hashlib.sha256(password.encode()).digest()

    def pad(self, s: str):
        remain = self.block_size - len(s) % self.block_size
        return s + remain * chr(remain)

    def unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, plain: str) -> bytes:
        plain = self.pad(plain)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(plain.encode())

    def decrypt(self, encrypted: bytes) -> str:
        iv = encrypted[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(encrypted[AES.block_size:])).decode("utf-8")


class AESCipher:
    def __init__(self, password: str) -> None:
        self.block_size = AES.block_size
        self.key = hashlib.sha256(password.encode()).digest()

    def pad(self, s: str):
        remain = self.block_size - len(s) % self.block_size
        return s + remain * chr(remain)

    def unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, plain: str) -> bytes:
        plain = self.pad(plain)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(plain.encode())

    def decrypt(self, encrypted: bytes) -> str:
        iv = encrypted[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(encrypted[AES.block_size:])).decode("utf-8")
