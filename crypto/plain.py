# chat/crypto/plain.py
from crypto.base import AsyncCodec

class PlainCodec(AsyncCodec):
    name = "PLAIN"
    async def encode(self, plaintext: bytes) -> bytes:
        return plaintext
    async def decode(self, ciphertext: bytes) -> bytes:
        return ciphertext