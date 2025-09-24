# chat/crypto/base.py
import asyncio
from typing import Protocol

class AsyncCodec(Protocol):
    name: str
    async def encode(self, plaintext: bytes) -> bytes: ...
    async def decode(self, ciphertext: bytes) -> bytes: ...