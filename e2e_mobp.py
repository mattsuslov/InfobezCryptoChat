import os
import base64
import secrets
from typing import Dict, Tuple, Optional, Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from client import AsyncChatClient

HELLO = "__E2E1_HELLO__:"
REPLY = "__E2E1_REPLY__:"
MSG = "__E2E1_MSG__:"  # "__E2E1_MSG__:recipient:b64(nonce+ciphertext)"
NONCE_LEN = 12
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
G = 2
BLEN = (P.bit_length() + 7) // 8

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))

def _hkdf(shared_bytes: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(shared_bytes)

def _i2b(x: int) -> bytes:
    return x.to_bytes(BLEN, "big")

class E2EModpManager:
    def __init__(self, client: AsyncChatClient, username: str):
        self.client = client
        self.username = username

        self._a = secrets.randbelow(P - 2) + 2
        self._A = pow(G, self._a, P)
        self._Ab = _i2b(self._A)

        # Запоминаем публичные ключи других пользователей
        self._peer_pub: Dict[str, int] = {}
        self._peer_pub_bytes: Dict[str, bytes] = {}

        # Запоминаем секретные ключи для шифрования с определенными пользователями
        self._aead_send: Dict[str, AESGCM] = {}
        self._aead_recv: Dict[str, AESGCM] = {}

    def get_users(self) -> Iterable[str]:
        return self._peer_pub.keys()

    async def announce(self) -> None:
        """Через broadcast сервер передем свой публичный ключ"""
        await self.client.send(f"{HELLO}{_b64e(self._Ab)}")

    async def _reply(self) -> None:
        """Через broadcast сервер передем свой публичный ключ"""
        await self.client.send(f"{REPLY}{_b64e(self._Ab)}")

    def _derive_aead_pair(self, peer: str) -> Tuple[AESGCM, AESGCM]:
        """Вычисляем секретные ключи для шифрования с определенными пользователями"""
        B = self._peer_pub[peer]
        if not (1 < B < P - 1):
            raise ValueError("Invalid peer public")
        s = pow(B, self._a, P)
        sb = _i2b(s)
        pk_self, pk_peer = (self._Ab, self._peer_pub_bytes[peer])

        info_send = b"E2E1-MODP14|" + self.username.encode() + b"->" + peer.encode() + b"|" + pk_self + pk_peer
        info_recv = b"E2E1-MODP14|" + peer.encode() + b"->" + self.username.encode() + b"|" + pk_peer + pk_self

        k_send = _hkdf(sb, info_send)
        k_recv = _hkdf(sb, info_recv)
        return AESGCM(k_send), AESGCM(k_recv)

    def _ensure_keys(self, peer: str) -> None:
        if peer not in self._aead_send or peer not in self._aead_recv:
            a_s, a_r = self._derive_aead_pair(peer)
            self._aead_send[peer] = a_s
            self._aead_recv[peer] = a_r

    async def send_private(self, message: str, recipients: Optional[Iterable[str]] = None) -> None:
        if recipients is None:
            recipients = [u for u in self._peer_pub.keys() if u != self.username]
        data = message.encode("utf-8")
        for r in recipients:
            if r not in self._peer_pub: #пользователь мог пропасть
                continue
            self._ensure_keys(r) #генерируем секретные ключи
            nonce = os.urandom(NONCE_LEN)
            aad = (self.username + "->" + r).encode()
            ct = self._aead_send[r].encrypt(nonce, data, aad) #укзаываем, кому отправляем
            await self.client.send(f"{MSG}{r}:{_b64e(nonce + ct)}")

    async def handle_incoming(self, sender: str, text: str):
        """Функция вызывается при получении любого сообщения на сервере"""
        if text.startswith(HELLO): #Если это инициирование общения
            try:
                pb = _b64d(text[len(HELLO):]) #Получаем публичный ключ
                if len(pb) == BLEN:
                    B = int.from_bytes(pb, "big")
                    if 1 < B < P - 1:
                        self._peer_pub[sender] = B #Сохраняем публичный ключ TODO: зачем? 
                        self._peer_pub_bytes[sender] = pb #Сохраняем публичный ключ в байтах
                        await self._reply() # сразу запускам процесс ответа
            except Exception:
                pass
            return True, None

        if text.startswith(REPLY): #Если пришел чей-то ответ
            try:
                pb = _b64d(text[len(REPLY):])
                if len(pb) == BLEN:
                    B = int.from_bytes(pb, "big")
                    if 1 < B < P - 1:
                        self._peer_pub[sender] = B
                        self._peer_pub_bytes[sender] = pb
            except Exception:
                pass
            return True, None

        if text.startswith(MSG): #Если пришло приватное сообщение, то зная публичный ключ отправителя и свой секретный ключ, можно расшифровать сообщение
            try:
                rest = text[len(MSG):]
                to_user, b64 = rest.split(":", 1)
                if to_user != self.username:
                    return True, None
                if sender not in self._peer_pub:
                    return True, None
                self._ensure_keys(sender) #Создаем секретные ключи с пользователем (на чтение и на запись сообщений)
                blob = _b64d(b64)
                nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
                aad = (sender + "->" + self.username).encode() #В тег AES было добавлено при отправке, поэтому тут проверяем
                pt = self._aead_recv[sender].decrypt(nonce, ct, aad)
                return True, pt.decode("utf-8")
            except Exception:
                return True, None

        return False, None