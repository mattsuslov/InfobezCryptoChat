import os
import secrets
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.base import AsyncCodec

#Выбираем большой простой модуль для построения кольца
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
) 
P = int(P_HEX, 16) 

# P = 2**32 + 1

G = 2 #генератор. В нашем случае будут степени двойки
BLEN = (P.bit_length() + 7) // 8 #размер в байтах округленный вверх для ключей
NONCE_LEN = 12 

def _i2b(x: int) -> bytes:
    return x.to_bytes(BLEN, "big") #переводим в байты (второй параметр - порядок байтов)

def _hkdf(shared: bytes, info: bytes) -> bytes:
    """
    HKDF (HMAC-based Extract-and-Expand Key Derivation Function) — функция получения ключа, основанная на коде аутентификации сообщения HMAC. 
    Основной подход HKDF — это парадигма «извлечь-затем-развернуть». Первый этап берёт входной ключевой материал и «извлекает» из него псевдослучайный ключ фиксированной длины, а затем второй этап «расширяет» этот ключ на несколько дополнительных псевдослучайных ключей (выходные данные KDF). 
    HKDF может быть использован, например, для преобразования общих секретов, которыми обмениваются через Диффи–Хеллмана, в ключевой материал, пригодный для использования при шифровании, проверке целостности или аутентификации.
    https://en.wikipedia.org/wiki/HKDF

    Таким образом тут происходит хеширование. Параметры:

    shared - секретная информация
    info - дополнительная информация
    """
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)

class DHModpAESGCMCodec(AsyncCodec):
    name = "DH-MODP14"
    def __init__(self, key: bytes):
        self._aead = AESGCM(key) #создаем объект для шифрования с помощью ключа

    @staticmethod
    def _rand_secret() -> int:
        """Генерация секретного ключа на стороне инициатора
        
        Можно заменить на чтение из файла
        """
        return secrets.randbelow(P - 2) + 2

    @classmethod
    def derive_as_client(cls, a: int, server_pub_bytes: bytes, client_pub_bytes: bytes) -> "DHModpAESGCMCodec":
        """Принимаем от сервера публичный ключ и генерируем секретный ключ"""
        B = int.from_bytes(server_pub_bytes, "big") 
        if not (1 < B < P - 1):
            raise ValueError("Invalid server public")
        s = pow(B, a, P) # формируем серкетный ключ
        key = _hkdf(_i2b(s), b"MODP-2048-AESGCM-CHAT" + client_pub_bytes + server_pub_bytes)  #хэшируем ключ с добавлением информации об алгоритме и публичных ключах
        # Таким обоазом 
        return cls(key)

    @classmethod
    def derive_as_server(cls, b: int, client_pub_bytes: bytes, server_pub_bytes: bytes) -> "DHModpAESGCMCodec":
        A = int.from_bytes(client_pub_bytes, "big")
        if not (1 < A < P - 1):
            raise ValueError("Invalid client public")
        s = pow(A, b, P)
        key = _hkdf(_i2b(s), b"MODP-2048-AESGCM-CHAT" + client_pub_bytes + server_pub_bytes)
        return cls(key)

    @staticmethod
    def gen_pub(secret: int) -> bytes:
        """Генерация публичного ключа"""
        # logging.info("Генерация публичного ключа: возводим {G} в степень {secret} по модулю {P}".format(G=G, secret=secret, P=P))
        result = _i2b(pow(G, secret, P))
        # logging.info("Генерация публичного ключа завершена: %s", result.hex())
        return result

    async def encode(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(NONCE_LEN) #случайные байты
        ct = self._aead.encrypt(nonce, plaintext, None)
        return nonce + ct

    async def decode(self, ciphertext: bytes) -> bytes:
        nonce = ciphertext[:NONCE_LEN] #случайные байты
        ct = ciphertext[NONCE_LEN:]
        return self._aead.decrypt(nonce, ct, None)