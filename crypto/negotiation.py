import asyncio
import logging
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from common import read_framed, write_framed
from crypto.plain import PlainCodec
from crypto.dh_modp_aesgcm import DHModpAESGCMCodec, BLEN as MODP14_BLEN


ALG_PLAIN = b"ALG:PLAIN"
ALG_DHMP14 = b"ALG:DHMP14"
ALG_DHMP14R = b"ALG:DHMP14R"

async def client_negotiate(reader, writer, alg: str = "plain"):
    a = alg.lower()
    if a == "plain":
        await write_framed(writer, ALG_PLAIN)
        return PlainCodec()

    if a in ("dh_modp", "modp14", "dh14"):
        sec = DHModpAESGCMCodec  # alias
        x = sec._rand_secret() #секретный ключ на стороне клиента
        A = sec.gen_pub(x) #публичный ключ
        logging.info("Отправляем публичный ключ на сервер: %s", A.hex())
        await write_framed(writer, ALG_DHMP14 + A) #отправляем публичный ключ на сервер
        logging.info("Ключ отправлен.")

        #ожидаем ответ ...
        logging.info("Ожидаем ответ сервера.")
        resp = await read_framed(reader) 
        logging.info("Ответ от сервера получен.")

        if not (len(resp) == len(ALG_DHMP14R) + MODP14_BLEN and resp.startswith(ALG_DHMP14R)):
            """Одновременно должны выполняться 2 условия:
            
            1. длина ответа == ожидаемая длина заголовка + длина секретного ключа
            2. Ответ начинается с правильного алгоритма
            """
            raise RuntimeError("Handshake failed")
        B = resp[len(ALG_DHMP14R):] 
        return DHModpAESGCMCodec.derive_as_client(x, B, A)

    raise ValueError("Unknown algorithm")

async def server_negotiate(reader, writer):
    hello = await read_framed(reader)
    logging.info("Клиент начинает рукопожатие: %s", hello)

    if hello == ALG_PLAIN:
        return PlainCodec()

    logging.info("длина заголовка: %d, ожидаемая длина заголовка: %d", len(hello), len(ALG_DHMP14) + MODP14_BLEN)
    if hello.startswith(ALG_DHMP14) and len(hello) == len(ALG_DHMP14) + MODP14_BLEN:
        client_pub = hello[len(ALG_DHMP14):] #Получаем публичный ключ клиента
        sec = DHModpAESGCMCodec
        logging.info("Генерируем секретный ключ")
        y = sec._rand_secret() #секретный ключ на стороне сервера
        logging.info("Секретный ключ сгенерирован")

        B = sec.gen_pub(y) #публичный ключ
        logging.info("Отправляем свой публичный ключ клиенту: %s", B.hex())
        await write_framed(writer, ALG_DHMP14R + B) #отправляем публичный ключ клиенту
        logging.info("Ключ отправлен.")

        return DHModpAESGCMCodec.derive_as_server(y, client_pub, B)

    raise ValueError("Unknown algorithm")