# chat/server.py
import asyncio
import logging
from typing import Dict, Tuple
from common import read_message, write_message, close_writer
from crypto.negotiation import server_negotiate

BROADCAST_TIMEOUT = 1.0

class ChatServer:
    def __init__(self) -> None:
        self.clients: Dict[asyncio.StreamWriter, Tuple[str, object]] = {}
        self._server: asyncio.Server | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 1234) -> asyncio.Server:
        self._server = await asyncio.start_server(self._handle_client, host, port)
        return self._server

    async def _broadcast(self, plaintext: bytes) -> None:
        """Функция рассылки сообщений всем клиентам.

        В параметрах функции plaintext - сообщение, которое нужно отправить всем клиентам
        """
        targets = [(w, self.clients[w][1]) for w in list(self.clients.keys())]
        async def send_one(w, codec):
            try:
                await asyncio.wait_for(write_message(w, plaintext, codec), timeout=BROADCAST_TIMEOUT)
                return True
            except Exception:
                return False
        results = await asyncio.gather(*(send_one(w, c) for w, c in targets)) # распараллеливаем отправку сообщений
        for (w, _), ok in zip(targets, results):
            if not ok: #если кому-то отправка не удалась, то отключаем его
                self.clients.pop(w, None)
                await close_writer(w)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Функция обработки подключения клиента. Функция передается в asyncio.start_server в качестве callback метода. 

        В параметрах функции reader - объект для чтения данных из сокета, writer - объект для записи данных в сокет
        """

        try:
            codec = await server_negotiate(reader, writer)
        except Exception:
            await close_writer(writer)
            return

        try:
            username = (await read_message(reader, codec)).decode("utf-8")
        except Exception:
            await close_writer(writer)
            return

        self.clients[writer] = (username, codec)
        try:
            while True:
                msg = await read_message(reader, codec)
                logging.info("Получено сообщение от %s: %s", username, msg.decode("utf-8"))
                out = f"{username} > {msg.decode('utf-8')}".encode("utf-8")
                await self._broadcast(out)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            logging.error("ОШИБКА: Потеряно соединение с клиентом %s", username)
            pass
        except Exception:
            logging.exception("Произошла ошибка в обработке клиента %s. ", username)
            pass
        finally:
            self.clients.pop(writer, None)
            logging.info("Клиент %s отключился", username)
            await close_writer(writer)

async def amain() -> None:
    server = ChatServer()
    srv = await server.start("127.0.0.1", 1234)
    async with srv:
        await srv.serve_forever()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(amain())