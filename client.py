import asyncio
from common import read_message, write_message, close_writer
from crypto.negotiation import client_negotiate
import logging

class AsyncChatClient:
    def __init__(self) -> None:
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.codec = None

    async def connect(self, host: str, port: int, username: str, alg: str = "plain") -> None:
        self.reader, self.writer = await asyncio.open_connection(host, port)
        self.codec = await client_negotiate(self.reader, self.writer, alg=alg) #Клиент получает кодек от сервера
        await write_message(self.writer, username.encode("utf-8"), self.codec)

    async def send(self, message: str) -> None:
        if not self.writer:
            raise RuntimeError("Not connected")
        await write_message(self.writer, message.encode("utf-8"), self.codec)

    async def recv(self, timeout: float | None = None) -> str:
        if not self.reader:
            raise RuntimeError("Not connected")
        if timeout is None:
            data = await read_message(self.reader, self.codec)
        else:
            data = await asyncio.wait_for(read_message(self.reader, self.codec), timeout=timeout)
        return '\n' + data.decode("utf-8")

    async def close(self) -> None:
        if self.writer:
            await close_writer(self.writer)
            self.writer = None
            self.reader = None
            self.codec = None

async def run_cli(host: str = "127.0.0.1", port: int = 1234, username: str = "user", alg: str = "plain") -> None:
    client = AsyncChatClient() 
    await client.connect(host, port, username, alg=alg) #тут идет handshake при вызове connect

    async def reader_task():
        try:
            while True:
                print(await client.recv(), flush=True) #читаем если что-то есть
        except Exception:
            pass

    async def writer_task():
        loop = asyncio.get_running_loop()
        try:
            while True:
                line = await loop.run_in_executor(None, input, f"{username} > ") #ждем пока что-то напишет человек
                if line is None:
                    break
                if line.strip() == "":
                    continue
                await client.send(line)
        except Exception:
            pass

    t1 = asyncio.create_task(reader_task())
    t2 = asyncio.create_task(writer_task())
    done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_EXCEPTION)
    for t in pending:
        t.cancel()
    await client.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    username = input("Enter your Username: ")
    asyncio.run(run_cli(username=username, alg="dh_modp"))