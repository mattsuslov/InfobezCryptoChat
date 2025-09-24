# chat/e2e_client.py
import asyncio
from typing import Iterable, Optional, Tuple
import logging

from client import AsyncChatClient
from e2e_mobp import E2EModpManager

def _split_sender(line: str) -> Tuple[Optional[str], str]:
    # формат с сервера: "username > message"
    sep = " > "
    i = line.find(sep)
    if i == -1:
        return None, line
    return line[:i].strip(), line[i + len(sep):].strip()

class E2EChatClient:
    def __init__(self) -> None:
        self.base = AsyncChatClient()
        self.username: Optional[str] = None
        self.e2e: Optional[E2EModpManager] = None

    async def connect(self, host: str, port: int, username: str, alg: str = "plain") -> None:
        await self.base.connect(host, port, username, alg=alg)
        self.username = username
        self.e2e = E2EModpManager(self.base, username)
        await self.e2e.announce()

    async def send_plain(self, text: str) -> None:
        await self.base.send(text)

    async def send_private(self, to_user: str, text: str) -> None:
        if not self.e2e:
            raise RuntimeError("E2E not initialized")
        await self.e2e.send_private(text, recipients=[to_user])

    async def send_private_group(self, recipients: Iterable[str], text: str) -> None:
        if not self.e2e:
            raise RuntimeError("E2E not initialized")
        await self.e2e.send_private(text, recipients=recipients)

    async def reannounce(self) -> None:
        if not self.e2e:
            raise RuntimeError("E2E not initialized")
        await self.e2e.announce()

    async def recv(self, timeout: float | None = None) -> str:
        # Пропускаем служебные E2E сообщения и возвращаем только отображаемые
        while True:
            line = await (self.base.recv() if timeout is None else asyncio.wait_for(self.base.recv(), timeout=timeout))
            sender, payload = _split_sender(line)
            if sender is None or not self.e2e:
                return line
            handled, plaintext = await self.e2e.handle_incoming(sender, payload)
            if not handled:
                return line
            if plaintext is not None:
                return f"{sender} [E2E] > {plaintext}"
            # handled == True и plaintext == None -> это служебное E2E сообщение; читаем дальше

    async def close(self) -> None:
        await self.base.close()
        self.e2e = None
        self.username = None


async def run_e2e_cli(host: str = "127.0.0.1", port: int = 1234, username: str = "user", alg: str = "plain") -> None:
    c = E2EChatClient()
    await c.connect(host, port, username, alg=alg)

    async def reader_task():
        try:
            while True:
                print(await c.recv(), flush=True)
        except Exception:
            pass

    async def writer_task():
        loop = asyncio.get_running_loop()
        try:
            while True:
                line = await loop.run_in_executor(None, input, f"{username} (e2e) > ")
                if line is None:
                    break
                if not line.strip():
                    continue
                if line.startswith("/personal "):
                    try:
                        _, rest = line.split(" ", 1)
                        to, msg = rest.split(" ", 1)
                        await c.send_private(to, msg)
                    except ValueError:
                        print("Usage: /personal <user> <message>")
                    continue
                if line.startswith("/group "):
                    try:
                        _, rest = line.split(" ", 1)
                        tolist, msg = rest.split(" ", 1)
                        recips = [t.strip() for t in tolist.split(",") if t.strip()]
                        await c.send_private_group(recips, msg)
                    except ValueError:
                        print("Usage: /group <user1,user2,...> <message>")
                    continue
                if line.startswith("/all "):
                    try:
                        _, msg = line.split(" ", 1)
                        recips = c.e2e.get_users()
                        await c.send_private_group(recips, msg)
                    except ValueError:
                        print("Usage: /all <message>")
                    continue
                if line.strip() == "/announce":
                    await c.reannounce()
                    continue
                if line.strip() == "/users":
                    known_users = c.e2e.get_users()
                    print(f"Known users: {known_users}")
                    continue
                await c.send_plain(line)
        except Exception:
            logging.error("", exc_info=True)
            pass

    t1 = asyncio.create_task(reader_task())
    t2 = asyncio.create_task(writer_task())
    done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_EXCEPTION)
    for t in pending:
        t.cancel()
    await c.close()

if __name__ == "__main__":
    asyncio.run(run_e2e_cli(username=input("Username: ")))