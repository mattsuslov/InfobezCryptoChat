# tests/test_chat.py
import asyncio
import pytest

from server import ChatServer
from client import AsyncChatClient

pytestmark = pytest.mark.asyncio

async def start_server():
    srv = ChatServer()
    server_obj = await srv.start("127.0.0.1", 0)
    host, port = server_obj.sockets[0].getsockname()[:2]
    return srv, server_obj, host, port

@pytest.fixture
async def running_server():
    srv, server_obj, host, port = await start_server()
    yield srv, host, port
    server_obj.close()
    await server_obj.wait_closed()

@pytest.mark.parametrize("alg", ["plain", "dh"])
async def test_broadcast_to_multiple_clients(running_server, alg):
    _, host, port = running_server
    c1, c2, c3 = AsyncChatClient(), AsyncChatClient(), AsyncChatClient()
    await c1.connect(host, port, "alice", alg=alg)
    await c2.connect(host, port, "bob", alg=alg)
    await c3.connect(host, port, "carol", alg=alg)

    await c1.send("hello")

    m2 = await c2.recv(timeout=2.0)
    m3 = await c3.recv(timeout=2.0)

    assert m2 == "alice > hello"
    assert m3 == "alice > hello"

    with pytest.raises(asyncio.TimeoutError):
        await c1.recv(timeout=0.3)

    await c1.close()
    await c2.close()
    await c3.close()

@pytest.mark.parametrize("alg", ["plain", "dh"])
async def test_client_disconnect_does_not_break_broadcast(running_server, alg):
    _, host, port = running_server
    c1, c2, c3 = AsyncChatClient(), AsyncChatClient(), AsyncChatClient()
    await c1.connect(host, port, "alice", alg=alg)
    await c2.connect(host, port, "bob", alg=alg)
    await c3.connect(host, port, "carol", alg=alg)

    await c2.close()
    await asyncio.sleep(0.1)

    await c1.send("hi all")
    m3 = await c3.recv(timeout=2.0)
    assert m3 == "alice > hi all"

    await c1.close()
    await c3.close()

@pytest.mark.parametrize("alg", ["plain", "dh"])
async def test_unicode_messages(running_server, alg):
    _, host, port = running_server
    c1, c2 = AsyncChatClient(), AsyncChatClient()
    await c1.connect(host, port, "алиса", alg=alg)
    await c2.connect(host, port, "борис", alg=alg)

    txt = "Привет, мир 🌍"
    await c1.send(txt)
    m2 = await c2.recv(timeout=2.0)
    assert m2 == f"алиса > {txt}"

    await c1.close()
    await c2.close()