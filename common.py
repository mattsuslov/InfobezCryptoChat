# chat/common.py
import asyncio
from crypto.base import AsyncCodec

HEADER_LENGTH = 10

async def read_framed(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(HEADER_LENGTH)
    size = int(header.decode("utf-8").strip())
    if size < 0:
        raise ValueError("Invalid frame size")
    return await reader.readexactly(size)

async def write_framed(writer: asyncio.StreamWriter, data: bytes) -> None:
    header = f"{len(data):<{HEADER_LENGTH}}".encode("utf-8")
    writer.write(header + data)
    await writer.drain() # flush

async def read_message(reader: asyncio.StreamReader, codec: AsyncCodec|None=None) -> bytes:
    data = await read_framed(reader)
    if codec is None:
        return data
    return await codec.decode(data)

async def write_message(writer: asyncio.StreamWriter, data: bytes, codec: AsyncCodec|None=None) -> None:
    if codec is not None:
        data = await codec.encode(data)
    await write_framed(writer, data)

async def close_writer(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass