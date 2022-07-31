import asyncio
import struct

__all__ = ("IntermediateTCP",)


class IntermediateTCP:
    __slots__ = ("_loop", "_host", "_port", "_connect_lock", "_reader", "_writer", "_write_lock", "_read_buffer")

    _loop: asyncio.AbstractEventLoop
    _host: str
    _port: int
    _connect_lock: asyncio.Lock
    _reader: asyncio.StreamReader | None
    _writer: asyncio.StreamWriter | None
    _write_lock: asyncio.Lock
    _read_buffer: bytearray

    @staticmethod
    async def _write_packet(data: bytes, writer: asyncio.StreamWriter):
        writer.write(struct.pack("<i", len(data)))
        writer.write(data)

    @staticmethod
    async def _read_packet(reader: asyncio.StreamReader) -> bytes:
        packet_data_length = struct.unpack("<i", await reader.readexactly(4))
        return await reader.readexactly(*packet_data_length)

    def __init__(self, host: str, port: int):
        self._loop = asyncio.get_event_loop()
        self._host = host
        self._port = port
        self._connect_lock = asyncio.Lock()
        self._reader = None
        self._writer = None
        self._write_lock = asyncio.Lock()
        self._read_buffer = bytearray()

    async def _reconnect_if_needed(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        async with self._connect_lock:
            reader, writer = self._reader, self._writer

            if reader is None or writer is None:
                reader, writer = await asyncio.open_connection(self._host, self._port)
                self._reader, self._writer = reader, writer
                writer.write(b"\xee" * 4)

            return reader, writer

    async def read(self) -> bytes:
        if self._read_buffer:
            result = bytes(self._read_buffer)
            self._read_buffer.clear()
        else:
            reader, _ = await self._reconnect_if_needed()
            result = await self._read_packet(reader)

        return result

    async def readn(self, n: int) -> bytes:
        reader, _ = await self._reconnect_if_needed()

        while len(self._read_buffer) < n:
            self._read_buffer += await self._read_packet(reader)

        result = self._read_buffer[:n]
        del self._read_buffer[:n]
        return bytes(result)

    async def write(self, data: bytes):
        data = bytearray(data)

        _, writer = await self._reconnect_if_needed()

        async with self._write_lock:
            while (data_len := len(data)) > 0:
                chunk_len = min(data_len, 0x7FFFFF)
                chunk_mem = data[:chunk_len]
                del data[:chunk_len]
                await self._write_packet(chunk_mem, writer)

    def stop(self):
        if writer := self._writer:
            writer.close()

        self._writer = None
        self._reader = None
        self._read_buffer.clear()
