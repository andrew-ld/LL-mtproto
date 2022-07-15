import asyncio

__all__ = ("AbridgedTCP",)


class AbridgedTCP:
    __slots__ = ("_loop", "_host", "_port", "_connect_lock", "_reader", "_writer", "_write_lock", "_read_buffer")

    _loop: asyncio.AbstractEventLoop
    _host: str
    _port: int
    _connect_lock: asyncio.Lock
    _reader: asyncio.StreamReader | None
    _writer: asyncio.StreamWriter | None
    _write_lock: asyncio.Lock
    _read_buffer: bytearray

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
                writer.write(b"\xef")

            return reader, writer

    async def _write_abridged_packet(self, data: bytes):
        reader, writer = await self._reconnect_if_needed()

        packet_data_length = len(data) >> 2

        if packet_data_length < 0x7F:
            writer.write(packet_data_length.to_bytes(1, "little"))

        elif packet_data_length <= 0x7FFFFF:
            writer.write(b"\x7f")
            writer.write(packet_data_length.to_bytes(3, "little"))

        else:
            raise OverflowError("Packet data is too long")

        writer.write(data)

    async def _read_abridged_packet(self) -> bytes:
        reader, writer = await self._reconnect_if_needed()

        packet_data_length = ord(await reader.readexactly(1))

        if packet_data_length > 0x7F:
            raise NotImplementedError(f"Wrong packet data length {packet_data_length:d}")

        if packet_data_length == 0x7F:
            packet_data_length = int.from_bytes(await reader.readexactly(3), "little", signed=False)

        return await reader.readexactly(packet_data_length * 4)

    async def read(self) -> bytes:
        if self._read_buffer:
            result = bytes(self._read_buffer)
            self._read_buffer.clear()
        else:
            result = await self._read_abridged_packet()

        return result

    async def readn(self, n: int) -> bytes:
        while len(self._read_buffer) < n:
            self._read_buffer += await self._read_abridged_packet()

        result = self._read_buffer[:n]
        del self._read_buffer[:n]
        return bytes(result)

    async def write(self, data: bytes):
        data = bytearray(data)

        async with self._write_lock:
            while (data_len := len(data)) > 0:
                chunk_len = min(data_len, 0x7FFFFF)
                chunk_mem = data[:chunk_len]
                del data[:chunk_len]
                await self._write_abridged_packet(chunk_mem)

    def stop(self):
        if writer := self._writer:
            writer.close()

        self._writer = None
        self._reader = None
        self._read_buffer.clear()
