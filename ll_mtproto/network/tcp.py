import asyncio
from asyncio import Lock, open_connection


class AbridgedTCP:
    _loop: asyncio.AbstractEventLoop
    _host: str
    _port: int
    _connect_lock: asyncio.Lock
    _buffer: bytes
    _reader: asyncio.StreamReader | None
    _writer: asyncio.StreamWriter | None
    _write_lock: asyncio.Lock

    def __init__(self, host: str, port: int):
        self._loop = asyncio.get_event_loop()
        self._host = host
        self._port = port
        self._connect_lock = Lock()
        self._buffer = b""
        self._reader = None
        self._writer = None
        self._write_lock = Lock()

    async def _reconnect_if_needed(self):
        async with self._connect_lock:
            if self._reader is None or self._writer is None:
                self._reader, self._writer = await open_connection(self._host, self._port, limit=2 ** 24)
                self._writer.write(b"\xef")

    async def _write_abridged_packet(self, data: bytes):
        await self._reconnect_if_needed()
        packet_data_length = len(data) >> 2

        if packet_data_length < 0x7F:
            self._writer.write(packet_data_length.to_bytes(1, "little"))

        elif packet_data_length <= 0x7FFFFF:
            self._writer.write(b"\x7f")
            self._writer.write(packet_data_length.to_bytes(3, "little"))

        else:
            raise OverflowError("Packet data is too long")

        self._writer.write(data)

    async def _read_abridged_packet(self) -> bytes:
        await self._reconnect_if_needed()
        packet_data_length = ord(await self._reader.readexactly(1))

        if packet_data_length > 0x7F:
            raise NotImplementedError(f"Wrong packet data length {packet_data_length:d}")

        if packet_data_length == 0x7F:
            packet_data_length = int.from_bytes(await self._reader.readexactly(3), "little", signed=False)

        return await self._reader.readexactly(packet_data_length * 4)

    def clear_buffer(self):
        self._buffer = b""

    async def read(self, nbytes: int) -> bytes:
        while len(self._buffer) < nbytes:
            self._buffer += await self._read_abridged_packet()

        result = self._buffer[:nbytes]
        self._buffer = self._buffer[nbytes:]
        return result

    async def write(self, data: bytes):
        async with self._write_lock:
            while len(data) > 0:
                chunk_len = min(len(data), 0x7FFFFF)
                await self._write_abridged_packet(data[:chunk_len])
                data = data[chunk_len:]

    async def stop(self):
        pass
