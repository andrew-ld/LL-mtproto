import asyncio
from . import TransportCodecBase, TransportCodecFactory

__all__ = ("TCP",)


class TCP:
    __slots__ = (
        "_loop",
        "_host",
        "_port",
        "_connect_lock",
        "_reader",
        "_writer",
        "_write_lock",
        "_read_buffer",
        "_codec_factory",
        "_codec"
    )

    _loop: asyncio.AbstractEventLoop
    _host: str
    _port: int
    _connect_lock: asyncio.Lock
    _reader: asyncio.StreamReader | None
    _writer: asyncio.StreamWriter | None
    _write_lock: asyncio.Lock
    _read_buffer: bytearray
    _codec_factory: TransportCodecFactory | None
    _codec: TransportCodecBase | None

    def __init__(self, host: str, port: int, codec_factory: TransportCodecFactory):
        self._loop = asyncio.get_event_loop()
        self._host = host
        self._port = port
        self._connect_lock = asyncio.Lock()
        self._reader = None
        self._writer = None
        self._write_lock = asyncio.Lock()
        self._read_buffer = bytearray()
        self._codec_factory = codec_factory
        self._codec = None

    async def _reconnect_if_needed(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, TransportCodecBase]:
        async with self._connect_lock:
            reader, writer, codec = self._reader, self._writer, self._codec

            if reader is None or writer is None or codec is None:
                reader, writer = await asyncio.open_connection(self._host, self._port)
                codec = self._codec_factory.new_codec()
                self._reader, self._writer, self._codec = reader, writer, codec
                await codec.write_header(writer, reader)

            return reader, writer, codec

    async def read(self) -> bytes:
        if self._read_buffer:
            result = bytes(self._read_buffer)
            self._read_buffer.clear()
        else:
            reader, _, codec = await self._reconnect_if_needed()
            result = await codec.read_packet(reader)

        return result

    async def readn(self, n: int) -> bytes:
        reader, _, codec = await self._reconnect_if_needed()

        while len(self._read_buffer) < n:
            self._read_buffer += await codec.read_packet(reader)

        result = self._read_buffer[:n]
        del self._read_buffer[:n]
        return bytes(result)

    async def write(self, data: bytes):
        data = bytearray(data)

        _, writer, codec = await self._reconnect_if_needed()

        async with self._write_lock:
            while (data_len := len(data)) > 0:
                chunk_len = min(data_len, 0x7FFFFF)
                chunk_mem = data[:chunk_len]
                del data[:chunk_len]
                await codec.write_packet(writer, chunk_mem)

    def stop(self):
        if writer := self._writer:
            writer.close()

        self._writer = None
        self._reader = None
        self._read_buffer.clear()
