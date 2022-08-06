import asyncio

from . import TransportCodecBase, TransportLinkBase, TransportLinkFactory, TransportCodecFactory
from .. import DatacenterInfo

__all__ = ("TransportLinkTcp", "TransportLinkTcpFactory")


class TransportLinkTcp(TransportLinkBase):
    __slots__ = (
        "_loop",
        "_datacenter",
        "_connect_lock",
        "_reader",
        "_writer",
        "_write_lock",
        "_read_buffer",
        "_transport_codec_factory",
        "_transport_codec"
    )

    _loop: asyncio.AbstractEventLoop
    _datacenter: DatacenterInfo
    _connect_lock: asyncio.Lock
    _reader: asyncio.StreamReader | None
    _writer: asyncio.StreamWriter | None
    _write_lock: asyncio.Lock
    _read_buffer: bytearray
    _transport_codec: TransportCodecBase | None
    _transport_codec_factory: TransportCodecFactory

    def __init__(self, datacenter: DatacenterInfo, transport_codec_factory: TransportCodecFactory):
        self._loop = asyncio.get_event_loop()

        self._datacenter = datacenter
        self._transport_codec_factory = transport_codec_factory

        self._connect_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

        self._read_buffer = bytearray()

        self._reader = None
        self._writer = None
        self._transport_codec = None

    async def _reconnect_if_needed(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, TransportCodecBase]:
        async with self._connect_lock:
            reader, writer, transport_codec = self._reader, self._writer, self._transport_codec

            if reader is None or writer is None or transport_codec is None:
                reader, writer = await asyncio.open_connection(self._datacenter.address, self._datacenter.port)
                transport_codec = self._transport_codec_factory.new_codec()
                self._reader, self._writer, self._transport_codec = reader, writer, transport_codec
                await transport_codec.write_header(writer, reader)

            return reader, writer, transport_codec

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
        self._transport_codec = None

        self._read_buffer.clear()


class TransportLinkTcpFactory(TransportLinkFactory):
    __slots__ = ("_transport_codec_factory",)

    _transport_codec_factory: TransportCodecFactory

    def __init__(self, transport_codec_factory: TransportCodecFactory):
        self._transport_codec_factory = transport_codec_factory

    def new_transport_link(self, datacenter: DatacenterInfo) -> TransportLinkBase:
        return TransportLinkTcp(datacenter, self._transport_codec_factory)
