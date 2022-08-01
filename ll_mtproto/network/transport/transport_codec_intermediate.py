import asyncio
import struct

from .transport_codec_base import TransportCodecBase
from .transport_codec_factory import TransportCodecFactory

__all__ = ("TransportCodecIntermediate",)


class TransportCodecIntermediate(TransportCodecBase, TransportCodecFactory):
    def new_codec(self) -> TransportCodecBase:
        return self

    async def read_packet(self, reader: asyncio.StreamReader) -> bytes:
        packet_data_length = struct.unpack("<i", await reader.readexactly(4))
        return await reader.readexactly(*packet_data_length)

    async def write_packet(self, writer: asyncio.StreamWriter, data: bytes):
        writer.write(struct.pack("<i", len(data)))
        writer.write(data)

    async def write_header(self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader):
        writer.write(b"\xee" * 4)
