import asyncio
import struct

from . import TransportCodecBase
from . import TransportCodecFactory

__all__ = ("TransportCodecIntermediate",)


class TransportCodecIntermediate(TransportCodecBase, TransportCodecFactory):
    __slots__ = ("_must_write_transport_type",)

    _must_write_transport_type: bool

    def __init__(self):
        self._must_write_transport_type = True

    def new_codec(self) -> TransportCodecBase:
        return TransportCodecIntermediate()

    async def read_packet(self, reader: asyncio.StreamReader) -> bytes:
        packet_data_length = struct.unpack("<i", await reader.readexactly(4))
        return await reader.readexactly(*packet_data_length)

    async def write_packet(self, writer: asyncio.StreamWriter, data: bytes):
        packet_header = bytearray()

        if self._must_write_transport_type:
            packet_header += b"\xee" * 4
            self._must_write_transport_type = False

        packet_header += struct.pack("<i", len(data))

        writer.write(packet_header + data)
