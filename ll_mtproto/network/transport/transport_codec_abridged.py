import asyncio

from . import TransportCodecBase
from . import TransportCodecFactory

__all__ = ("TransportCodecAbridgedFactory", "TransportCodecAbridged")


class TransportCodecAbridged(TransportCodecBase):
    __slots__ = ("_must_write_transport_type",)

    _must_write_transport_type: bool

    def __init__(self):
        self._must_write_transport_type = True

    async def read_packet(self, reader: asyncio.StreamReader) -> bytes:
        packet_data_length = ord(await reader.readexactly(1))

        if packet_data_length > 0x7F:
            raise NotImplementedError(f"Wrong packet data length {packet_data_length:d}")

        if packet_data_length == 0x7F:
            packet_data_length = int.from_bytes(await reader.readexactly(3), "little", signed=False)

        return await reader.readexactly(packet_data_length * 4)

    async def write_packet(self, writer: asyncio.StreamWriter, data: bytes):
        packet_header = bytearray()

        if self._must_write_transport_type:
            packet_header += b"\xef"
            self._must_write_transport_type = False

        packet_data_length = len(data) >> 2

        if packet_data_length < 0x7F:
            packet_header += packet_data_length.to_bytes(1, "little")

        elif packet_data_length <= 0x7FFFFF:
            packet_header += b"\x7f"
            packet_header += packet_data_length.to_bytes(3, "little")

        else:
            raise OverflowError("Packet data is too long")

        writer.write(packet_header + data)


class TransportCodecAbridgedFactory(TransportCodecFactory):
    def new_codec(self) -> TransportCodecBase:
        return TransportCodecAbridgedFactory()
