import asyncio

from . import TransportCodecBase
from . import TransportCodecFactory

__all__ = ("TransportCodecAbridged",)


class TransportCodecAbridged(TransportCodecBase, TransportCodecFactory):
    def new_codec(self) -> TransportCodecBase:
        return self

    async def read_packet(self, reader: asyncio.StreamReader) -> bytes:
        packet_data_length = ord(await reader.readexactly(1))

        if packet_data_length > 0x7F:
            raise NotImplementedError(f"Wrong packet data length {packet_data_length:d}")

        if packet_data_length == 0x7F:
            packet_data_length = int.from_bytes(await reader.readexactly(3), "little", signed=False)

        return await reader.readexactly(packet_data_length * 4)

    async def write_packet(self, writer: asyncio.StreamWriter, data: bytes):
        packet_data_length = len(data) >> 2

        if packet_data_length < 0x7F:
            writer.write(packet_data_length.to_bytes(1, "little"))

        elif packet_data_length <= 0x7FFFFF:
            writer.write(b"\x7f")
            writer.write(packet_data_length.to_bytes(3, "little"))

        else:
            raise OverflowError("Packet data is too long")

        writer.write(data)

    async def write_header(self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader):
        writer.write(b"\xef")

