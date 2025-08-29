# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2025 (andrew) https://github.com/andrew-ld/LL-mtproto
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import asyncio

from ll_mtproto.network.transport.transport_codec_base import TransportCodecBase
from ll_mtproto.network.transport.transport_codec_factory import TransportCodecFactory
from ll_mtproto.network.transport_error import TransportError

__all__ = ("TransportCodecAbridgedFactory", "TransportCodecAbridged")


class TransportCodecAbridged(TransportCodecBase):
    __slots__ = ("_must_write_transport_type",)

    _must_write_transport_type: bool

    def __init__(self) -> None:
        self._must_write_transport_type = True

    async def read_packet(self, reader: asyncio.StreamReader) -> bytes:
        length = ord(await reader.readexactly(1))

        if length > 0x7F:
            raise NotImplementedError(f"Wrong packet data length {length:d}")

        if length == 0x7F:
            length = int.from_bytes(await reader.readexactly(3), "little", signed=False)

        length *= 4
        result = await reader.readexactly(length)

        if length == 4:
            error_code = int.from_bytes(result, "little", signed=True)
            if error_code < 0:
                raise TransportError(error_code)

        return result

    async def write_packet(self, writer: asyncio.StreamWriter, data: bytes | bytearray) -> None:
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
        return TransportCodecAbridged()
