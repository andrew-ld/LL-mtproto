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
import struct

from ll_mtproto.network.transport.transport_codec_base import TransportCodecBase
from ll_mtproto.network.transport.transport_codec_factory import TransportCodecFactory

__all__ = ("TransportCodecIntermediate", "TransportCodecIntermediateFactory")


class TransportCodecIntermediate(TransportCodecBase):
    __slots__ = ("_must_write_transport_type",)

    _must_write_transport_type: bool

    def __init__(self) -> None:
        self._must_write_transport_type = True

    async def read_packet(self, reader: asyncio.StreamReader) -> bytes:
        packet_data_length = struct.unpack("<i", await reader.readexactly(4))
        return await reader.readexactly(*packet_data_length)

    async def write_packet(self, writer: asyncio.StreamWriter, data: bytes | bytearray) -> None:
        packet_header = bytearray()

        if self._must_write_transport_type:
            packet_header += b"\xee" * 4
            self._must_write_transport_type = False

        packet_header += struct.pack("<i", len(data))

        writer.write(packet_header + data)


class TransportCodecIntermediateFactory(TransportCodecFactory):
    def new_codec(self) -> TransportCodecBase:
        return TransportCodecIntermediate()
