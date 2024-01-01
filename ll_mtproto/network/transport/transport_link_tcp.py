# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2023 (andrew) https://github.com/andrew-ld/LL-mtproto

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
import _socket
import ipaddress
import socket

from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.network.transport.transport_address_resolver_base import TransportAddressResolverBase
from ll_mtproto.network.transport.transport_codec_base import TransportCodecBase
from ll_mtproto.network.transport.transport_codec_factory import TransportCodecFactory
from ll_mtproto.network.transport.transport_link_base import TransportLinkBase
from ll_mtproto.network.transport.transport_link_factory import TransportLinkFactory

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
        "_transport_codec",
        "_resolver"
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
    _resolver: TransportAddressResolverBase

    def __init__(
            self,
            datacenter: DatacenterInfo,
            transport_codec_factory: TransportCodecFactory,
            resolver: TransportAddressResolverBase
    ):
        self._loop = asyncio.get_running_loop()

        self._datacenter = datacenter
        self._transport_codec_factory = transport_codec_factory
        self._resolver = resolver

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
                self._read_buffer.clear()

                if writer is not None:
                   writer.close()

                address, port = await self._resolver.get_address(self._datacenter)

                match address_version := ipaddress.ip_address(address):
                    case ipaddress.IPv4Address():
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                    case ipaddress.IPv6Address():
                        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

                    case _:
                        raise TypeError(f"Invalid IP address: `{address_version!r}` `{address!r}`")

                if hasattr(_socket, "SO_REUSEADDR"):
                    sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)

                if hasattr(_socket, "SO_KEEPALIVE"):
                    sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_KEEPALIVE, 1)

                if hasattr(_socket, "SO_NOSIGPIPE"):
                    sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_NOSIGPIPE, 1)

                if hasattr(_socket, "TCP_NODELAY"):
                    sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)

                sock.setblocking(False)

                await asyncio.get_running_loop().sock_connect(sock, (address, port))

                reader, writer = await asyncio.open_connection(sock=sock)
                transport_codec = self._transport_codec_factory.new_codec()

                self._reader, self._writer, self._transport_codec = reader, writer, transport_codec

            return reader, writer, transport_codec

    async def read(self) -> bytes:
        if self._read_buffer:
            result = bytes(self._read_buffer)
            self._read_buffer.clear()
        else:
            reader, _, codec = await self._reconnect_if_needed()
            result = await codec.read_packet(reader)

        return result

    def discard_packet(self) -> None:
        self._read_buffer.clear()

    async def readn(self, n: int) -> bytes:
        reader, _, codec = await self._reconnect_if_needed()

        while len(self._read_buffer) < n:
            self._read_buffer += bytearray(await codec.read_packet(reader))

        result = self._read_buffer[:n]
        del self._read_buffer[:n]
        return bytes(result)

    async def write(self, data: bytes) -> None:
        data = bytearray(data)

        _, writer, codec = await self._reconnect_if_needed()

        async with self._write_lock:
            while (writable_len := min(len(data), 0x7FFFFF)) > 0:
                await codec.write_packet(writer, data[:writable_len])
                del data[:writable_len]

    def stop(self) -> None:
        if writer := self._writer:
            writer.close()

        self._writer = None
        self._reader = None
        self._transport_codec = None

        self._read_buffer.clear()


class TransportLinkTcpFactory(TransportLinkFactory):
    __slots__ = ("_transport_codec_factory", "_resolver")

    _transport_codec_factory: TransportCodecFactory
    _resolver: TransportAddressResolverBase

    def __init__(self, transport_codec_factory: TransportCodecFactory, resolver: TransportAddressResolverBase):
        self._transport_codec_factory = transport_codec_factory
        self._resolver = resolver

    def new_transport_link(self, datacenter: DatacenterInfo) -> TransportLinkBase:
        return TransportLinkTcp(datacenter, self._transport_codec_factory, self._resolver)
