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


import functools
import hashlib
import typing
import zlib

from ll_mtproto.in_thread import InThread
from ll_mtproto.tl.bytereader import SyncByteReader, ByteConsumer, ByteReader

__all__ = (
    "xor",
    "sha1",
    "sha256",
    "to_bytes",
    "ByteReaderApply",
    "short_hex",
    "GzipStreamReader",
    "SyncByteReaderProxy",
    "BinaryStreamReader",
)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(ca ^ cb for ca, cb in zip(a, b))


@functools.lru_cache()
def sha1(b: bytes) -> bytes:
    return bytes(hashlib.sha1(b).digest())


@functools.lru_cache()
def sha256(b: bytes) -> bytes:
    return bytes(hashlib.sha256(b).digest())


@functools.lru_cache()
def to_bytes(x: int, byte_order: typing.Literal["big", "little"] = "big", signed: bool = False) -> bytes:
    return x.to_bytes(((x.bit_length() - 1) // 8) + 1, byte_order, signed=signed)


class GzipStreamReader(SyncByteReader):
    __slots__ = ("_parent", "_buffer", "_decompressor")

    _parent: SyncByteReader
    _buffer: bytearray

    # _decompressor: zlib.Decompress

    def __init__(self, parent: SyncByteReader):
        self._parent = parent
        self._buffer = bytearray()
        self._decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)

    def __bool__(self) -> bool:
        return bool(self._buffer) or bool(self._parent)

    def __call__(self, nbytes: int) -> bytes:
        if nbytes == -1:
            buffer = self._buffer[:]
            del self._buffer[:]
            return bytes(buffer + bytearray(self._decompressor.decompress(self._parent(-1))))

        while len(self._buffer) < nbytes:
            self._buffer += bytearray(self._decompressor.decompress(self._parent(4096)))

        result = self._buffer[:nbytes]
        del self._buffer[:nbytes]
        return bytes(result)


class ByteReaderApply:
    __slots__ = ("_parent", "_apply_function", "_in_thread")

    _parent: ByteReader
    _apply_function: ByteConsumer
    _in_thread: InThread

    def __init__(self, parent: ByteReader, apply_function: ByteConsumer, in_thread: InThread):
        self._parent = parent
        self._apply_function = apply_function
        self._in_thread = in_thread

    async def __call__(self, nbytes: int) -> bytes:
        result = await self._parent(nbytes)
        await self._in_thread(lambda: self._apply_function(result))
        return result


class SyncByteReaderProxy(SyncByteReader):
    __slots__ = ("_parent", "_apply_function")

    _parent: SyncByteReader
    _apply_function: ByteConsumer

    def __init__(self, parent: SyncByteReader, proxy_function: ByteConsumer):
        self._parent = parent
        self._apply_function = proxy_function

    def __bool__(self) -> bool:
        return bool(self._parent)

    def __call__(self, nbytes: int) -> bytes:
        result = self._parent(nbytes)
        self._apply_function(result)
        return result


class BinaryStreamReader(SyncByteReader):
    __slots__ = ("_parent", "_remaining", "_padding")

    _parent: SyncByteReader
    _remaining: int
    _padding: int

    def __init__(self, parent: SyncByteReader, remaining: int, padding: int):
        self._parent = parent
        self._remaining = remaining
        self._padding = padding

    def __bool__(self) -> bool:
        return self._remaining != 0

    def __call__(self, nbytes: int) -> bytes:
        if nbytes == -1:
            nbytes = self._remaining

        if nbytes >= (remaining := self._remaining):
            result = self._parent(remaining)

            if remaining > 0:
                self._parent(self._padding)
                self._remaining = 0

            return result
        else:
            self._remaining -= nbytes
            return self._parent(nbytes)


@functools.lru_cache()
def short_hex(data: bytes) -> str:
    return ":".join("%02X" % b for b in data)
