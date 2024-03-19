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


import base64
import functools
import hashlib
import secrets
import typing
import zlib

from ll_mtproto.tl.byteutils_nomypyc import _SyncByteReaderByteUtilsImpl
from ll_mtproto.typed import ByteConsumer, SyncByteReader

__all__ = (
    "xor",
    "base64encode",
    "base64decode",
    "sha1",
    "sha256",
    "to_bytes",
    "pack_binary_string",
    "unpack_binary_string_header",
    "unpack_binary_string_stream",
    "unpack_long_binary_string_stream",
    "unpack_binary_string",
    "pack_long_binary_string",
    "long_hex",
    "short_hex",
    "short_hex_int",
    "reader_is_empty",
    "reader_discard",
    "GzipStreamReader",
    "to_reader",
    "to_composed_reader",
    "SyncByteReaderApply",
    "pack_long_binary_string_padded"
)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(ca ^ cb for ca, cb in zip(a, b))


def base64encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def base64decode(s: str | bytes) -> bytes:
    return base64.b64decode(s)


@functools.lru_cache()
def sha1(b: bytes) -> bytes:
    return bytes(hashlib.sha1(b).digest())


@functools.lru_cache()
def sha256(b: bytes) -> bytes:
    return bytes(hashlib.sha256(b).digest())


@functools.lru_cache()
def to_bytes(x: int, byte_order: typing.Literal["big", "little"] = "big", signed: bool = False) -> bytes:
    return x.to_bytes(((x.bit_length() - 1) // 8) + 1, byte_order, signed=signed)


@functools.lru_cache()
def pack_binary_string(data: bytes) -> bytes:
    length = len(data)

    if length < 254:
        padding = b"\x00" * ((3 - length) % 4)
        return length.to_bytes(1, "little", signed=False) + data + padding

    elif length <= 0xFFFFFF:
        padding = b"\x00" * ((-length) % 4)
        return b"\xfe" + length.to_bytes(3, "little", signed=False) + data + padding

    else:
        raise OverflowError("String too long")


class GzipStreamReader:
    __slots__ = ("_parent", "_buffer", "_decompressor")

    _parent: SyncByteReader
    _buffer: bytearray

    # _decompressor: zlib.Decompress

    def __init__(self, parent: SyncByteReader):
        self._parent = parent
        self._buffer = bytearray()
        self._decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)

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


def to_composed_reader(*buffers: bytes) -> SyncByteReader:
    return to_reader(b"".join(buffers))


def to_reader(buffer: bytes) -> SyncByteReader:
    return typing.cast(SyncByteReader, _SyncByteReaderByteUtilsImpl(buffer))


def reader_is_empty(reader: SyncByteReader) -> bool:
    return typing.cast(_SyncByteReaderByteUtilsImpl, reader).is_empty()


def reader_discard(reader: SyncByteReader) -> None:
    typing.cast(_SyncByteReaderByteUtilsImpl, reader).close()


def unpack_binary_string_header(bytereader: SyncByteReader) -> tuple[int, int]:
    str_len = ord(bytereader(1))

    if str_len > 0xFE:
        raise RuntimeError("Length equal to 255 in string")

    elif str_len == 0xFE:
        str_len = int.from_bytes(bytereader(3), "little", signed=False)
        padding_len = (-str_len) % 4

    else:
        padding_len = (3 - str_len) % 4

    return str_len, padding_len


class SyncByteReaderApply:
    __slots__ = ("_parent", "_apply_function")

    _parent: SyncByteReader
    _apply_function: ByteConsumer

    def __init__(self, parent: SyncByteReader, apply_function: ByteConsumer):
        self._parent = parent
        self._apply_function = apply_function

    def __call__(self, nbytes: int) -> bytes:
        result = self._parent(nbytes)
        self._apply_function(result)
        return result


class BinaryStreamReader:
    __slots__ = ("_parent", "_remaining", "_padding")

    _parent: SyncByteReader
    _remaining: int
    _padding: int

    def __init__(self, parent: SyncByteReader, remaining: int, padding: int):
        self._parent = parent
        self._remaining = remaining
        self._padding = padding

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


def unpack_binary_string_stream(bytereader: SyncByteReader) -> SyncByteReader:
    return BinaryStreamReader(bytereader, *unpack_binary_string_header(bytereader))


def unpack_long_binary_string_stream(bytereader: SyncByteReader) -> SyncByteReader:
    return BinaryStreamReader(bytereader, int.from_bytes(bytereader(4), "little", signed=False), 0)


def unpack_binary_string(bytereader: SyncByteReader) -> bytes:
    str_len, padding_len = unpack_binary_string_header(bytereader)
    string = bytereader(str_len)
    bytereader(padding_len)
    return string


def pack_long_binary_string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "little", signed=False) + data


def pack_long_binary_string_padded(data: bytes) -> bytes:
    padding_len = -len(data) & 15
    padding_len += 16 * (secrets.randbits(64) % 16)
    padding = secrets.token_bytes(padding_len)
    header = (len(data) + len(padding)).to_bytes(4, "little", signed=False)
    return header + data + padding


@functools.lru_cache()
def long_hex(data: bytes, word_size: int = 4, chunk_size: int = 4) -> str:
    length = len(data)

    if length == 0:
        return "Empty data"

    address_octets = 1 + (length.bit_length() - 1) // 4

    _format = "%0{:d}X   {}   %s".format(
        address_octets,
        "  ".join(" ".join("%s" for _ in range(word_size)) for _ in range(chunk_size)),
    )

    output = []

    for chunk in range(0, len(data), word_size * chunk_size):
        ascii_chunk = bytes(
            c if 31 < c < 127 else 46
            for c in data[chunk: chunk + word_size * chunk_size]
        )

        byte_chunk = (
            "%02X" % data[i] if i < length else "  "
            for i in range(chunk, chunk + word_size * chunk_size)
        )

        output.append(_format % (chunk, *byte_chunk, ascii_chunk.decode("ascii")))

    return "\n".join(output)


@functools.lru_cache()
def short_hex(data: bytes) -> str:
    return ":".join("%02X" % b for b in data)


@functools.lru_cache()
def short_hex_int(x: int, byte_order: typing.Literal["big", "little"] = "big", signed: bool = False) -> str:
    data = to_bytes(x, byte_order=byte_order, signed=signed)
    return ":".join("%02X" % b for b in data)
