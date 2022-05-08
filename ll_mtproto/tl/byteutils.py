import base64
import functools
import hashlib
import io
import typing
import zlib
from typing import Literal

from ..typed import ByteReader, InThread, ByteConsumer, SyncByteReader

__all__ = (
    "xor",
    "base64encode",
    "base64decode",
    "sha1",
    "sha256",
    "to_bytes",
    "pack_binary_string",
    "unpack_gzip_stream",
    "unpack_binary_string_header",
    "async_stream_apply",
    "unpack_binary_stream",
    "unpack_binary_string_stream",
    "unpack_long_binary_string_stream",
    "unpack_binary_string",
    "pack_long_binary_string",
    "long_hex",
    "short_hex",
    "short_hex_int",
    "Bytedata"
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
def to_bytes(x: int, byte_order: Literal["big", "little"] = "big", signed=False) -> bytes:
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


class _GzipDecompressStreamState:
    __slots__ = ("buffer",)

    buffer: bytearray

    def __init__(self):
        self.buffer = bytearray()


def unpack_gzip_stream(bytedata: SyncByteReader) -> SyncByteReader:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    state = _GzipDecompressStreamState()

    def read(num_bytes: int) -> bytes:
        while len(state.buffer) < num_bytes:
            state.buffer += decompressor.decompress(bytedata(4096))

        result = state.buffer[:num_bytes]
        state.buffer = state.buffer[num_bytes:]
        return bytes(result)

    return read


def to_reader(buffer: bytes) -> SyncByteReader:
    return io.BytesIO(buffer).read


def unpack_binary_string_header(bytereader: SyncByteReader) -> tuple[int, int]:
    str_len = ord(bytereader(1))

    if str_len > 0xFE:
        raise RuntimeError("Length equal to 255 in string")

    elif str_len == 0xFE:
        str_len = int.from_bytes(bytereader(3), "little", signed=False)
        padding_bytes = (-str_len) % 4

    else:
        padding_bytes = (3 - str_len) % 4

    return str_len, padding_bytes


def async_stream_apply(bytereader: ByteReader, apply: ByteConsumer, in_thread: InThread) -> ByteReader:
    async def wrapper(num_bytes: int) -> bytes:
        result = await bytereader(num_bytes)
        await in_thread(apply, result)
        return result

    return wrapper


class _BinaryStreamState:
    __slots__ = ("remaining", "padding")

    remaining: int
    padding: int

    def __init__(self, remaining: int, padding: int):
        self.remaining = remaining
        self.padding = padding


def unpack_binary_stream(bytereader: SyncByteReader, state: _BinaryStreamState) -> SyncByteReader:
    def reader(num_bytes: int) -> bytes:
        if num_bytes >= state.remaining:
            result = bytereader(state.remaining)

            if state.remaining > 0:
                bytereader(state.padding)
                state.remaining = 0

            return result
        else:
            state.remaining -= num_bytes
            return bytereader(num_bytes)

    return reader


def unpack_binary_string_stream(bytereader: SyncByteReader) -> SyncByteReader:
    state = _BinaryStreamState(*unpack_binary_string_header(bytereader))
    return unpack_binary_stream(bytereader, state)


def unpack_long_binary_string_stream(bytereader: SyncByteReader) -> SyncByteReader:
    state = _BinaryStreamState(int.from_bytes(bytereader(4), "little", signed=False), 0)
    return unpack_binary_stream(bytereader, state)


def unpack_binary_string(bytereader: SyncByteReader) -> bytes:
    str_len, padding_bytes = unpack_binary_string_header(bytereader)
    string = bytereader(str_len)
    bytereader(padding_bytes)
    return string


def pack_long_binary_string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "little", signed=False) + data


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
def short_hex_int(x: int, byte_order: Literal["big", "little"] = "big", signed: bool = False) -> str:
    data = to_bytes(x, byte_order=byte_order, signed=signed)
    return ":".join("%02X" % b for b in data)


# .read for bytes
# this is basically a simplified and possibly buggy but very cozy homebrew StringIO clone
class Bytedata:
    __slots__ = ("_byte_order", "_signed", "_offset", "_data")

    _byte_order: Literal["big", "little"]
    _signed: bool
    _offset: int
    _data: bytes

    def __init__(self, data: bytes, byte_order: Literal["big", "little"] = "big", signed: bool = False):
        self._byte_order = byte_order
        self._signed = signed
        self._offset = 0
        self._data = bytes(data)

    def __repr__(self):
        if len(self._data) - self._offset <= 16:
            return f"Bytedata: {short_hex(self._data[self._offset:])}"

        return f"Bytedata:\n{long_hex(self._data[self._offset:])}"

    def __bytes__(self):
        return self._data[self._offset:]

    def __bool__(self):
        return self._offset < len(self._data)

    def int(self) -> int:
        return int.from_bytes(self._data, self._byte_order, signed=self._signed)

    def unpack_binary_string(self) -> bytes:
        strlen = ord(self.read(1))

        if strlen > 0xFE:
            raise NotImplementedError(f"Length equal to 255 in string {self!r}")

        elif strlen == 0xFE:
            strlen = int.from_bytes(self.read(3), "little", signed=False)
            padding_bytes = (-strlen) % 4

        else:
            padding_bytes = (3 - strlen) % 4

        s = self.read(strlen)
        self.read(padding_bytes)

        return s

    def read(self, num_bytes: int) -> bytes:
        if len(self._data) < num_bytes:
            raise ValueError(f"Unexpected end of data `{self!r}` while reading {num_bytes:d} bytes")

        result = self._data[self._offset: self._offset + num_bytes]
        self._offset += num_bytes
        return result

    async def cororead(self, num_bytes: int) -> bytes:
        return self.read(num_bytes)

    def blocks(self, block_size: int) -> typing.Generator[bytes, None, None]:
        while self._offset < len(self._data):
            block = self._data[self._offset: self._offset + block_size]
            self._offset += block_size
            yield block
