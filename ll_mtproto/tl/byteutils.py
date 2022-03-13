import base64
import functools
import hashlib
import typing
import zlib
from typing import Literal

from ..typed import ByteReader, InThread, ByteConsumer


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
    __slots__ = ["buffer"]

    buffer: bytes

    def __init__(self):
        self.buffer = b""


def unpack_gzip_stream(bytedata: ByteReader, in_thread: InThread) -> ByteReader:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    state = _GzipDecompressStreamState()

    async def read(num_bytes: int) -> bytes:
        while len(state.buffer) < num_bytes:
            state.buffer += await in_thread(decompressor.decompress, await bytedata(1024))

        result = state.buffer[:num_bytes]
        state.buffer = state.buffer[num_bytes:]
        return result

    return read


async def unpack_binary_string_header(bytereader: ByteReader) -> tuple[int, int]:
    str_len = ord(await bytereader(1))

    if str_len > 0xFE:
        raise RuntimeError("Length equal to 255 in string")

    elif str_len == 0xFE:
        str_len = int.from_bytes(await bytereader(3), "little", signed=False)
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
    __slots__ = ["remaining", "padding"]

    remaining: int
    padding: int

    def __init__(self, remaining: int, padding: int):
        self.remaining = remaining
        self.padding = padding


def unpack_binary_stream(bytereader: ByteReader, state: _BinaryStreamState) -> ByteReader:
    async def reader(num_bytes: int) -> bytes:
        if num_bytes >= state.remaining:
            result = await bytereader(state.remaining)

            if state.remaining > 0:
                await bytereader(state.padding)
                state.remaining = 0

            return result
        else:
            state.remaining -= num_bytes
            return await bytereader(num_bytes)

    return reader


async def unpack_binary_string_stream(bytereader: ByteReader):
    state = _BinaryStreamState(*await unpack_binary_string_header(bytereader))
    return unpack_binary_stream(bytereader, state)


async def unpack_long_binary_string_stream(bytereader: ByteReader) -> ByteReader:
    state = _BinaryStreamState(int.from_bytes(await bytereader(4), "little", signed=False), 0)
    return unpack_binary_stream(bytereader, state)


async def unpack_binary_string(bytereader: ByteReader) -> bytes:
    str_len, padding_bytes = await unpack_binary_string_header(bytereader)
    string = await bytereader(str_len)
    await bytereader(padding_bytes)
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
    _byte_order: Literal["big", "little"]
    _signed: bool
    _offset: int
    _date: bytes

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
