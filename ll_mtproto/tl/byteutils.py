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
import _hashlib

from ll_mtproto.in_thread import InThread
from ll_mtproto.tl.bytereader import AsyncByteReader, ByteConsumer

__all__ = (
    "xor",
    "sha1",
    "sha256",
    "to_bytes",
    "ByteReaderApply",
    "short_hex",
)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(ca ^ cb for ca, cb in zip(a, b))


def _perform_hash(hash_state: _hashlib.HASH, values: typing.Iterable[bytes | memoryview]) -> bytes:
    for value in values:
        hash_state.update(value)
    return hash_state.digest()


def sha1(*values: bytes | memoryview) -> bytes:
    return _perform_hash(hashlib.sha1(), values)


def sha256(*values: bytes | memoryview) -> bytes:
    return _perform_hash(hashlib.sha256(), values)


@functools.lru_cache()
def to_bytes(x: int, byte_order: typing.Literal["big", "little"] = "big", signed: bool = False) -> bytes:
    return x.to_bytes(((x.bit_length() - 1) // 8) + 1, byte_order, signed=signed)


class ByteReaderApply:
    __slots__ = ("_parent", "_apply_function", "_in_thread")

    _parent: AsyncByteReader
    _apply_function: ByteConsumer
    _in_thread: InThread

    def __init__(self, parent: AsyncByteReader, apply_function: ByteConsumer, in_thread: InThread):
        self._parent = parent
        self._apply_function = apply_function
        self._in_thread = in_thread

    async def __call__(self, nbytes: int) -> bytes:
        result = await self._parent(nbytes)
        await self._in_thread(lambda: self._apply_function(result))
        return result


@functools.lru_cache()
def short_hex(data: bytes) -> str:
    return ":".join("%02X" % b for b in data)
