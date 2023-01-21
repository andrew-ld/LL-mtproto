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
import typing

if typing.TYPE_CHECKING:
    from .tl.tl import Structure
else:
    Structure = None

__all__ = (
    "InThread",
    "ByteReader",
    "PartialByteReader",
    "Loop",
    "ByteConsumer",
    "RpcError",
    "TlMessageBody",
    "Structure",
    "SyncByteReader",
    "TlRequestBody"
)

InThread = typing.Callable[..., typing.Awaitable[typing.Any]]
ByteReader = typing.Callable[[int], typing.Awaitable[bytes]]
SyncByteReader = typing.Callable[[int], bytes]
PartialByteReader = typing.Callable[[], typing.Awaitable[bytes]]
Loop = asyncio.AbstractEventLoop
ByteConsumer = typing.Callable[[bytes], None]
TlMessageBody = Structure | list[Structure]
SeqNoGenerator = typing.Callable[[], int]
TlRequestBody = dict[str, TlMessageBody | list[TlMessageBody] | bytes | str | int]


class RpcError(BaseException):
    __slots__ = ("code", "message")

    code: int
    message: str

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
