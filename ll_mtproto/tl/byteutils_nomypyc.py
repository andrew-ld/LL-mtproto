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


import io

from ll_mtproto.typed import ByteReader, ByteConsumer, InThread, SyncByteReader

__all__ = ("ByteReaderApply", "_SyncByteReaderByteUtilsImpl")


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


class _SyncByteReaderByteUtilsImpl:
    __slots__ = ("_io", "__call__")

    _io: io.BytesIO
    __call__: SyncByteReader

    def __init__(self, buffer: bytes):
        bytes_io = self._io = io.BytesIO(buffer)
        self.__call__ = bytes_io.read
        bytes_io.seek(0)

    def is_empty(self) -> bool:
        return self._io.tell() == self._io.getbuffer().nbytes

    def close(self) -> None:
        self._io.close()
