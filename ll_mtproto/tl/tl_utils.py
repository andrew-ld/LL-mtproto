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


import typing

from ll_mtproto.tl.bytereader import SyncByteReader
from ll_mtproto.tl.structure import TypedStructure, Structure
from ll_mtproto.tl.tl import Schema, Constructor, Value

__all__ = ("TypedSchemaConstructor", "flat_value_buffer")

T = typing.TypeVar('T')


class TypedSchemaConstructor[T: TypedStructure[typing.Any]]:
    __slots__ = (
        "cons",
    )

    cons: Constructor

    def __init__(self, schema: Schema, cls: typing.Type[T]):
        self.cons = schema.constructors[cls.CONS]

    def deserialize_boxed_data(self, reader: SyncByteReader) -> T:
        return typing.cast(T, Structure.from_tl_obj(self.cons.deserialize_boxed_data(reader)))

    def deserialize_bare_data(self, reader: SyncByteReader) -> T:
        return typing.cast(T, Structure.from_tl_obj(self.cons.deserialize_bare_data(reader)))

    def boxed_buffer_match(self, buffer: bytes | bytearray | Value) -> bool:
        return self.cons.boxed_buffer_match(buffer)


def flat_value_buffer(buffer: Value | bytes) -> bytes:
    if isinstance(buffer, Value):
        return buffer.get_flat_bytes()

    return buffer
