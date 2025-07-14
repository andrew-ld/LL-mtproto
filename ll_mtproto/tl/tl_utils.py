import typing

from ll_mtproto.tl.bytereader import SyncByteReader
from ll_mtproto.tl.structure import TypedStructure, Structure
from ll_mtproto.tl.tl import Schema, Constructor, Value

__all__ = ("TypedSchemaConstructor", "flat_value_buffer")

T = typing.TypeVar('T', bound=TypedStructure)


class TypedSchemaConstructor(typing.Generic[T]):
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
