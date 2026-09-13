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


import binascii
import gzip
import random
import re
import secrets
import sys
import typing
import zlib

from librt.strings import (
    BytesWriter,
    read_f64_le,
    read_i32_le,
    read_i64_le,
    write_f64_le,
    write_i32_le,
    write_i64_le,
)
from librt.vecs import vec
from mypy_extensions import i32, i64

__all__ = (
    "Schema",
    "Parameter",
    "Constructor",
    "TlBodyData",
    "TlBodyDataValue",
    "pack_binary_string",
    "ByteReader",
    "TlPrimitiveValue",
    "Value",
    "extract_cons_from_tl_body",
    "extract_cons_from_tl_body_opt"
)

_zlib_decompress: typing.Final = zlib.decompress
_zlib_max_wbits: typing.Final = 16 + zlib.MAX_WBITS
_gzip_compress: typing.Final = gzip.compress
_randbits: typing.Final = secrets.randbits
_randbytes: typing.Final = random.randbytes

_U32_RANGE: typing.Final = 0x100000000
_U64_RANGE: typing.Final = 0x10000000000000000


class ByteReader:
    __slots__ = ("buffer", "offset")

    buffer: typing.Final[bytes]
    offset: int

    def __init__(self, buffer: bytes):
        self.buffer = buffer
        self.offset = 0

    def __bool__(self) -> bool:
        return self.offset < len(self.buffer)

    def __call__(self, nbytes: int) -> bytes:
        current_offset = self.offset

        if nbytes == -1:
            nbytes = len(self.buffer) - current_offset

        self.offset = result_end = current_offset + nbytes

        return self.buffer[current_offset:result_end]

    def read_binary(self, nbytes: int) -> bytes:
        offset = self.offset
        self.offset = offset + nbytes

        return self.buffer[offset:offset + nbytes]

    def read_remaining(self) -> bytes:
        offset = self.offset
        self.offset = len(self.buffer)

        return self.buffer[offset:]

    def read_i32(self) -> "i32":
        offset = self.offset
        self.offset = offset + 4
        return read_i32_le(self.buffer, offset)

    def read_u32(self) -> int:
        offset = self.offset
        self.offset = offset + 4
        value: int = read_i32_le(self.buffer, offset)

        if value < 0:
            value += _U32_RANGE

        return value

    def read_i64(self) -> int:
        offset = self.offset
        self.offset = offset + 8
        return read_i64_le(self.buffer, offset)

    def read_u64(self) -> int:
        offset = self.offset
        self.offset = offset + 8
        value: int = read_i64_le(self.buffer, offset)

        if value < 0:
            value += _U64_RANGE

        return value

    def read_f64(self) -> float:
        offset = self.offset
        self.offset = offset + 8
        return read_f64_le(self.buffer, offset)

    def read_binary_string_zlib(self) -> bytes:
        return _zlib_decompress(self.read_binary_string(), _zlib_max_wbits)

    def read_binary_string(self) -> bytes:
        buffer = self.buffer
        offset = self.offset
        str_len = buffer[offset]
        offset += 1

        if str_len > 0xFE:
            raise RuntimeError("Length equal to 255 in string")

        elif str_len == 0xFE:
            if offset + 4 <= len(buffer):
                str_len = read_i32_le(buffer, offset) & 0xFFFFFF
            else:
                str_len = int.from_bytes(buffer[offset:offset + 3], "little", signed=False)

            offset += 3
            padding_len = (-str_len) % 4

        else:
            padding_len = (3 - str_len) % 4

        self.offset = offset + str_len + padding_len

        return buffer[offset:offset + str_len]


def _compile_cons_number(definition: bytes) -> int:
    crc = binascii.crc32(definition)
    return crc - _U32_RANGE if crc > 0x7FFFFFFF else crc


def _cons_number_hex(number: int) -> str:
    return hex(number & 0xFFFFFFFF)


_bool_true_cons_number_int: typing.Final["i32"] = _compile_cons_number(b"boolTrue = Bool")
_bool_false_cons_number_int: typing.Final["i32"] = _compile_cons_number(b"boolFalse = Bool")
_vector_cons_number_int: typing.Final["i32"] = _compile_cons_number(b"vector t:Type # [ t ] = Vector t")

_zero_padding: typing.Final = (b"", b"\x00", b"\x00\x00", b"\x00\x00\x00")

_NO_FLAG_SLOTS: typing.Final[list[tuple[int, int]]] = []


def pack_binary_string(data: bytes) -> bytes:
    writer = BytesWriter()
    _write_binary_string(writer, data)
    return writer.getvalue()


def _deserialize_bool(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_i32() == _bool_true_cons_number_int


def _deserialize_int(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_i32()


def _deserialize_uint(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_u32()


def _deserialize_long(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_i64()


def _deserialize_ulong(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_u64()


def _deserialize_int128(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_binary(16)


def _deserialize_sha1(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_binary(20)


def _deserialize_int256(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_binary(32)


def _deserialize_double(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_f64()


def _deserialize_string(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_binary_string().decode("utf-8")


def _deserialize_bytes(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_binary_string()


def _deserialize_rawobject(reader: ByteReader) -> "TlBodyDataValue":
    return reader.read_remaining()


_primitive_deserializers: typing.Final[dict[str, typing.Callable[[ByteReader], "TlBodyDataValue"]]] = {
    "Bool": _deserialize_bool,
    "int": _deserialize_int,
    "uint": _deserialize_uint,
    "long": _deserialize_long,
    "ulong": _deserialize_ulong,
    "int128": _deserialize_int128,
    "sha1": _deserialize_sha1,
    "int256": _deserialize_int256,
    "double": _deserialize_double,
    "string": _deserialize_string,
    "bytes": _deserialize_bytes,
    "rawobject": _deserialize_rawobject,
}


def _write_true(_writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if argument is True:
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `true`")


def _write_bool(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if argument is True:
        write_i32_le(writer, _bool_true_cons_number_int)
        return

    if argument is False:
        write_i32_le(writer, _bool_false_cons_number_int)
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `Bool`")


def _write_int(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, int) and not isinstance(argument, bool):
        write_i32_le(writer, argument)
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `int`")


def _write_uint(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, int) and not isinstance(argument, bool):
        writer.write(argument.to_bytes(4, "little", signed=False))
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `uint`")


def _write_long(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, int) and not isinstance(argument, bool):
        write_i64_le(writer, argument)
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `long`")


def _write_ulong(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, int) and not isinstance(argument, bool):
        writer.write(argument.to_bytes(8, "little", signed=False))
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `ulong`")


def _write_double(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, bool):
        raise TypeError(f"Cannot serialize python {argument!r} as `double`")

    if isinstance(argument, int):
        write_f64_le(writer, float(argument))
        return

    if isinstance(argument, float):
        write_f64_le(writer, argument)
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `double`")


def _write_int128(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, bool):
        raise TypeError(f"Cannot serialize python {argument!r} as `int128`")

    if isinstance(argument, int):
        writer.write(argument.to_bytes(16, "little", signed=True))
        return

    if isinstance(argument, bytes):
        if len(argument) != 16:
            raise TypeError("int128 bytes must be 16 bytes long")

        writer.write(argument)
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `int128`")


def _write_sha1(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, bytes):
        if len(argument) != 20:
            raise TypeError("sha1 bytes must be 20 bytes long")

        writer.write(argument)
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `sha1`")


def _write_int256(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, bool):
        raise TypeError(f"Cannot serialize python {argument!r} as `int256`")

    if isinstance(argument, int):
        writer.write(argument.to_bytes(32, "little", signed=True))
        return

    if isinstance(argument, bytes):
        if len(argument) != 32:
            raise TypeError("int256 bytes must be 32 bytes long")

        writer.write(argument)
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `int256`")


def _write_binary_string(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, bytes):
        length = len(argument)

        if length < 254:
            writer.append(length)
            writer.write(argument)
            writer.write(_zero_padding[(3 - length) % 4])
            return

        if length <= 0xFFFFFF:
            writer.append(0xFE)
            writer.write(length.to_bytes(3, "little", signed=False))
            writer.write(argument)
            writer.write(_zero_padding[(-length) % 4])
            return

        raise OverflowError("String too long")

    raise TypeError(f"Cannot serialize python {argument!r} as `string`/`bytes`")


def _write_rawobject(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, bytes):
        writer.write(argument)
        return

    if isinstance(argument, Value):
        writer.write(argument.get_flat_bytes())
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `rawobject`")


def _write_plain_object(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, Value):
        data = argument.get_flat_bytes()
        write_i32_le(writer, len(data))
        writer.write(data)
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `PlainObject`")


def _write_padded_object(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, Value):
        data = argument.get_flat_bytes()
        padding_len = -len(data) & 15
        padding_len += 16 * (_randbits(64) % 16)
        write_i32_le(writer, len(data) + padding_len)
        writer.write(data)
        writer.write(_randbytes(padding_len))
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `PaddedObject`")


def _write_gzip(writer: BytesWriter, argument: "TlBodyDataValue") -> None:
    if isinstance(argument, Value):
        writer.write(pack_binary_string(_gzip_compress(argument.get_flat_bytes())))
        return

    raise TypeError(f"Cannot serialize python {argument!r} as `gzip`")


# Ints, not an Enum: mypyc turns the dispatch chain into direct calls.
_KIND_TRUE: typing.Final = 0
_KIND_BOOL: typing.Final = 1
_KIND_INT: typing.Final = 2
_KIND_UINT: typing.Final = 3
_KIND_LONG: typing.Final = 4
_KIND_ULONG: typing.Final = 5
_KIND_DOUBLE: typing.Final = 6
_KIND_INT128: typing.Final = 7
_KIND_SHA1: typing.Final = 8
_KIND_INT256: typing.Final = 9
_KIND_STRING: typing.Final = 10
_KIND_RAWOBJECT: typing.Final = 11
_KIND_PLAIN_OBJECT: typing.Final = 12
_KIND_PADDED_OBJECT: typing.Final = 13
_KIND_GZIP: typing.Final = 14

_serialize_kinds: typing.Final[dict[str, int]] = {
    "true": _KIND_TRUE,
    "Bool": _KIND_BOOL,
    "int": _KIND_INT,
    "uint": _KIND_UINT,
    "long": _KIND_LONG,
    "ulong": _KIND_ULONG,
    "double": _KIND_DOUBLE,
    "int128": _KIND_INT128,
    "sha1": _KIND_SHA1,
    "int256": _KIND_INT256,
    "string": _KIND_STRING,
    "bytes": _KIND_STRING,
    "rawobject": _KIND_RAWOBJECT,
    "PlainObject": _KIND_PLAIN_OBJECT,
    "PaddedObject": _KIND_PADDED_OBJECT,
    "gzip": _KIND_GZIP,
}


def _write_primitive(writer: BytesWriter, kind: int, argument: "TlBodyDataValue") -> None:
    if kind == _KIND_INT:
        _write_int(writer, argument)
        return

    if kind == _KIND_LONG:
        _write_long(writer, argument)
        return

    if kind == _KIND_STRING:
        _write_binary_string(writer, argument)
        return

    if kind == _KIND_TRUE:
        return

    if kind == _KIND_UINT:
        _write_uint(writer, argument)
        return

    if kind == _KIND_ULONG:
        _write_ulong(writer, argument)
        return

    if kind == _KIND_DOUBLE:
        _write_double(writer, argument)
        return

    if kind == _KIND_BOOL:
        _write_bool(writer, argument)
        return

    if kind == _KIND_INT128:
        _write_int128(writer, argument)
        return

    if kind == _KIND_INT256:
        _write_int256(writer, argument)
        return

    if kind == _KIND_SHA1:
        _write_sha1(writer, argument)
        return

    if kind == _KIND_RAWOBJECT:
        _write_rawobject(writer, argument)
        return

    if kind == _KIND_PLAIN_OBJECT:
        _write_plain_object(writer, argument)
        return

    if kind == _KIND_PADDED_OBJECT:
        _write_padded_object(writer, argument)
        return

    if kind == _KIND_GZIP:
        _write_gzip(writer, argument)
        return

    raise TypeError(f"Unknown primitive kind {kind} for {argument!r}")


_str_accepting_primitives: typing.Final[frozenset[str]] = frozenset(("string", "bytes", "rawobject"))
_value_accepting_primitives: typing.Final[frozenset[str]] = frozenset(("rawobject", "PlainObject", "PaddedObject", "gzip"))

_primitives: typing.Final[frozenset[str]] = frozenset(
    (
        "int",
        "uint",
        "long",
        "ulong",
        "int128",
        "sha1",
        "int256",
        "double",
        "string",
        "bytes",
        "rawobject",
        "flags",
        "gzip",
        "true",
        "Bool",
        "PlainObject",
        "PaddedObject"
    )
)

_schema_RE: typing.Final[re.Pattern[str]] = re.compile(
    r"^(?P<empty>$)"
    r"|(?P<comment>//.*)"
    r"|(?P<typessection>---types---)"
    r"|(?P<functionssection>---functions---)"
    r"|(?P<vector>vector#1cb5c415 {t:Type} # \[ t ] = Vector t;)"
    r"|(?P<cons>(?P<name>[a-zA-Z\d._]+)(#(?P<number>[a-f\d]{1,8}))?"
    r"(?P<xtype> {X:Type})?"
    r"(?P<parameters>.*?)"
    r"(?(xtype) query:!X = X| = (?P<type>[a-zA-Z\d._<>]+));)"
    r"$"
)

_parameter_RE: typing.Final[re.Pattern[str]] = re.compile(
    r"^(?P<name>\w+):"
    r"(flags(?P<flag_index>\d+)?.(?P<flag_number>\d+)\?)?"
    r"(?P<type>"
    r"(?P<vector>((?P<bare_vector>vector)|(?P<boxed_vector>Vector))<)?"
    r"(?P<element_type>((?P<namespace>[a-zA-Z\d._]*)\.)?"
    r"((?P<bare>(?!gzip)[a-z][a-zA-Z\d._]*)|(?P<boxed>[A-Zg][a-zA-Z\d._]*)))"
    r"(?(vector)>)?)$"
)

_flag_RE: typing.Final[re.Pattern[str]] = re.compile(
    r"flags(?P<flag_index>\d+)?:#"
)

_layer_RE: typing.Final[re.Pattern[str]] = re.compile(
    r"^// LAYER (?P<layer>\d+)$"
)

_ptype_RE: typing.Final[re.Pattern[str]] = re.compile(
    r"^(?P<is_vector>Vector<(?P<vector_element_type>[a-zA-Z\d._]*)>$)?(?P<element_type>[a-zA-Z\d._]*$)?"
)

_IntKeyDict_EMPTY_SLOT: typing.Final["i64"] = -0x8000000000000000


class IntKeyDict:
    __slots__ = ("_keys", "_values", "_mask", "_size")

    _keys: "vec[i64]"
    _values: "vec[i64]"
    _mask: "i64"
    _size: "i64"

    def __init__(self) -> None:
        self._keys = vec[i64]([_IntKeyDict_EMPTY_SLOT] * 8)
        self._values = vec[i64]([0] * 8)
        self._mask = 7
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def get(self, key: int) -> "i64":
        keys = self._keys
        values = self._values
        mask = self._mask
        k: i64 = key
        index = (k ^ (k >> 16)) & mask

        while True:
            stored = keys[index]

            if stored == k:
                return values[index]

            if stored == _IntKeyDict_EMPTY_SLOT:
                return -1

            index = (index + 1) & mask

    def __setitem__(self, key: int, value: int) -> None:
        if (self._size + 1) * 2 > len(self._keys):
            self._resize(self._size + 1)

        k: i64 = key
        v: i64 = value

        if self._place(self._keys, self._values, self._mask, k, v):
            self._size += 1

    @staticmethod
    def _place(keys: "vec[i64]", values: "vec[i64]", mask: "i64", key: "i64", value: "i64") -> bool:
        index = (key ^ (key >> 16)) & mask

        while keys[index] != _IntKeyDict_EMPTY_SLOT:
            if keys[index] == key:
                values[index] = value
                return False

            index = (index + 1) & mask

        keys[index] = key
        values[index] = value
        return True

    def _resize(self, min_entries: "i64") -> None:
        size: i64 = 8

        while size < min_entries * 2:
            size <<= 1

        mask = size - 1
        keys = vec[i64]([_IntKeyDict_EMPTY_SLOT] * size)
        values = vec[i64]([0] * size)
        old_keys = self._keys
        old_values = self._values

        for index in range(len(old_keys)):
            key = old_keys[index]

            if key != _IntKeyDict_EMPTY_SLOT:
                self._place(keys, values, mask, key, old_values[index])

        self._keys = keys
        self._values = values
        self._mask = mask


class Schema:
    __slots__ = (
        "constructors",
        "types",
        "layer",
        "_cons_ids",
        "_cons_lookup",
    )

    constructors: typing.Final[dict[str, "Constructor"]]
    types: typing.Final[dict[str, set["Constructor"]]]
    layer: int | None
    _cons_ids: list["Constructor"]
    _cons_lookup: IntKeyDict

    def __init__(self) -> None:
        self.constructors = dict()
        self.types = dict()
        self.layer = None
        self._cons_ids = []
        self._cons_lookup = IntKeyDict()

    def _index_cons_number(self, number: int, cons: "Constructor") -> None:
        cons_id = len(self._cons_ids)
        self._cons_ids.append(cons)
        self._cons_lookup[number] = cons_id

    def __repr__(self) -> str:
        return "\n".join(repr(cons) for cons in self.constructors.values())

    def extend_from_raw_schema(self, schema: str, is_function: bool = False) -> None:
        for schema_line in schema.split("\n"):
            if schema_line == "---types---":
                is_function = False

            elif schema_line == "---functions---":
                is_function = True

            else:
                self._parse_line(schema_line, is_function)

    @staticmethod
    def _parse_token(regex: re.Pattern[str], text: str) -> None | dict[str, str]:
        match = regex.match(text)

        if not match:
            return None
        else:
            return {k: v for k, v in match.groupdict().items() if v is not None}

    def _parse_line(self, line: str, is_function: bool) -> None:
        cons_parsed = self._parse_token(_schema_RE, line)

        if not cons_parsed:
            raise SyntaxError(f"Error in schema: f{line}")

        if "cons" not in cons_parsed:
            layer_parsed = self._parse_token(_layer_RE, line)

            if layer_parsed and "layer" in layer_parsed:
                self.layer = int(layer_parsed["layer"])

            return

        parameter_tokens: list[str] = cons_parsed["parameters"].split(" ")[1:]
        parameters = []

        if "number" in cons_parsed:
            cons_number_int = int(cons_parsed["number"], base=16)
            cons_number = cons_number_int.to_bytes(4, "little", signed=False)
        else:
            cons_number = None

        for parameter_token in parameter_tokens:
            parameter_parsed = self._parse_token(_parameter_RE, parameter_token)

            if not parameter_parsed and parameter_token.endswith(":#"):
                flag_parsed = self._parse_token(_flag_RE, parameter_token)

                if flag_parsed is None:
                    raise SyntaxError(f"Error in flag: `{parameter_token}`")

                flag_index = int(flag_parsed["flag_index"]) if "flag_index" in flag_parsed else 0
            else:
                flag_parsed = None
                flag_index = None

            if parameter_parsed is None and flag_parsed is None:
                raise SyntaxError(f"Error in parameter `{parameter_token}`")

            if parameter_parsed:
                if parameter_parsed["name"] == "from":
                    parameter_parsed["name"] = "from_"

                is_vector = "vector" in parameter_parsed

                if is_vector:
                    element_parameter = Parameter(
                        pname=f"<element of vector `{parameter_parsed['name']}`>",
                        ptype=sys.intern(parameter_parsed["element_type"]),
                        is_boxed="boxed" in parameter_parsed,
                    )
                else:
                    element_parameter = None
            else:
                is_vector = False
                element_parameter = None

            if parameter_parsed:
                parameter = Parameter(
                    pname=sys.intern(parameter_parsed["name"]),
                    ptype=sys.intern(parameter_parsed["type"]),
                    flag_number=int(parameter_parsed["flag_number"])
                    if "flag_number" in parameter_parsed
                    else None,
                    flag_index=int(parameter_parsed["flag_index"])
                    if "flag_index" in parameter_parsed
                    else 0,
                    is_vector=is_vector,
                    is_boxed="boxed_vector" in parameter_parsed if is_vector else "boxed" in parameter_parsed,
                    element_parameter=element_parameter,
                )
            else:
                parameter = Parameter(
                    is_boxed=False,
                    is_flag=True,
                    is_vector=False,
                    pname=parameter_token,
                    ptype="flags",
                    flag_index=flag_index
                )

            parameters.append(parameter)

        if "xtype" in cons_parsed:
            parameters.append(
                Parameter(
                    pname="_wrapped",
                    ptype="rawobject",
                    flag_number=None,
                    is_vector=False,
                    is_boxed=True,
                    element_parameter=None,
                )
            )

        ptype = None if "xtype" in cons_parsed else cons_parsed["type"]
        ptype_parsed = None if ptype is None else self._parse_token(_ptype_RE, ptype)

        if ptype_parsed is None and ptype is not None:
            raise SyntaxError(f"Error in ptype: `{ptype}`")

        ptype_parameter = None

        if ptype_parsed:
            ptype_is_vector = "is_vector" in ptype_parsed
            ptype_vector_ptype = sys.intern(ptype_parsed["vector_element_type"]) if ptype_is_vector else None
            ptype_type = sys.intern(ptype_parsed["element_type"]) if not ptype_is_vector else None

            if ptype_is_vector:
                element_parameter = Parameter(
                    pname=f"<element of vector `{ptype_vector_ptype}`>",
                    ptype=ptype_vector_ptype,
                    is_boxed=True,
                )
            else:
                element_parameter = None

            ptype_parameter = Parameter(
                is_boxed=True,
                is_vector=ptype_is_vector,
                ptype=ptype_type,
                pname=f"<return type of `{ptype}`>",
                element_parameter=element_parameter
            )

        cons = Constructor(
            schema=self,
            ptype=ptype,
            name=sys.intern(cons_parsed["name"]),
            number=cons_number,
            parameters=tuple(parameters),
            flags=set(p.flag_index for p in parameters if p.is_flag and p.flag_index is not None) or None,
            is_function=is_function,
            ptype_parameter=ptype_parameter,
            line=line
        )

        self.constructors[cons.name] = cons

        if cons.number is not None:
            self._index_cons_number(cons.number_int, cons)

        if (cons_ptype := cons.ptype) is not None:
            self.types.setdefault(cons_ptype, set()).add(cons)

    def deserialize_primitive(self, reader: ByteReader, parameter: "Parameter") -> "TlBodyDataValue":
        match parameter.type:
            case "gzip":
                raise RuntimeError(f"must not directly deserialize gzip {reader!r} {parameter!r}")

            case "PaddedObject" | "PlainObject":
                length = reader.read_u32()
                return self.read_by_boxed_data(ByteReader(reader.read_binary(length)))

            case "flags":
                raise TypeError(f"Cannot deserialize flags directly {parameter!r}")

            case _:
                raise TypeError(f"Unknown primitive type {parameter!r}")

    def typecheck(self, expected: "Parameter", found: typing.Union["TlBodyDataValue", "Value"]) -> None:
        if not isinstance(found, Value):
            raise TypeError("not an object for nonbasic type", f"expected: {expected!r}, found {found!r}")

        self.typecheck_cons(expected, found.cons)

    def typecheck_cons(self, expected: "Parameter", found: "Constructor") -> None:
        expected_type = expected.type

        if expected_type is None:
            raise TypeError("unsupported Parameter, type is None", f"expected: {expected!r}, found {found!r}")

        if expected.is_boxed:
            allowed = expected.typecheck_constructors

            if allowed is None:
                allowed = self.types[expected_type]
                expected.typecheck_constructors = allowed

            if found not in allowed:
                raise TypeError("type mismatch", f"expected: {expected!r}, found {found!r}")

            if found.number is None:
                raise TypeError("expected boxed, found bare", f"expected: {expected!r}, found {found!r}")
        elif found.name != expected_type:
            raise TypeError("wrong constructor", f"expected: {expected!r}, found {found!r}")

    def deserialize(self, reader: ByteReader, parameter: "Parameter") -> "TlBodyDataValue":
        if parameter.is_primitive:
            deserialize_fn = parameter.primitive_deserializer

            if deserialize_fn is not None:
                return deserialize_fn(reader)

            return self.deserialize_primitive(reader, parameter)

        if parameter.is_boxed:
            cons_number = reader.read_i32()

            if parameter.is_vector:
                if cons_number != _vector_cons_number_int:
                    cons_id = self._cons_lookup.get(cons_number)

                    if cons_id >= 0 and self._cons_ids[cons_id].is_gzip_container:
                        return self.deserialize(ByteReader(reader.read_binary_string_zlib()), parameter)

                    raise ValueError(f"Unknown constructor {_cons_number_hex(cons_number)} for vector")

                element_parameter = parameter.element_parameter

                if element_parameter is None:
                    raise TypeError(f"Unknown vector parameter type {parameter!r}")

                return [
                    self.deserialize(reader, element_parameter)
                    for _ in range(reader.read_u32())
                ]

            cons_id = self._cons_lookup.get(cons_number)

            if cons_id < 0:
                raise ValueError(f"Unknown constructor {_cons_number_hex(cons_number)}")

            boxed_cons = self._cons_ids[cons_id]

            if boxed_cons.is_gzip_container:
                return self.deserialize(ByteReader(reader.read_binary_string_zlib()), parameter)

            parameter_type = parameter.type

            if parameter_type is not None:
                allowed = parameter.typecheck_constructors

                if allowed is None:
                    allowed = self.types[parameter_type]
                    parameter.typecheck_constructors = allowed

                if boxed_cons not in allowed and boxed_cons.ptype:
                    raise ValueError(f"type mismatch, constructor `{boxed_cons.name}` not in type `{parameter_type}`")

            return boxed_cons.deserialize_bare_data(reader)
        else:
            if parameter.is_vector:
                element_parameter = parameter.element_parameter

                if element_parameter is None:
                    raise TypeError(f"Unknown vector parameter type {parameter!r}")

                return [
                    self.deserialize(reader, element_parameter)
                    for _ in range(reader.read_u32())
                ]

            parameter_type = parameter.type

            if parameter_type is None:
                raise TypeError(f"Unknown type for bare constructor {parameter!r}")

            cons = self.constructors.get(parameter_type, None)

            if not cons:
                raise ValueError(f"Unknown constructor in parameter `{parameter!r}`")

            return cons.deserialize_bare_data(reader)

    def serialize(self, boxed: bool, cons_name: str, body: "TlBodyData") -> "Value":
        if cons := self.constructors.get(cons_name, None):
            return cons.serialize(boxed, body)
        else:
            raise NotImplementedError(f"Constructor `{cons_name}` not present in schema.")

    def bare_kwargs(self, *, _cons: str, **body: "TlBodyDataValue") -> "Value":
        return self.serialize(False, _cons, body)

    def boxed_kwargs(self, *, _cons: str, **body: "TlBodyDataValue") -> "Value":
        return self.serialize(True, _cons, body)

    def boxed(self, body: "TlBodyData") -> "Value":
        return self.serialize(True, extract_cons_from_tl_body(body), body)

    def read_by_parameter(self, reader: ByteReader, parameter: "Parameter") -> "TlBodyDataValue":
        return self.deserialize(reader, parameter)

    def read_by_boxed_data(self, reader: ByteReader) -> "TlBodyData":
        cons_number = reader.read_i32()
        cons_id = self._cons_lookup.get(cons_number)

        if cons_id < 0:
            raise TypeError(f"Unknown constructor for constructor number {_cons_number_hex(cons_number)}")

        cons = self._cons_ids[cons_id]

        if cons.is_gzip_container:
            return self.read_by_boxed_data(ByteReader(reader.read_binary_string_zlib()))

        return cons.deserialize_bare_data(reader)


class Value:
    __slots__ = ("cons", "boxed", "data")

    cons: typing.Final["Constructor"]
    boxed: typing.Final[bool]
    data: bytes

    def __init__(self, cons: "Constructor", boxed: bool = False, data: bytes = b""):
        self.cons = cons
        self.boxed = boxed

        if boxed and cons.number is None:
            raise RuntimeError(f"Tried to create a boxed value for a numberless constructor `{cons!r}`")

        self.data = data

    def __repr__(self) -> str:
        return f"{'boxed' if self.boxed else 'bare'}({self.cons!r})"

    def get_flat_bytes(self) -> bytes:
        return self.data


class ParameterFlag:
    __slots__ = (
        "flag_index",
        "flag_number",
        "extended_flag_mask",
        "group_id"
    )

    flag_index: typing.Final[int]
    flag_number: typing.Final[int]
    extended_flag_mask: typing.Final[int]
    group_id: int

    def __init__(self, flag_index: int, flag_number: int):
        self.flag_index = flag_index
        self.flag_number = flag_number
        self.extended_flag_mask = (1 << flag_number) << (max(0, flag_index - 1) * 31)
        self.group_id = -1

    def __repr__(self) -> str:
        return f"flags{self.flag_index}.{self.flag_number}"


class Parameter:
    __slots__ = (
        "name",
        "type",
        "is_vector",
        "is_boxed",
        "element_parameter",
        "is_flag",
        "flag_index",
        "is_primitive",
        "required",
        "parameter_flag",
        "extended_flag_index",
        "primitive_deserializer",
        "serialize_kind",
        "direct_serialize_kind",
        "accepts_str",
        "accepts_dict",
        "typecheck_constructors"
    )

    name: typing.Final[str]
    type: typing.Final[str | None]
    flag_index: typing.Final[int | None]
    is_vector: typing.Final[bool]
    is_boxed: typing.Final[bool]
    is_flag: typing.Final[bool]
    element_parameter: typing.Final["Parameter | None"]
    is_primitive: typing.Final[bool]
    required: typing.Final[bool]
    parameter_flag: typing.Final[ParameterFlag | None]
    extended_flag_index: typing.Final[int | None]
    primitive_deserializer: typing.Final[typing.Callable[[ByteReader], "TlBodyDataValue"] | None]
    serialize_kind: typing.Final[int]
    direct_serialize_kind: typing.Final[int]
    accepts_str: typing.Final[bool]
    accepts_dict: typing.Final[bool]
    typecheck_constructors: set["Constructor"] | None

    def __init__(
            self,
            pname: str,
            ptype: str | None,
            is_boxed: bool,
            flag_number: int | None = None,
            is_vector: bool = False,
            is_flag: bool = False,
            flag_index: int | None = None,
            element_parameter: "Parameter | None" = None,
    ):
        self.name = pname
        self.type = ptype
        self.is_vector = is_vector
        self.is_boxed = is_boxed
        self.element_parameter = element_parameter
        self.is_flag = is_flag
        self.flag_index = flag_index if is_flag else None
        self.extended_flag_index = (max(0, flag_index - 1) * 31) if flag_index is not None else None
        self.is_primitive = ptype in _primitives
        self.required = flag_number is None
        self.parameter_flag = None if flag_number is None or flag_index is None else ParameterFlag(flag_index, flag_number)
        self.primitive_deserializer = None if ptype is None else _primitive_deserializers.get(ptype)
        self.serialize_kind = -1 if ptype is None else _serialize_kinds.get(ptype, -1)
        self.accepts_str = ptype in _str_accepting_primitives
        self.accepts_dict = ptype in _value_accepting_primitives or (not self.is_primitive and not is_vector)
        self.direct_serialize_kind = -1 if self.accepts_str or self.accepts_dict else self.serialize_kind
        self.typecheck_constructors = None

    def __repr__(self) -> str:
        if self.parameter_flag is not None:
            return f"{self.name}:flags.{self.parameter_flag!r}?{self.type}"
        else:
            return f"{self.name}:{self.type}"


class AbstractDeserializationStep:
    __slots__ = ()

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return False

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "AbstractDeserializationStep | None":
        raise TypeError(f"Unsupported optimized deserialization {parameter!r}")

    @staticmethod
    def _flag_mask(parameter: "Parameter") -> int:
        parameter_flag = parameter.parameter_flag

        if parameter_flag is None:
            raise TypeError(f"Unknown flag for parameter `{parameter!r}`")

        return parameter_flag.extended_flag_mask

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        """Read one field, returning the flag bits it contributes (``0`` for data fields)."""
        raise NotImplementedError()


class StringFieldDeserialization(AbstractDeserializationStep):
    __slots__ = ("_key",)

    _key: typing.Final[str]

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return parameter.parameter_flag is None and parameter.type == "string"

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "StringFieldDeserialization":
        return cls(parameter.name)

    def __init__(self, key: str) -> None:
        self._key = key

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        output[self._key] = reader.read_binary_string().decode("utf-8")
        return 0


class FlaggedStringFieldDeserialization(StringFieldDeserialization):
    __slots__ = ("_mask",)

    _mask: typing.Final[int]

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return parameter.parameter_flag is not None and parameter.type == "string"

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "FlaggedStringFieldDeserialization":
        return cls(parameter.name, cls._flag_mask(parameter))

    def __init__(self, key: str, mask: int) -> None:
        super().__init__(key)
        self._mask = mask

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        if flags & self._mask:
            output[self._key] = reader.read_binary_string().decode("utf-8")

        return 0


class ByteStringFieldDeserialization(AbstractDeserializationStep):
    __slots__ = ("_key",)

    _key: typing.Final[str]

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return parameter.parameter_flag is None and parameter.type == "bytes"

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "ByteStringFieldDeserialization":
        return cls(parameter.name)

    def __init__(self, key: str) -> None:
        self._key = key

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        output[self._key] = reader.read_binary_string()
        return 0


class FlaggedByteStringFieldDeserialization(ByteStringFieldDeserialization):
    __slots__ = ("_mask",)

    _mask: typing.Final[int]

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return parameter.parameter_flag is not None and parameter.type == "bytes"

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "FlaggedByteStringFieldDeserialization":
        return cls(parameter.name, cls._flag_mask(parameter))

    def __init__(self, key: str, mask: int) -> None:
        super().__init__(key)
        self._mask = mask

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        if flags & self._mask:
            output[self._key] = reader.read_binary_string()

        return 0


_fixed_size_kinds: typing.Final[dict[str, int]] = {
    "int": _KIND_INT,
    "uint": _KIND_UINT,
    "long": _KIND_LONG,
    "ulong": _KIND_ULONG,
    "double": _KIND_DOUBLE,
}

_fixed_size_byte_sizes: typing.Final[dict[str, int]] = {
    "int128": 16,
    "sha1": 20,
    "int256": 32,
}


def _read_fixed_size(reader: ByteReader, kind: int) -> int | float:
    if kind == _KIND_INT:
        return reader.read_i32()

    if kind == _KIND_UINT:
        return reader.read_u32()

    if kind == _KIND_LONG:
        return reader.read_i64()

    if kind == _KIND_ULONG:
        return reader.read_u64()

    if kind == _KIND_DOUBLE:
        return reader.read_f64()

    raise TypeError(f"Unknown fixed size kind {kind}")


class StructFieldDeserialization(AbstractDeserializationStep):
    __slots__ = ("_key", "_kind")

    _key: typing.Final[str]
    _kind: typing.Final[int]

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return parameter.parameter_flag is None and parameter.type in _fixed_size_kinds

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "StructFieldDeserialization":
        parameter_type = parameter.type

        if parameter_type is None or parameter_type not in _fixed_size_kinds:
            raise TypeError(f"Unsupported optimized deserialization {parameter!r}")

        return cls(parameter.name, _fixed_size_kinds[parameter_type])

    def __init__(self, key: str, kind: int) -> None:
        self._key = key
        self._kind = kind

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        output[self._key] = _read_fixed_size(reader, self._kind)
        return 0


class FlaggedStructFieldDeserialization(StructFieldDeserialization):
    __slots__ = ("_mask",)

    _mask: typing.Final[int]

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return parameter.parameter_flag is not None and parameter.type in _fixed_size_kinds

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "FlaggedStructFieldDeserialization":
        parameter_type = parameter.type

        if parameter_type is None or parameter_type not in _fixed_size_kinds:
            raise TypeError(f"Unsupported optimized deserialization {parameter!r}")

        return cls(parameter.name, _fixed_size_kinds[parameter_type], cls._flag_mask(parameter))

    def __init__(self, key: str, kind: int, mask: int) -> None:
        super().__init__(key, kind)
        self._mask = mask

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        if flags & self._mask:
            output[self._key] = _read_fixed_size(reader, self._kind)

        return 0


class BoolFieldDeserialization(AbstractDeserializationStep):
    __slots__ = ("_key",)

    _key: typing.Final[str]

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return parameter.parameter_flag is None and parameter.type == "Bool"

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "BoolFieldDeserialization":
        return cls(parameter.name)

    def __init__(self, key: str) -> None:
        self._key = key

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        output[self._key] = reader.read_i32() == _bool_true_cons_number_int
        return 0


class BytesFieldDeserialization(AbstractDeserializationStep):
    __slots__ = ("_key", "_size")

    _key: typing.Final[str]
    _size: typing.Final[int]

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return parameter.parameter_flag is None and parameter.type in _fixed_size_byte_sizes

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "BytesFieldDeserialization":
        parameter_type = parameter.type

        if parameter_type is None or parameter_type not in _fixed_size_byte_sizes:
            raise TypeError(f"Unsupported optimized deserialization {parameter!r}")

        return cls(parameter.name, _fixed_size_byte_sizes[parameter_type])

    def __init__(self, key: str, size: int) -> None:
        self._key = key
        self._size = size

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        output[self._key] = reader.read_binary(self._size)
        return 0


class FlagFieldDeserialization(AbstractDeserializationStep):
    __slots__ = ("_shift", "_true_parameters")

    _shift: typing.Final[int]
    _true_parameters: tuple[tuple[int, str], ...]

    @staticmethod
    def is_supported(parameter: "Parameter") -> bool:
        return parameter.is_flag or (parameter.type == "true" and parameter.parameter_flag is not None)

    @classmethod
    def from_parameter(cls, parameter: "Parameter", constructor: "Constructor") -> "FlagFieldDeserialization | None":
        if parameter.type == "true":
            return None

        shift = parameter.extended_flag_index

        if shift is None:
            raise TypeError(f"Unknown flag index for parameter `{parameter!r}`")

        true_parameters: tuple[tuple[int, str], ...] = tuple(
            (1 << p.parameter_flag.flag_number, p.name)
            for p in constructor.parameters
            if p.type == "true" and p.parameter_flag is not None and p.parameter_flag.flag_index == parameter.flag_index
        )

        return cls(shift, true_parameters)

    def __init__(self, shift: int, true_parameters: tuple[tuple[int, str], ...]) -> None:
        self._shift = shift
        self._true_parameters = true_parameters

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        flags = reader.read_u32()

        for (flag_mask, flag_name) in self._true_parameters:
            if flags & flag_mask:
                output[flag_name] = True

        return flags << self._shift


class RequiredParameterFieldDeserialization(AbstractDeserializationStep):
    __slots__ = ("_schema", "_parameter", "_key")

    _schema: typing.Final["Schema"]
    _parameter: typing.Final["Parameter"]
    _key: typing.Final[str]

    def __init__(self, schema: "Schema", parameter: "Parameter") -> None:
        self._schema = schema
        self._parameter = parameter
        self._key = parameter.name

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        output[self._key] = self._schema.deserialize(reader, self._parameter)
        return 0


class OptionalParameterFieldDeserialization(AbstractDeserializationStep):
    __slots__ = ("_schema", "_parameter", "_key", "_mask")

    _schema: typing.Final["Schema"]
    _parameter: typing.Final["Parameter"]
    _key: typing.Final[str]
    _mask: typing.Final[int]

    def __init__(self, schema: "Schema", parameter: "Parameter") -> None:
        parameter_flag = parameter.parameter_flag

        if parameter_flag is None:
            raise TypeError(f"Unsupported optional parameter flag {parameter!r}")

        self._schema = schema
        self._parameter = parameter
        self._key = parameter.name
        self._mask = parameter_flag.extended_flag_mask

    def deserialize_bare_data(self, reader: ByteReader, output: "TlBodyData", flags: int) -> int:
        if flags & self._mask:
            output[self._key] = self._schema.deserialize(reader, self._parameter)

        return 0


_OptimizedParameters = tuple[AbstractDeserializationStep, ...]

_field_deserializations: typing.Final[tuple[type[AbstractDeserializationStep], ...]] = (
    FlagFieldDeserialization,
    StructFieldDeserialization,
    FlaggedStructFieldDeserialization,
    BoolFieldDeserialization,
    BytesFieldDeserialization,
    StringFieldDeserialization,
    FlaggedStringFieldDeserialization,
    ByteStringFieldDeserialization,
    FlaggedByteStringFieldDeserialization,
)


class Constructor:
    __slots__ = (
        "schema",
        "ptype",
        "name",
        "number",
        "number_int",
        "parameters",
        "flags",
        "is_function",
        "ptype_parameter",
        "deserialization_optimized_parameters",
        "flags_check_table",
        "deserialization_default_dict",
        "flag_words_count",
        "is_gzip_container",
        "line"
    )

    schema: typing.Final[Schema]
    ptype: typing.Final[str | None]
    name: typing.Final[str]
    number: typing.Final[bytes | None]
    number_int: typing.Final["i32"]
    flags: typing.Final[frozenset[int] | None]
    parameters: typing.Final[tuple[Parameter, ...]]
    is_function: typing.Final[bool]
    ptype_parameter: typing.Final[Parameter | None]
    deserialization_optimized_parameters: typing.Final[_OptimizedParameters]
    flags_check_table: typing.Final[tuple[tuple[int, int, frozenset[str], int], ...]]
    deserialization_default_dict: typing.Final["TlBodyData"]
    flag_words_count: typing.Final[int]
    is_gzip_container: typing.Final[bool]
    line: typing.Final[str]

    def __init__(
            self,
            schema: Schema,
            ptype: str | None,
            name: str,
            number: bytes | None,
            parameters: tuple[Parameter, ...],
            flags: set[int] | None,
            is_function: bool,
            ptype_parameter: Parameter | None,
            line: str
    ):
        self.line = line
        self.schema = schema
        self.name = name
        self.number = number
        self.number_int = 0 if number is None else read_i32_le(number, 0)
        self.ptype = ptype
        self.parameters = parameters
        self.flags = None if flags is None else frozenset(flags)
        self.is_function = is_function
        self.ptype_parameter = ptype_parameter
        self.deserialization_optimized_parameters = self._optimize_parameters_for_deserialization(parameters)
        self.flags_check_table = self._generate_flags_check_table(parameters)
        self.deserialization_default_dict = self._generate_deserialization_default_dict(parameters, name)
        cons_flags = self.flags
        self.flag_words_count = 0 if cons_flags is None else max(cons_flags) + 1
        self.is_gzip_container = name == "gzip_packed"

    def boxed_buffer_match(self, buffer: bytes | bytearray | Value) -> bool:
        if isinstance(buffer, Value):
            return buffer.cons.name == self.name

        if self.number is None:
            raise TypeError(f"Tried to check a boxed value for a numberless constructor `{self!r}`")

        if len(buffer) < len(self.number):
            raise RuntimeError(f"EOF, buffer size {len(buffer)} < constructor number {len(self.number)}")

        return buffer.startswith(self.number)

    @staticmethod
    def _generate_deserialization_default_dict(parameters: tuple[Parameter, ...], name: str) -> "TlBodyData":
        elements: list[tuple[str, TlBodyDataValue]] = []
        elements.extend((p.name, None) for p in parameters if not p.is_flag)
        elements.append(("_cons", name))
        return dict(elements)

    @staticmethod
    def _generate_flags_check_table(parameters: tuple[Parameter, ...]) -> tuple[tuple[int, int, frozenset[str], int], ...]:
        table: dict[tuple[int, int], list[Parameter]] = dict()

        for parameter in parameters:
            parameter_flag = parameter.parameter_flag

            if parameter_flag is None:
                continue

            table.setdefault((parameter_flag.flag_number, parameter_flag.flag_index), []).append(parameter)

        groups: list[tuple[int, int, frozenset[str], int]] = []

        for (flag_number, flag_index), members in table.items():
            if len(members) < 2:
                continue

            group_id = len(groups)

            for parameter in members:
                parameter_flag = parameter.parameter_flag

                if parameter_flag is not None:
                    parameter_flag.group_id = group_id

            groups.append((flag_number, flag_index, frozenset(parameter.name for parameter in members), len(members)))

        return tuple(groups)

    def _optimize_parameters_for_deserialization(self, parameters: tuple[Parameter, ...]) -> _OptimizedParameters:
        schema = self.schema
        output: list[AbstractDeserializationStep] = []

        for parameter in parameters:
            for step_class in _field_deserializations:
                if step_class.is_supported(parameter):
                    step_instance = step_class.from_parameter(parameter, self)
                    if step_instance is not None:
                        output.append(step_instance)
                    break
            else:
                if parameter.required:
                    output.append(RequiredParameterFieldDeserialization(schema, parameter))
                else:
                    output.append(OptionalParameterFieldDeserialization(schema, parameter))

        return tuple(output)

    def __repr__(self) -> str:
        return self.line

    def _append_argument(self, writer: BytesWriter, parameter: Parameter, argument: typing.Union["TlBodyDataValue", "Value"]) -> None:
        if parameter.accepts_str and isinstance(argument, str):
            argument = argument.encode("utf-8")

        if parameter.accepts_dict and isinstance(argument, dict):
            cons_name = typing.cast(str, argument["_cons"])

            if parameter.is_primitive:
                argument = self.schema.serialize(parameter.is_boxed, cons_name, argument)
            else:
                nested = self.schema.constructors.get(cons_name, None)

                if nested is None:
                    raise NotImplementedError(f"Constructor `{cons_name}` not present in schema.")

                self.schema.typecheck_cons(parameter, nested)

                if parameter.is_boxed:
                    if nested.number is None:
                        raise RuntimeError(f"Tried to create a boxed value for a numberless constructor `{nested!r}`")

                    write_i32_le(writer, nested.number_int)

                nested._serialize_fields(writer, argument)
                return

        if parameter.is_primitive:
            serialize_kind = parameter.serialize_kind

            if serialize_kind < 0:
                raise TypeError(f"Unknown primitive type `{parameter!r}` `{argument!r}`")

            _write_primitive(writer, serialize_kind, argument)
        elif parameter.is_vector:
            if parameter.is_boxed:
                write_i32_le(writer, _vector_cons_number_int)

            if not isinstance(argument, list):
                raise TypeError(f"Expected a list for parameter `{parameter!r}` but found `{argument!r}`")

            write_i32_le(writer, len(argument))

            element_parameter = parameter.element_parameter

            if element_parameter is None:
                raise TypeError(f"Unknown vector parameter type {parameter:!r}")

            for element_argument in argument:
                self._append_argument(writer, element_parameter, element_argument)
        else:
            self.schema.typecheck(parameter, argument)

            if isinstance(argument, bytes):
                writer.write(argument)
            elif isinstance(argument, Value):
                writer.write(argument.get_flat_bytes())
            else:
                raise TypeError(f"For parameter {parameter!r} expected a serialized value, but found `{argument!r}`")

    def _serialize_fields(self, writer: BytesWriter, body: "TlBodyData") -> None:
        cons_flags = self.flags
        flag_values: list[int] | None = [0] * self.flag_words_count if cons_flags is not None else None
        flag_slots: list[tuple[int, int]] = [] if cons_flags is not None else _NO_FLAG_SLOTS

        groups = self.flags_check_table
        group_counts = [0] * len(groups) if groups else None

        for parameter in self.parameters:
            if parameter.is_flag:
                flag_index = parameter.flag_index

                if flag_index is None:
                    raise TypeError(f"Unknown flag index for parameter `{parameter!r}`")

                if flag_values is None:
                    raise TypeError(f"Tried to append flag to data for a flagless constructor `{self!r}`")

                flag_slots.append((len(writer), flag_index))
                write_i32_le(writer, 0)
                continue

            argument = body.get(parameter.name)

            if argument is None:
                if parameter.required:
                    raise TypeError(f"required `{parameter}` is missing in `{self.name}`")
                continue

            parameter_flag = parameter.parameter_flag

            if parameter_flag is not None:
                if flag_values is None:
                    raise TypeError(f"Tried to set flag for a flagless constructor `{self!r}`")

                flag_values[parameter_flag.flag_index] |= 1 << parameter_flag.flag_number

                group_id = parameter_flag.group_id

                if group_counts is not None and group_id >= 0:
                    group_counts[group_id] += 1

            direct_serialize_kind = parameter.direct_serialize_kind

            if direct_serialize_kind >= 0:
                _write_primitive(writer, direct_serialize_kind, argument)
            else:
                self._append_argument(writer, parameter, argument)

        if flag_values is not None:
            for slot, flag_index in flag_slots:
                flag_word = flag_values[flag_index]
                writer[slot] = flag_word & 0xFF
                writer[slot + 1] = (flag_word >> 8) & 0xFF
                writer[slot + 2] = (flag_word >> 16) & 0xFF
                writer[slot + 3] = (flag_word >> 24) & 0xFF

        if group_counts is not None:
            for group_id, (flag_number, flag_index, names, parameters_len) in enumerate(groups):
                present_len = group_counts[group_id]

                if present_len == 0 or present_len == parameters_len:
                    continue

                missing = {name for name in names if body.get(name) is None}

                raise TypeError(f"Missing parameters `{missing!r}` in `{self.name}` for flag number `{flag_number}` in flags index `{flag_index}`")

    def serialize(self, boxed: bool, body: "TlBodyData") -> Value:
        writer = BytesWriter()

        if boxed:
            if self.number is None:
                raise RuntimeError(f"Tried to create a boxed value for a numberless constructor `{self!r}`")

            write_i32_le(writer, self.number_int)

        self._serialize_fields(writer, body)
        return Value(self, boxed, writer.getvalue())

    def deserialize_boxed_data(self, reader: ByteReader) -> "TlBodyData":
        if self.number is None:
            raise TypeError(f"Constructor `{self!r}` is bare")

        number_int = self.number_int
        cons_number = reader.read_i32()

        if cons_number != number_int:
            raise TypeError(f"Constructor number `{_cons_number_hex(cons_number)}` mismatch {self!r}")

        return self.deserialize_bare_data(reader)

    def deserialize_bare_data(self, reader: ByteReader) -> "TlBodyData":
        fields = self.deserialization_default_dict.copy()
        extended_flags = 0

        for step in self.deserialization_optimized_parameters:
            extended_flags |= step.deserialize_bare_data(reader, fields, extended_flags)

        return fields


def extract_cons_from_tl_body(data: "TlBodyData") -> str:
    # noinspection PyUnnecessaryCast
    return typing.cast(str, data["_cons"])


def extract_cons_from_tl_body_opt(data: "TlBodyData") -> str | None:
    # noinspection PyUnnecessaryCast
    return typing.cast("str | None", data.get("_cons", None))


TlPrimitiveValue = typing.Union[
    bytes,
    str,
    int,
    float,
    None,
    Value
]

TlBodyDataValue = typing.Union[
    typing.Iterable["TlBodyDataValue"],
    "TlBodyData",
    TlPrimitiveValue
]

TlBodyData = typing.Dict[str, TlBodyDataValue]
