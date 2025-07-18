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


import abc
import binascii
import gzip
import operator
import random
import re
import secrets
import struct
import sys
import typing

from ll_mtproto.tl.bytereader import SyncByteReader
from ll_mtproto.tl.byteutils import GzipStreamReader, BinaryStreamReader

__all__ = (
    "Schema",
    "Parameter",
    "Constructor",
    "TlBodyData",
    "TlBodyDataValue",
    "pack_binary_string",
    "NativeByteReader",
    "Flags",
    "TlPrimitiveValue",
    "Value",
    "extract_cons_from_tl_body",
    "extract_cons_from_tl_body_opt"
)


class NativeByteReader(SyncByteReader):
    __slots__ = ("buffer", "offset")

    buffer: bytes
    offset: int

    def __init__(self, buffer: bytes):
        self.buffer = buffer
        self.offset = 0

    def __bool__(self) -> bool:
        return self.offset < len(self.buffer)

    def __call__(self, n: int) -> bytes:
        current_offset = self.offset

        if n == -1:
            n = len(self.buffer) - current_offset

        self.offset = result_end = current_offset + n

        return self.buffer[current_offset:result_end]


def _compile_cons_number(definition: bytes) -> bytes:
    n = binascii.crc32(definition)
    return n.to_bytes(4, "little", signed=False)


_boolTrueConsNumber = _compile_cons_number(b"boolTrue = Bool")
_boolFalseConsNumber = _compile_cons_number(b"boolFalse = Bool")
_vectorConsNumber = _compile_cons_number(b"vector t:Type # [ t ] = Vector t")

_decode_float_internal = typing.cast(typing.Callable[[bytes], tuple[float]], struct.Struct(b"<d").unpack)


def _decode_float(reader: SyncByteReader) -> float:
    return _decode_float_internal(reader(8))[0]


def _unpack_binary_string_header(bytereader: SyncByteReader) -> tuple[int, int]:
    str_len = ord(bytereader(1))

    if str_len > 0xFE:
        raise RuntimeError("Length equal to 255 in string")

    elif str_len == 0xFE:
        str_len = int.from_bytes(bytereader(3), "little", signed=False)
        padding_len = (-str_len) % 4

    else:
        padding_len = (3 - str_len) % 4

    return str_len, padding_len


def _unpack_binary_string_stream(bytereader: SyncByteReader) -> SyncByteReader:
    return BinaryStreamReader(bytereader, *_unpack_binary_string_header(bytereader))


def _unpack_long_binary_string_stream(bytereader: SyncByteReader) -> SyncByteReader:
    return BinaryStreamReader(bytereader, int.from_bytes(bytereader(4), "little", signed=False), 0)


def _unpack_binary_string(bytereader: SyncByteReader) -> bytes:
    str_len, padding_len = _unpack_binary_string_header(bytereader)
    string = bytereader(str_len)
    bytereader(padding_len)
    return string


def _pack_long_binary_string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "little", signed=False) + data


def _pack_long_binary_string_padded(data: bytes) -> bytes:
    padding_len = -len(data) & 15
    padding_len += 16 * (secrets.randbits(64) % 16)
    padding = random.randbytes(padding_len)
    header = (len(data) + len(padding)).to_bytes(4, "little", signed=False)
    return header + data + padding


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


_primitives = frozenset(
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

_fixed_size_primitives = frozenset(
    (
        "int",
        "uint",
        "long",
        "ulong",
        "double",
        "int128",
        "sha1",
        "int256"
    )
)

_schemaRE = re.compile(
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

_parameterRE = re.compile(
    r"^(?P<name>\w+):"
    r"(flags(?P<flag_index>\d+)?.(?P<flag_number>\d+)\?)?"
    r"(?P<type>"
    r"(?P<vector>((?P<bare_vector>vector)|(?P<boxed_vector>Vector))<)?"
    r"(?P<element_type>((?P<namespace>[a-zA-Z\d._]*)\.)?"
    r"((?P<bare>(?!gzip)[a-z][a-zA-Z\d._]*)|(?P<boxed>[A-Zg][a-zA-Z\d._]*)))"
    r"(?(vector)>)?)$"
)

_flagRE = re.compile(
    r"flags(?P<flag_index>\d+)?:#"
)

_layerRE = re.compile(
    r"^// LAYER (?P<layer>\d+)$"
)

_ptypeRE = re.compile(
    r"^(?P<is_vector>Vector<(?P<vector_element_type>[a-zA-Z\d._]*)>$)?(?P<element_type>[a-zA-Z\d._]*$)?"
)


class Schema:
    __slots__ = ("constructors", "types", "cons_numbers", "layer")

    constructors: typing.Final[dict[str, "Constructor"]]
    types: typing.Final[dict[str, set["Constructor"]]]
    cons_numbers: typing.Final[dict[bytes, "Constructor"]]
    layer: int | None

    def __init__(self) -> None:
        self.constructors = dict()
        self.types = dict()
        self.cons_numbers = dict()
        self.layer = None

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
    def _parse_token(regex: re.Pattern[str], s: str) -> None | dict[str, str]:
        match = regex.match(s)

        if not match:
            return None
        else:
            return {k: v for k, v in match.groupdict().items() if v is not None}

    def _parse_line(self, line: str, is_function: bool) -> None:
        cons_parsed = self._parse_token(_schemaRE, line)

        if not cons_parsed:
            raise SyntaxError(f"Error in schema: f{line}")

        if "cons" not in cons_parsed:
            layer_parsed = self._parse_token(_layerRE, line)

            if layer_parsed and "layer" in layer_parsed:
                self.layer = int(layer_parsed["layer"])

            return

        parameter_tokens: list[str] = cons_parsed["parameters"].split(" ")[1:]
        parameters = []

        if "number" in cons_parsed:
            con_number_int = int(cons_parsed["number"], base=16)
            cons_number = con_number_int.to_bytes(4, "little", signed=False)
        else:
            cons_number = None

        for parameter_token in parameter_tokens:
            parameter_parsed = self._parse_token(_parameterRE, parameter_token)

            if not parameter_parsed and parameter_token.endswith(":#"):
                flag_parsed = self._parse_token(_flagRE, parameter_token)

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
        ptype_parsed = None if ptype is None else self._parse_token(_ptypeRE, ptype)

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
            ptype_parameter=ptype_parameter
        )

        if (cons_name := cons.name) is not None:
            self.constructors[cons_name] = cons

        if (cons_number := cons.number) is not None:
            self.cons_numbers[cons_number] = cons

        if (cons_ptype := cons.ptype) is not None:
            self.types.setdefault(cons_ptype, set()).add(cons)

    def deserialize_primitive(self, reader: SyncByteReader, parameter: "Parameter") -> "TlBodyDataValue":
        match parameter.type:
            case "true":
                return True

            case "Bool":
                return reader(4) == _boolTrueConsNumber

            case "int":
                return int.from_bytes(reader(4), "little", signed=True)

            case "uint":
                return int.from_bytes(reader(4), "little", signed=False)

            case "long":
                return int.from_bytes(reader(8), "little", signed=True)

            case "ulong":
                return int.from_bytes(reader(8), "little", signed=False)

            case "int128":
                return reader(16)

            case "sha1":
                return reader(20)

            case "int256":
                return reader(32)

            case "double":
                return _decode_float(reader)

            case "string":
                return _unpack_binary_string(reader).decode()

            case "bytes":
                return _unpack_binary_string(reader)

            case "gzip":
                raise RuntimeError(f"must not directly deserialize gzip {reader!r} {parameter!r}")

            case "rawobject":
                return reader(-1)

            case "PaddedObject" | "PlainObject":
                return self.read_by_boxed_data(_unpack_long_binary_string_stream(reader))

            case "flags":
                raise TypeError(f"Cannot deserialize flags directly {parameter!r}")

            case _:
                raise TypeError(f"Unknown primitive type {parameter!r}")

    def typecheck(self, expected: "Parameter", found: typing.Union["TlBodyDataValue", "Value"]) -> None:
        def _debug_type_error_msg() -> str:
            return f"expected: {expected!r}, found: {found!r}"

        if not isinstance(found, Value):
            raise TypeError("not an object for nonbasic type", _debug_type_error_msg())

        if expected.type is None:
            raise TypeError("unsupported Parameter, type is None", _debug_type_error_msg())

        if expected.is_boxed:
            if found.cons not in self.types[expected.type]:
                raise TypeError("type mismatch", _debug_type_error_msg())

            if found.cons.number is None:
                raise TypeError("expected boxed, found bare", _debug_type_error_msg())
        else:
            if expected.type not in self.constructors:
                raise TypeError("expected boxed, found bare", _debug_type_error_msg())

            if found.cons.name != self.constructors[expected.type].name:
                raise TypeError("wrong constructor", _debug_type_error_msg())

    def deserialize(self, reader: SyncByteReader, parameter: "Parameter") -> "TlBodyDataValue":
        if parameter.is_primitive:
            return self.deserialize_primitive(reader, parameter)

        if parameter.is_boxed:
            cons_number = reader(4)

            if parameter.is_vector:
                if cons_number != _vectorConsNumber:
                    cons = self.cons_numbers.get(cons_number, None)

                    if cons is not None and cons.is_gzip_container:
                        return self.deserialize(GzipStreamReader(_unpack_binary_string_stream(reader)), parameter)

                    raise ValueError(f"Unknown constructor {hex(int.from_bytes(cons_number, 'little'))} for vector")

                element_parameter = parameter.element_parameter

                if element_parameter is None:
                    raise TypeError(f"Unknown vector parameter type {parameter!r}")

                return [
                    self.deserialize(reader, element_parameter)
                    for _ in range(int.from_bytes(reader(4), "little", signed=False))
                ]

            cons = self.cons_numbers.get(cons_number, None)

            if not cons:
                raise ValueError(f"Unknown constructor {hex(int.from_bytes(cons_number, 'little'))}")

            if cons.is_gzip_container:
                return self.deserialize(GzipStreamReader(_unpack_binary_string_stream(reader)), parameter)

            if parameter.type is not None and cons not in self.types[parameter.type] and cons.ptype:
                raise ValueError(f"type mismatch, constructor `{cons.name}` not in type `{parameter.type}`")

            return cons.deserialize_bare_data(reader)
        else:
            if parameter.is_vector:
                element_parameter = parameter.element_parameter

                if element_parameter is None:
                    raise TypeError(f"Unknown vector parameter type {parameter!r}")

                return [
                    self.deserialize(reader, element_parameter)
                    for _ in range(int.from_bytes(reader(4), "little", signed=False))
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

    def bare(self, body: "TlBodyData") -> "Value":
        return self.serialize(False, extract_cons_from_tl_body(body), body)

    def boxed_kwargs(self, *, _cons: str, **body: "TlBodyDataValue") -> "Value":
        return self.serialize(True, _cons, body)

    def boxed(self, body: "TlBodyData") -> "Value":
        return self.serialize(True, extract_cons_from_tl_body(body), body)

    def read_by_parameter(self, reader: SyncByteReader, parameter: "Parameter") -> "TlBodyDataValue":
        return self.deserialize(reader, parameter)

    def read_by_boxed_data(self, reader: SyncByteReader) -> "TlBodyData":
        cons_number = reader(4)
        cons = self.cons_numbers.get(cons_number, None)

        if cons is None:
            raise TypeError(f"Unknown constructor for constructor number {cons_number!r}")

        if cons.is_gzip_container:
            return self.read_by_boxed_data(GzipStreamReader(_unpack_binary_string_stream(reader)))

        return cons.deserialize_bare_data(reader)


class Flags:
    __slots__ = ("_flags",)

    _flags: int

    def __init__(self, initial_value: int = 0) -> None:
        self._flags = initial_value

    def add_flag(self, flag: int) -> None:
        self._flags |= 1 << flag

    def has_flag(self, flag: int) -> bool:
        return (self._flags & (1 << flag)) != 0

    def get_flat_bytes(self) -> bytes:
        return self._flags.to_bytes(4, "little", signed=False)

    @property
    def flags(self) -> int:
        return self._flags


class Value:
    __slots__ = ("cons", "boxed", "flags", "buffers")

    cons: typing.Final["Constructor"]
    boxed: typing.Final[bool]
    buffers: typing.Final[list["bytes | Flags"]]
    flags: typing.Final[dict[int, Flags] | None]

    def __init__(self, cons: "Constructor", boxed: bool = False):
        self.cons = cons
        self.boxed = boxed

        cons_number = self.cons.number

        if boxed and cons_number is None:
            raise RuntimeError(f"Tried to create a boxed value for a numberless constructor `{cons!r}`")

        self.flags = dict((flag_index, Flags()) for flag_index in cons.flags) if cons.flags else None
        self.buffers = [cons_number] if boxed and cons_number else []

    def set_flag(self, flag_number: int, flag_index: int) -> None:
        if (flags := self.flags) is None:
            raise TypeError(f"Tried to set flag for a flagless Value `{self.cons!r}`")
        else:
            flags[flag_index].add_flag(flag_number)

    def append_serializable_flag(self, flag_index: int) -> None:
        if (flags := self.flags) is None:
            raise TypeError(f"Tried to append flag to data for a flagless Value `{self.cons!r}`")
        else:
            self.buffers.append(flags[flag_index])

    def append_serialized_tl(self, data: typing.Union["Value", bytes]) -> None:
        if isinstance(data, bytes):
            self.buffers.append(data)
        else:
            self.buffers.extend(data.buffers)

    def __repr__(self) -> str:
        return f'{"boxed" if self.boxed else "bare"}({self.cons!r})'

    def get_flat_bytes(self) -> bytes:
        return b"".join(map(lambda k: k.get_flat_bytes() if isinstance(k, Flags) else k, self.buffers))


class ParameterFlag:
    __slots__ = (
        "flag_index",
        "flag_number",
        "extended_flag_mask"
    )

    flag_index: typing.Final[int]
    flag_number: typing.Final[int]
    extended_flag_mask: typing.Final[int]

    def __init__(self, flag_index: int, flag_number: int):
        self.flag_index = flag_index
        self.flag_number = flag_number
        self.extended_flag_mask = (1 << flag_number) << (max(0, flag_index - 1) * 31)

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
        "extended_flag_index"
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

    def __repr__(self) -> str:
        if self.parameter_flag is not None:
            return f"{self.name}:flags.{self.parameter_flag!r}?{self.type}"
        else:
            return f"{self.name}:{self.type}"


class AbstractSpecializedDeserialization(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def deserialize_bare_data(self, reader: SyncByteReader, output: "TlBodyData") -> None:
        raise NotImplementedError()


class FixedSizePrimitiveFastPathDeserialization(AbstractSpecializedDeserialization):
    __slots__ = ("_key", "_size", "_method")

    _key: str
    _size: int
    _method: typing.Callable[[bytes], "TlBodyDataValue"]

    def __init__(self, parameter: "Parameter"):
        self._key = parameter.name
        self._method, self._size = self._generate_method(parameter)

    @staticmethod
    def is_supported(p: Parameter) -> bool:
        if p.parameter_flag is not None:
            return False

        if p.type in _fixed_size_primitives:
            return True

        if p.type == "Bool":
            return True

        return False

    @staticmethod
    def _unpack_int(buf: bytes) -> int:
        return int.from_bytes(buf, "little", signed=True)

    @staticmethod
    def _unpack_uint(buf: bytes) -> int:
        return int.from_bytes(buf, "little", signed=False)

    @staticmethod
    def _unpack_double(buf: bytes) -> float:
        return _decode_float_internal(buf)[0]

    @staticmethod
    def _unpack_boolean(buf: bytes) -> bool:
        return buf == _boolTrueConsNumber

    @classmethod
    def _generate_method(cls, parameter: Parameter) -> tuple[typing.Callable[[bytes], "TlBodyDataValue"], int]:
        match parameter.type:
            case "int":
                return cls._unpack_int, 4

            case "uint":
                return cls._unpack_uint, 4

            case "long":
                return cls._unpack_int, 8

            case "ulong":
                return cls._unpack_uint, 8

            case "double":
                return cls._unpack_double, 8

            case "int128":
                return operator.itemgetter(0), 16

            case "sha1":
                return operator.itemgetter(0), 20

            case "int256":
                return operator.itemgetter(0), 32

            case "Bool":
                return cls._unpack_boolean, 4

            case _:
                raise TypeError(f"Unsupported optimized deserialization {parameter!r}")

    def deserialize_bare_data(self, reader: SyncByteReader, output: "TlBodyData") -> None:
        output[self._key] = self._method(reader(self._size))


class ContinuousFixedSizeBareValuesBatchDeserialization(AbstractSpecializedDeserialization):
    __slots__ = ("_unpack_fn", "_keys", "_size")

    _unpack_fn: typing.Final[typing.Callable[[bytes], typing.Iterable["TlBodyDataValue"]]]
    _keys: typing.Final[tuple[str, ...]]
    _size: typing.Final[int]

    def __init__(self, parameters: list[Parameter]):
        struct_fmt = struct.Struct("<" + "".join(map(self._generate_struct_fmt, parameters)))
        self._size = struct_fmt.size
        self._unpack_fn = struct_fmt.unpack
        self._keys = tuple(p.name for p in parameters)

    @staticmethod
    def _generate_struct_fmt(parameter: Parameter) -> str:
        match parameter.type:
            case "int":
                return "i"

            case "uint":
                return "I"

            case "long":
                return "q"

            case "ulong":
                return "Q"

            case "double":
                return "d"

            case "int128":
                return "16s"

            case "sha1":
                return "20s"

            case "int256":
                return "32s"

            case _:
                raise TypeError(f"Unsupported optimized deserialization {parameter!r}")

    def deserialize_bare_data(self, reader: SyncByteReader, output: "TlBodyData") -> None:
        output.update(zip(self._keys, self._unpack_fn(reader(self._size))))


_OPTIMIZED_PARAMETERS = tuple[Parameter | AbstractSpecializedDeserialization, ...]


class Constructor:
    __slots__ = (
        "schema",
        "ptype",
        "name",
        "number",
        "parameters",
        "flags",
        "is_function",
        "ptype_parameter",
        "deserialization_optimized_parameters",
        "flags_check_table",
        "deserialization_default_dict",
        "is_gzip_container"
    )

    schema: typing.Final[Schema]
    ptype: typing.Final[str | None]
    name: typing.Final[str]
    number: typing.Final[bytes | None]
    flags: typing.Final[frozenset[int] | None]
    parameters: typing.Final[tuple[Parameter, ...]]
    is_function: typing.Final[bool]
    ptype_parameter: typing.Final[Parameter | None]
    deserialization_optimized_parameters: typing.Final[_OPTIMIZED_PARAMETERS]
    flags_check_table: typing.Final[tuple[tuple[int, int, frozenset[str], int], ...]]
    deserialization_default_dict: typing.Final["TlBodyData"]
    is_gzip_container: typing.Final[bool]

    def __init__(
            self,
            schema: Schema,
            ptype: str | None,
            name: str,
            number: bytes | None,
            parameters: tuple[Parameter, ...],
            flags: set[int] | None,
            is_function: bool,
            ptype_parameter: Parameter | None
    ):
        self.schema = schema
        self.name = name
        self.number = number
        self.ptype = ptype
        self.parameters = parameters
        self.flags = None if flags is None else frozenset(flags)
        self.is_function = is_function
        self.ptype_parameter = ptype_parameter
        self.deserialization_optimized_parameters = self._optimize_parameters_for_deserialization(parameters)
        self.flags_check_table = self._generate_flags_check_table(parameters)
        self.deserialization_default_dict = self._generate_deserialization_default_dict(parameters, name)
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
        table: dict[tuple[int, int], set[str]] = dict()

        for parameter in parameters:
            if parameter.parameter_flag is None:
                continue

            table_key = (parameter.parameter_flag.flag_number, parameter.parameter_flag.flag_index)
            table.setdefault(table_key, set()).add(parameter.name)

        return tuple((flag_number, flags_index, frozenset(v), len(v)) for (flag_number, flags_index), v in table.items())

    @classmethod
    def _optimize_parameters_for_deserialization(cls, parameters: _OPTIMIZED_PARAMETERS) -> _OPTIMIZED_PARAMETERS:
        res = cls._sequential_fixed_size_primitives_optimization_for_deserialization(parameters)
        res = cls._fixed_size_primitives_fastpath_optimization_for_deserialization(res)
        return res

    @staticmethod
    def _fixed_size_primitives_fastpath_optimization_for_deserialization(parameters: _OPTIMIZED_PARAMETERS) -> _OPTIMIZED_PARAMETERS:
        output: list[Parameter | AbstractSpecializedDeserialization] = []

        for parameter in parameters:
            if isinstance(parameter, Parameter) and FixedSizePrimitiveFastPathDeserialization.is_supported(parameter):
                output.append(FixedSizePrimitiveFastPathDeserialization(parameter))
            else:
                output.append(parameter)

        return tuple(output)

    @staticmethod
    def _sequential_fixed_size_primitives_optimization_for_deserialization(parameters: _OPTIMIZED_PARAMETERS) -> _OPTIMIZED_PARAMETERS:
        sequential_optimizable_params: list[Parameter] = []
        output: list[Parameter | AbstractSpecializedDeserialization] = []

        def flush_sequential_optimizable_params() -> None:
            if len(sequential_optimizable_params) > 1:
                output.append(ContinuousFixedSizeBareValuesBatchDeserialization(sequential_optimizable_params))

            elif len(sequential_optimizable_params) == 1:
                output.append(sequential_optimizable_params[0])

            sequential_optimizable_params.clear()

        for parameter in parameters:
            if isinstance(parameter, Parameter) and parameter.type in _fixed_size_primitives and parameter.parameter_flag is None:
                sequential_optimizable_params.append(parameter)

            else:
                flush_sequential_optimizable_params()
                output.append(parameter)

        flush_sequential_optimizable_params()

        return tuple(output)

    def __repr__(self) -> str:
        return f"{self.name} {''.join(repr(p) for p in self.parameters)}= {self.ptype};"

    def _serialize_argument(self, data: Value, parameter: Parameter, argument: typing.Union["TlBodyDataValue", "Value"]) -> None:
        if isinstance(argument, str):
            argument = argument.encode("utf-8")

        if isinstance(argument, dict):
            argument = self.schema.serialize(parameter.is_boxed, extract_cons_from_tl_body(argument), argument)

        if argument is not None and (parameter_flag := parameter.parameter_flag) is not None:
            data.set_flag(parameter_flag.flag_number, parameter_flag.flag_index)

        if parameter.is_primitive:
            match argument:
                case bool():
                    match parameter.type:
                        case "true":
                            if not argument:
                                raise TypeError(f"Cannot serialize python False as `{parameter!r}`")

                        case "Bool":
                            if argument:
                                data.append_serialized_tl(_boolTrueConsNumber)
                            else:
                                data.append_serialized_tl(_boolFalseConsNumber)

                        case _:
                            raise TypeError(f"Cannot serialize python boolean `{argument!r}` as `{parameter!r}`")

                case int():
                    match parameter.type:
                        case "int":
                            data.append_serialized_tl(argument.to_bytes(4, "little", signed=True))

                        case "uint":
                            data.append_serialized_tl(argument.to_bytes(4, "little", signed=False))

                        case "long":
                            data.append_serialized_tl(argument.to_bytes(8, "little", signed=True))

                        case "ulong":
                            data.append_serialized_tl(argument.to_bytes(8, "little", signed=False))

                        case "double":
                            data.append_serialized_tl(struct.pack(b"<d", float(argument)))

                        case _:
                            raise TypeError(f"Cannot serialize python integer `{argument!r}` as `{parameter!r}`")

                case float():
                    match parameter.type:
                        case "double":
                            data.append_serialized_tl(struct.pack(b"<d", argument))

                        case _:
                            raise TypeError(f"Cannot serialize python float `{argument!r}` as `{parameter!r}`")

                case bytes():
                    match parameter.type:
                        case "rawobject":
                            data.append_serialized_tl(argument)

                        case "int128" | "sha1" | "int256":
                            match parameter.type:
                                case "int128":
                                    expected_size = 16

                                case "sha1":
                                    expected_size = 20

                                case "int256":
                                    expected_size = 32

                                case _:
                                    raise RuntimeError("unreachable!")

                            if len(argument) != expected_size:
                                raise TypeError(f"Cannot serialize python bytes `{argument!r}` as `{parameter!r}` because size is not `{expected_size}`")

                            data.append_serialized_tl(argument)

                        case "string" | "bytes":
                            data.append_serialized_tl(pack_binary_string(argument))

                        case _:
                            raise TypeError(f"Cannot serialize python bytes `{argument!r}` as `{parameter!r}`")

                case Value():
                    match parameter.type:
                        case "PlainObject":
                            data.append_serialized_tl(_pack_long_binary_string(argument.get_flat_bytes()))

                        case "rawobject":
                            data.append_serialized_tl(argument.get_flat_bytes())

                        case "PaddedObject":
                            data.append_serialized_tl(_pack_long_binary_string_padded(argument.get_flat_bytes()))

                        case "gzip":
                            data.append_serialized_tl(pack_binary_string(gzip.compress(argument.get_flat_bytes())))

                        case _:
                            raise TypeError(f"Cannot serialize Value `{argument!r}` as `{parameter!r}`")

                case _:
                    raise TypeError(f"Unknown primitive type `{parameter!r}` `{argument!r}`")
        else:
            if parameter.is_vector:
                if parameter.is_boxed:
                    data.append_serialized_tl(_vectorConsNumber)

                if not isinstance(argument, list):
                    raise TypeError(f"Expected a list for parameter `{parameter!r}` but found `{argument!r}`")

                data.append_serialized_tl(len(argument).to_bytes(4, "little", signed=False))

                element_parameter = parameter.element_parameter

                if element_parameter is None:
                    raise TypeError(f"Unknown vector parameter type {parameter:!r}")

                for element_argument in argument:
                    self._serialize_argument(data, element_parameter, element_argument)

            else:
                self.schema.typecheck(parameter, argument)

                if not isinstance(argument, (bytes, Value)):
                    raise TypeError(f"For parameter {parameter!r} expected a serialized value, but found `{argument!r}`")

                data.append_serialized_tl(argument)

    def serialize(self, boxed: bool, body: "TlBodyData") -> Value:
        for flag_number, flags_index, parameters, parameters_len in self.flags_check_table:
            present_len = sum(body.get(p) is not None for p in parameters)

            if present_len == 0 or present_len == parameters_len:
                continue

            missing = parameters - {p for p in parameters if body.get(p) is not None}

            raise TypeError(f"Missing parameters `{missing!r}` in `{self.name}` for flag number `{flag_number}` in flags index `{flags_index}`")

        data = Value(self, boxed=boxed)

        for parameter in self.parameters:
            if parameter.is_flag:
                flag_index = parameter.flag_index

                if flag_index is None:
                    raise TypeError(f"Unknown flag index for parameter `{parameter!r}`")

                data.append_serializable_flag(flag_index)

            else:
                argument = body.get(parameter.name)

                if argument is None:
                    if parameter.required:
                        raise TypeError(f"required `{parameter}` is missing in `{self.name}`")
                else:
                    self._serialize_argument(data, parameter, argument)

        return data

    def deserialize_boxed_data(self, reader: SyncByteReader) -> "TlBodyData":
        if self.number is None:
            raise TypeError(f"Constructor `{self!r}` is bare")

        cons_number = reader(4)

        if cons_number != self.number:
            raise TypeError(f"Constructor number `{cons_number!r}` mismatch {self!r}")

        return self.deserialize_bare_data(reader)

    def deserialize_bare_data(self, reader: SyncByteReader) -> "TlBodyData":
        fields = self.deserialization_default_dict.copy()
        extended_flags: int = 0

        for parameter in self.deserialization_optimized_parameters:
            if isinstance(parameter, AbstractSpecializedDeserialization):
                parameter.deserialize_bare_data(reader, fields)
            else:
                if parameter.is_flag:
                    extended_flag_index = parameter.extended_flag_index

                    if extended_flag_index is None:
                        raise TypeError(f"Unknown flag index for parameter `{parameter!r}`")

                    extended_flags |= (int.from_bytes(reader(4), "little", signed=False) << extended_flag_index)

                elif parameter.required:
                    fields[parameter.name] = self.schema.deserialize(reader, parameter)

                else:
                    parameter_flag = parameter.parameter_flag

                    if parameter_flag is None:
                        raise TypeError(f"Unknown flag for parameter `{parameter!r}`")

                    if extended_flags & parameter_flag.extended_flag_mask:
                        fields[parameter.name] = self.schema.deserialize(reader, parameter)

        return fields


def extract_cons_from_tl_body(data: "TlBodyData") -> str:
    return typing.cast(str, data["_cons"])


def extract_cons_from_tl_body_opt(data: "TlBodyData") -> str | None:
    return typing.cast(str | None, data.get("_cons", None))


TlPrimitiveValue = typing.Union[
    bytes,
    str,
    int,
    float,
    None,
    Value
]

TlBodyDataValue = typing.Union[
    typing.Iterable['TlBodyDataValue'],
    'TlBodyData',
    TlPrimitiveValue
]

TlBodyData = typing.Dict[str, TlBodyDataValue]
