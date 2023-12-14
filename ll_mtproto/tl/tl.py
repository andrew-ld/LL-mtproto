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


import binascii
import functools
import gzip
import re
import struct
import sys
import typing

from ll_mtproto.tl.byteutils import (
    pack_binary_string,
    unpack_binary_string,
    pack_long_binary_string,
    unpack_long_binary_string_stream,
    GzipStreamReader,
    pack_long_binary_string_padded, unpack_binary_string_stream
)
from ll_mtproto.typed import SyncByteReader

__all__ = ("Schema", "Value", "Parameter", "Constructor", "TlBodyData", "TlBodyDataValue")


@functools.lru_cache()
def _compile_cons_number(definition: bytes) -> bytes:
    n = binascii.crc32(definition)
    return n.to_bytes(4, "little", signed=False)


def _pack_flags(flags: set[int]) -> bytes:
    n = 0

    for flag in flags:
        n |= 1 << int(flag)

    return n.to_bytes(4, "little", signed=False)


@functools.lru_cache()
def _unpack_flags(n: int) -> set[int]:
    i = 0
    flags = set()

    while n > 0:
        if n % 2 == 1:
            flags.add(i)

        i += 1
        n >>= 1

    return flags

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
        "object",
        "padded_object",
        "bytesobject",
        "flags",
        "encrypted",
        "gzip",
    )
)

_optimizable_params_types = frozenset(
    (
        "int",
        "uint",
        "long",
        "ulong"
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
    r"(flags(?P<flag_name>\d+)?.(?P<flag_number>\d+)\?)?"
    r"(?P<type>"
    r"(?P<vector>((?P<bare_vector>vector)|(?P<boxed_vector>Vector))<)?"
    r"(?P<element_type>((?P<namespace>[a-zA-Z\d._]*)\.)?"
    r"((?P<bare>[a-z][a-zA-Z\d._]*)|(?P<boxed>[A-Z][a-zA-Z\d._]*)))"
    r"(?(vector)>)?)$"
)

_flagRE = re.compile(
    r"flags(?P<flag_name>\d+)?:#"
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
    layer: int

    def __init__(self) -> None:
        self.constructors = dict()
        self.types = dict()
        self.cons_numbers = dict()

    def __repr__(self) -> str:
        return "\n".join(repr(cons) for cons in self.constructors.values())

    def extend_from_raw_schema(self, schema: str) -> None:
        is_function = False

        for schema_line in schema.split("\n"):
            if schema_line == "---functions---":
                is_function = True

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

            if parameter_parsed and parameter_parsed.get("name", None) == "self":
                parameter_parsed["name"] = "_self"

            if not parameter_parsed and parameter_token.endswith(":#"):
                flag_parsed = self._parse_token(_flagRE, parameter_token)

                if flag_parsed is None:
                    raise SyntaxError(f"Error in flag: `{parameter_token}`")

                flag_name = int(flag_parsed["flag_name"]) if "flag_name" in flag_parsed else 0
            else:
                flag_parsed = None
                flag_name = None

            if parameter_parsed is None and flag_parsed is None:
                raise SyntaxError(f"Error in parameter `{parameter_token}`")

            if parameter_parsed:
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
                    flag_name=int(parameter_parsed["flag_name"])
                    if "flag_name" in parameter_parsed
                    else 0,
                    is_vector=is_vector,
                    is_boxed="boxed_vector" in parameter_parsed
                    if is_vector
                    else "boxed" in parameter_parsed,
                    element_parameter=element_parameter,
                )
            else:
                parameter = Parameter(
                    is_boxed=False,
                    is_flag=True,
                    is_vector=False,
                    pname=parameter_token,
                    ptype="flags",
                    flag_name=flag_name
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
            parameters=parameters,
            flags=set(p.flag_name for p in parameters if p.is_flag and p.flag_name is not None) or None,
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
                return typing.cast(float, struct.unpack(b"<d", reader(8))[0])

            case "string":
                return unpack_binary_string(reader).decode()

            case "bytes":
                return unpack_binary_string(reader)

            case "gzip":
                raise RuntimeError(f"must not directly deserialize gzip {reader!r} {parameter!r}")

            case "rawobject":
                return reader(-1)

            case "object" | "padded_object":
                return self.read_by_boxed_data(unpack_long_binary_string_stream(reader))

            case "bytesobject":
                return reader(int.from_bytes(reader(4), "little", signed=False))

            case "flags":
                return _unpack_flags(int.from_bytes(reader(4), "little", signed=False))

            case _:
                raise TypeError(f"Unknown primitive type {parameter!r}")


    def typecheck(self, parameter: "Parameter", argument: "Value") -> None:
        def _debug_type_error_msg() -> str:
            return f"expected: {parameter!r}, found: {argument!r}"

        if not isinstance(argument, Value):
            raise TypeError("not an object for nonbasic type", _debug_type_error_msg())

        if parameter.is_boxed:
            if parameter.type not in self.types:
                raise TypeError("unknown type", _debug_type_error_msg())

            if argument.cons not in self.types[parameter.type]:
                raise TypeError("type mismatch", _debug_type_error_msg())

            if not argument.boxed:
                raise TypeError("expected boxed, found bare", _debug_type_error_msg())

        else:
            if parameter.type not in self.constructors:
                raise TypeError("expected boxed, found bare", _debug_type_error_msg())

            if argument.cons != self.constructors[parameter.type]:
                raise TypeError("wrong constructor", _debug_type_error_msg())

            if argument.boxed:
                raise TypeError("expected bare, found boxed", _debug_type_error_msg())

    def deserialize(self, reader: SyncByteReader, parameter: "Parameter") -> "TlBodyDataValue":
        if parameter.is_primitive:
            return self.deserialize_primitive(reader, parameter)

        if parameter.is_boxed:
            cons_number = reader(4)

            if parameter.is_vector:
                if cons_number != _compile_cons_number(b"vector t:Type # [ t ] = Vector t"):
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

            if cons.name == "gzip_packed":
                return self.deserialize(GzipStreamReader(unpack_binary_string_stream(reader)), parameter)

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
        return self.serialize(False, typing.cast(str, body["_cons"]), body)

    def boxed_kwargs(self, *, _cons: str, **body: "TlBodyDataValue") -> "Value":
        return self.serialize(True, _cons, body)

    def boxed(self, body: "TlBodyData") -> "Value":
        return self.serialize(True, typing.cast(str, body["_cons"]), body)

    def read_by_parameter(self, reader: SyncByteReader, parameter: "Parameter") -> "TlBodyDataValue":
        return self.deserialize(reader, parameter)

    def read_by_boxed_data(self, reader: SyncByteReader) -> "TlBodyData":
        cons_number = reader(4)
        cons = self.cons_numbers.get(cons_number, None)

        if cons is None:
            raise TypeError(f"Unknown constructor for constructor number {cons_number!r}")

        return cons.deserialize_bare_data(reader)


class Flags:
    __slots__ = ("_flags",)

    _flags: typing.Final[set[int]]

    def __init__(self) -> None:
        self._flags = set()

    def add_flag(self, flag: int) -> None:
        self._flags.add(flag)

    def get_flat_bytes(self) -> bytes:
        return _pack_flags(self._flags)


class Value:
    __slots__ = ("cons", "boxed", "_flags", "_buffers")

    cons: typing.Final["Constructor"]
    boxed: typing.Final[bool]
    _flags: dict[int, Flags] | None
    _buffers: typing.Final[list["bytes | Flags"]]

    def __init__(self, cons: "Constructor", boxed: bool = False):
        self.cons = cons
        self.boxed = boxed

        if self.boxed and self.cons.number is None:
            raise RuntimeError(f"Tried to create a boxed value for a numberless constructor `{cons!r}`")

        if cons.flags:
            self._flags = dict((flag_name, Flags()) for flag_name in cons.flags)
        else:
            self._flags = None

        self._buffers = []

    def set_flag(self, flag_number: int, flag_name: int) -> None:
        if (flags := self._flags) is None:
            raise TypeError(f"Tried to set flag for a flagless Value `{self.cons!r}`")
        else:
            flags[flag_name].add_flag(flag_number)

    def append_serializable_flag(self, flag_name: int) -> None:
        if (flags := self._flags) is None:
            raise TypeError(f"Tried to append flag to data for a flagless Value `{self.cons!r}`")
        else:
            self._buffers.append(flags[flag_name])

    def append_serialized_tl(self, data: typing.Union["Value", bytes]) -> None:
        self._buffers.append(data if isinstance(data, bytes) else data.get_flat_bytes())

    def __repr__(self) -> str:
        return f'{"boxed" if self.boxed else "bare"}({self.cons!r})'

    def get_flat_bytes(self) -> bytes:
        if self.boxed:
            cons_number = self.cons.number

            if cons_number is None:
                raise TypeError(f"Tried to prefix cons number to data for a numberless Constructor `{self.cons!r}`")

            prefix = cons_number
        else:
            prefix = b""

        return b"".join(map(lambda k: k.get_flat_bytes() if isinstance(k, Flags) else k, (prefix, *self._buffers)))


class Parameter:
    __slots__ = ("name", "type", "flag_number", "is_vector", "is_boxed", "element_parameter", "is_flag", "flag_name", "is_primitive")

    name: typing.Final[str]
    type: typing.Final[str | None]
    flag_number: typing.Final[int | None]
    flag_name: typing.Final[int | None]
    is_vector: typing.Final[bool]
    is_boxed: typing.Final[bool]
    is_flag: typing.Final[bool]
    element_parameter: typing.Final["Parameter | None"]
    is_primitive: typing.Final[bool]

    def __init__(
            self,
            pname: str,
            ptype: str | None,
            is_boxed: bool,
            flag_number: int | None = None,
            is_vector: bool = False,
            is_flag: bool = False,
            flag_name: int | None = None,
            element_parameter: "Parameter | None" = None,
    ):
        self.name = pname
        self.type = ptype
        self.flag_number = flag_number
        self.is_vector = is_vector
        self.is_boxed = is_boxed
        self.element_parameter = element_parameter
        self.is_flag = is_flag
        self.flag_name = flag_name
        self.is_primitive = ptype in _primitives

    def __repr__(self) -> str:
        if self.flag_number is not None:
            return f"{self.name}:flags.{self.flag_number:d}?{self.type}"
        else:
            return f"{self.name}:{self.type}"


class OptimizedDeserializationParameters:
    __slots__ = ( "_struct", "_keys")

    _struct: typing.Final[struct.Struct]
    _keys: typing.Final[list[str]]

    def __init__(self, parameters: list[Parameter]):
        self._struct = struct.Struct("<" + "".join(map(self._generate_struct_fmt, parameters)))
        self._keys = [p.name for p in parameters]

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

            case _:
                raise TypeError(f"Unsupported optimized deserialization {parameter!r}")

    def deserialize_bare_data(self, reader: SyncByteReader) -> typing.Iterable[tuple[str, "TlBodyDataValue"]]:
        return zip(self._keys, self._struct.unpack(reader(self._struct.size)))


class Constructor:
    __slots__ = ("schema", "ptype", "name", "number", "parameters", "flags", "is_function", "ptype_parameter", "optimized_parameters_for_deserialization")

    schema: typing.Final[Schema]
    ptype: typing.Final[str | None]
    name: typing.Final[str]
    number: typing.Final[bytes | None]
    flags: typing.Final[set[int] | None]
    parameters: typing.Final[list[Parameter]]
    is_function: typing.Final[bool]
    ptype_parameter: typing.Final[Parameter | None]
    optimized_parameters_for_deserialization: typing.Final[list[Parameter | OptimizedDeserializationParameters]]

    def __init__(
            self,
            schema: Schema,
            ptype: str | None,
            name: str,
            number: bytes | None,
            parameters: list[Parameter],
            flags: set[int] | None,
            is_function: bool,
            ptype_parameter: Parameter | None
    ):
        self.schema = schema
        self.name = name
        self.number = number
        self.ptype = ptype
        self.parameters = parameters
        self.flags = flags
        self.is_function = is_function
        self.ptype_parameter = ptype_parameter
        self.optimized_parameters_for_deserialization = self._optimize_parameters_for_deserialization(parameters)

    @staticmethod
    def _optimize_parameters_for_deserialization(parameters: list[Parameter]) -> list[Parameter | OptimizedDeserializationParameters]:
        sequential_optimizable_params: list[Parameter] = []
        output: list[Parameter | OptimizedDeserializationParameters] = []

        def flush_sequential_optimizable_params() -> None:
            if len(sequential_optimizable_params) > 1:
                output.append(OptimizedDeserializationParameters(sequential_optimizable_params))

            elif len(sequential_optimizable_params) == 1:
                output.append(sequential_optimizable_params[0])

            sequential_optimizable_params.clear()

        for parameter in parameters:
            if parameter.type in _optimizable_params_types and parameter.flag_number is None:
                sequential_optimizable_params.append(parameter)

            else:
                flush_sequential_optimizable_params()
                output.append(parameter)

        flush_sequential_optimizable_params()

        return output

    def __repr__(self) -> str:
        return f"{self.name} {''.join(repr(p) for p in self.parameters)}= {self.ptype};"

    def _serialize_argument(self, data: Value, parameter: Parameter, argument: typing.Any) -> None:
        if isinstance(argument, str):
            argument = argument.encode("utf-8")

        if argument is False:
            argument = {"_cons": "boolFalse"}

        if argument is True and parameter.type == "true":
            argument = {"_cons": "true"}

        if argument is True and parameter.type == "Bool":
            argument = {"_cons": "boolTrue"}

        if isinstance(argument, dict):
            argument = self.schema.serialize(parameter.is_boxed, typing.cast(str, argument["_cons"]), argument)

        if argument is not None and parameter.flag_number is not None and parameter.flag_name is not None:
            data.set_flag(parameter.flag_number, parameter.flag_name)

        if parameter.is_primitive:
            match parameter.type:
                case "int":
                    data.append_serialized_tl(int(argument).to_bytes(4, "little", signed=True))

                case "uint":
                    data.append_serialized_tl(int(argument).to_bytes(4, "little", signed=False))

                case "long":
                    data.append_serialized_tl(int(argument).to_bytes(8, "little", signed=True))

                case "ulong":
                    data.append_serialized_tl(int(argument).to_bytes(8, "little", signed=False))

                case "int128":
                    data.append_serialized_tl(argument)

                case "sha1":
                    data.append_serialized_tl(argument)

                case "int256":
                    data.append_serialized_tl(argument)

                case "double":
                    data.append_serialized_tl(struct.pack(b"<d", float(argument)))

                case "string":
                    data.append_serialized_tl(pack_binary_string(argument))

                case "bytes":
                    data.append_serialized_tl(pack_binary_string(argument))

                case "object":
                    data.append_serialized_tl(pack_long_binary_string(argument.get_flat_bytes()))

                case "padded_object":
                    data.append_serialized_tl(pack_long_binary_string_padded(argument.get_flat_bytes()))

                case "rawobject":
                    data.append_serialized_tl(argument)

                case "encrypted":
                    data.append_serialized_tl(argument)

                case "gzip":
                    data.append_serialized_tl(pack_binary_string(gzip.compress(argument.get_flat_bytes())))

                case _:
                    raise TypeError(f"Unknown primitive type `{parameter!r}`")

        else:
            if parameter.is_vector:
                if parameter.is_boxed:
                    data.append_serialized_tl(_compile_cons_number(b"vector t:Type # [ t ] = Vector t"))

                data.append_serialized_tl(len(argument).to_bytes(4, "little", signed=False))

                element_parameter = parameter.element_parameter

                if element_parameter is None:
                    raise TypeError(f"Unknown vector parameter type {parameter:!r}")

                for element_argument in argument:
                    self._serialize_argument(data, element_parameter, element_argument)

            else:
                self.schema.typecheck(parameter, argument)
                data.append_serialized_tl(argument)

    def serialize(self, boxed: bool, body: "TlBodyData") -> Value:
        data = Value(self, boxed=boxed)

        for parameter in self.parameters:
            if parameter.is_flag:
                flag_name = parameter.flag_name

                if flag_name is None:
                    raise TypeError(f"Unknown flag name for parameter `{parameter!r}`")

                data.append_serializable_flag(flag_name)

            elif parameter.name not in body:
                if parameter.flag_number is None:
                    raise TypeError(f"required `{parameter}` not found in `{self.name}`")

            else:
                argument = body[parameter.name]

                if parameter.flag_number is None and argument is None:
                    raise TypeError(f"required `{parameter}` is None in `{self.name}`")

                if argument is None and parameter.flag_name is not None:
                    continue

                self._serialize_argument(data, parameter, argument)

        return data

    def deserialize_boxed_data(self, reader: SyncByteReader) -> "TlBodyData":
        if self.number is None:
            raise TypeError(f"constructor `{self!r}` is bare")

        cons_number = reader(4)

        if cons_number != self.number:
            raise TypeError(f"impossible deserialization, constructor number `{cons_number!r}` mismatch {self!r}")

        return self.deserialize_bare_data(reader)

    def deserialize_bare_data(self, reader: SyncByteReader) -> "TlBodyData":
        fields: TlBodyData = {"_cons": self.name}

        if self.flags is not None:
            flags: dict[int, set[int]] = {}

            for parameter in self.optimized_parameters_for_deserialization:
                if isinstance(parameter, OptimizedDeserializationParameters):
                    fields.update(parameter.deserialize_bare_data(reader))
                else:
                    if parameter.is_flag:
                        flag_name = parameter.flag_name

                        if flag_name is None:
                            raise TypeError(f"Unknown flag name for parameter `{parameter!r}`")

                        flags[flag_name] = _unpack_flags(int.from_bytes(reader(4), "little", signed=False))

                    elif parameter.flag_number is not None:
                        flag_name = parameter.flag_name

                        if flag_name is None:
                            raise TypeError(f"Unknown flag name for parameter `{parameter!r}`")

                        if parameter.flag_number in flags[flag_name]:
                            fields[parameter.name] = self.schema.deserialize(reader, parameter)
                        else:
                            fields[parameter.name] = None

                    else:
                        fields[parameter.name] = self.schema.deserialize(reader, parameter)
        else:
            for parameter in self.optimized_parameters_for_deserialization:
                if isinstance(parameter, OptimizedDeserializationParameters):
                    fields.update(parameter.deserialize_bare_data(reader))
                else:
                    fields[parameter.name] = self.schema.deserialize(reader, parameter)

        return fields


TlBodyDataValue = typing.Union[
    bytes,
    str,
    int,
    float,
    typing.Iterable['TlBodyDataValue'],
    typing.Dict[str, 'TlBodyDataValue'],
    'TlBodyData',
    None,
    Value
]

TlBodyData = typing.Dict[str, TlBodyDataValue]
