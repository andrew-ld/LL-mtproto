import binascii
import functools
import gzip
import re
import struct
import sys
import typing

from .byteutils import (
    long_hex,
    pack_binary_string,
    unpack_binary_string,
    pack_long_binary_string,
    unpack_binary_string_stream,
    unpack_long_binary_string_stream,
    GzipStreamReader,
    pack_long_binary_string_padded,
)
from ..typed import TlMessageBody, SyncByteReader

__all__ = ("Schema", "Value", "Structure", "Parameter", "Constructor",)


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
def unpack_flags(n: int) -> set[int]:
    i = 0
    flags = set()

    while n > 0:
        if n % 2 == 1:
            flags.add(i)

        i += 1
        n >>= 1

    return flags


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


class Schema:
    __slots__ = ("constructors", "types", "cons_numbers", "layer")

    constructors: dict[str, "Constructor"]
    types: dict[str, set]
    cons_numbers: dict[bytes, "Constructor"]
    layer: int

    def __init__(self, parsable_schema: str):
        self.constructors = dict()
        self.types = dict()
        self.cons_numbers = dict()
        self._parse_file(parsable_schema)

    def __repr__(self):
        return "\n".join(repr(cons) for cons in self.constructors.values())

    def _parse_file(self, schema: str):
        for schema_line in schema.split("\n"):
            self._parse_line(schema_line)

    @staticmethod
    def _parse_token(regex, s: str) -> None | dict[str, str]:
        match = regex.match(s)

        if not match:
            return None
        else:
            return {k: v for k, v in match.groupdict().items() if v is not None}

    def _parse_line(self, line: str):
        cons_parsed = self._parse_token(_schemaRE, line)

        if not cons_parsed:
            raise SyntaxError("Error in schema: `%s`" % line)

        if "cons" not in cons_parsed:
            layer_parsed = self._parse_token(_layerRE, line)

            if layer_parsed and "layer" in layer_parsed:
                self.layer = int(layer_parsed["layer"])

            return

        parameter_tokens: list[str] = cons_parsed["parameters"].split(" ")[1:]

        cons_parsed["cons"] = sys.intern(cons_parsed["cons"])
        cons_parsed["name"] = sys.intern(cons_parsed["name"])

        if "xtype" not in cons_parsed:
            cons_parsed["type"] = sys.intern(cons_parsed["type"])

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
                flag_name = int(flag_parsed["flag_name"]) if "flag_name" in flag_parsed else 0
            else:
                flag_parsed = None
                flag_name = None

            if parameter_parsed is None and flag_parsed is None:
                raise SyntaxError(f"Error in parameter `{parameter_token}`")

            if parameter_parsed:
                parameter_parsed["name"] = sys.intern(parameter_parsed["name"])
                parameter_parsed["type"] = sys.intern(parameter_parsed["type"])
                parameter_parsed["element_type"] = sys.intern(parameter_parsed["element_type"])
                is_vector = "vector" in parameter_parsed
            else:
                is_vector = False

            if is_vector:
                element_parameter = Parameter(
                    pname="<element of vector `%s`>" % parameter_parsed["name"],
                    ptype=parameter_parsed["element_type"],
                    is_boxed="boxed" in parameter_parsed,
                )
            else:
                element_parameter = None

            if parameter_parsed:
                parameter = Parameter(
                    pname=parameter_parsed["name"],
                    ptype=parameter_parsed["type"],
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

        cons = Constructor(
            schema=self,
            ptype=None if "xtype" in cons_parsed else cons_parsed["type"],
            name=cons_parsed["name"],
            number=cons_number,
            parameters=parameters,
            flags=set(p.flag_name for p in parameters if p.is_flag) or None
        )

        self.constructors[cons.name] = cons
        self.cons_numbers[cons.number] = cons
        self.types.setdefault(cons.type, set()).add(cons)

    @staticmethod
    def _debug_type_error_msg(parameter: "Parameter", argument: "Value") -> str:
        return f"expected: {parameter!r}, found: {argument!r}"

    def typecheck(self, parameter: "Parameter", argument: "Value"):
        if not isinstance(argument, Value):
            raise TypeError("not an object for nonbasic type", self._debug_type_error_msg(parameter, argument))

        if parameter.is_boxed:
            if parameter.type not in self.types:
                raise TypeError("unknown type", self._debug_type_error_msg(parameter, argument))

            if argument.cons not in self.types[parameter.type]:
                raise TypeError("type mismatch", self._debug_type_error_msg(parameter, argument))

            if not argument.boxed:
                raise TypeError("expected boxed, found bare", self._debug_type_error_msg(parameter, argument))

        else:
            if parameter.type not in self.constructors:
                raise TypeError("expected boxed, found bare", self._debug_type_error_msg(parameter, argument))

            if argument.cons != self.constructors[parameter.type]:
                raise TypeError("wrong constructor", self._debug_type_error_msg(parameter, argument))

            if argument.boxed:
                raise TypeError("expected bare, found boxed", self._debug_type_error_msg(parameter, argument))

    def deserialize(self, bytereader: SyncByteReader, parameter: "Parameter") -> TlMessageBody:
        if parameter.is_boxed:
            if parameter.type is not None and parameter.type not in self.types:
                raise ValueError(f"Unknown type `{parameter.type}`")

            cons_number = bytereader(4)

            if cons_number == _compile_cons_number(b"vector t:Type # [ t ] = Vector t"):
                return [
                    self.deserialize(bytereader, parameter)
                    for _ in range(int.from_bytes(bytereader(4), "little", signed=False))
                ]

            cons = self.cons_numbers.get(cons_number, None)

            if not cons:
                raise ValueError(f"Unknown constructor {hex(int.from_bytes(cons_number, 'little'))}")

            if parameter.type is not None and cons not in self.types[parameter.type]:
                raise ValueError(f"type mismatch, constructor `{cons.name}` not in type `{parameter.type}`")
        else:
            cons = self.constructors.get(parameter.type, None)

            if not cons:
                raise ValueError(f"Unknown constructor in parameter `{parameter!r}`")

        return cons.deserialize_bare_data(bytereader)

    def serialize(self, boxed: bool, _cons: str, **kwargs) -> "Value":
        if cons := self.constructors.get(_cons, False):
            return typing.cast(Constructor, cons).serialize(boxed=boxed, **kwargs)
        else:
            raise NotImplementedError(f"Constructor `{_cons}` not present in schema.")

    def bare(self, **kwargs) -> "Value":
        return self.serialize(boxed=False, **kwargs)

    def boxed(self, **kwargs) -> "Value":
        return self.serialize(boxed=True, **kwargs)

    def read(self, bytereader: SyncByteReader, is_boxed=True, parameter_type=None) -> "Structure":
        parameter = Parameter("", parameter_type, is_boxed=is_boxed)
        return self.deserialize(bytereader, parameter)


class Flags:
    __slots__ = ("_flags",)

    _flags: set[int]

    def __init__(self):
        self._flags = set()

    def add_flag(self, flag: int):
        self._flags.add(flag)

    def get_flat_bytes(self) -> bytes:
        return _pack_flags(self._flags)


class Value:
    __slots__ = ("cons", "boxed", "_flags", "_data")

    cons: "Constructor"
    boxed: bool
    _flags: dict[int, Flags] | None
    _data: list["bytearray | Flags"]

    def __init__(self, cons: "Constructor", boxed: bool = False):
        self.cons = cons
        self.boxed = boxed

        if self.boxed and self.cons.number is None:
            raise RuntimeError(f"Tried to create a boxed value for a numberless constructor `{cons!r}`")

        if cons.flags:
            self._flags = dict((flag_name, Flags()) for flag_name in cons.flags)
        else:
            self._flags = None

        self._data = [bytearray()]

    def set_flag(self, flag_number: int, flag_name: int):
        self._flags[flag_name].add_flag(flag_number)

    def append_serializable_flag(self, flag_name: int):
        self._data.extend((self._flags[flag_name], bytearray()))

    def append_serialized_tl(self, data: "bytes | Value"):
        self._data[-1] += data if isinstance(data, bytes) else data.get_flat_bytes()

    def __repr__(self):
        return f'{"boxed" if self.boxed else "bare"}({self.cons!r})'

    def get_flat_bytes(self) -> bytes:
        prefix = b""

        if self.boxed:
            prefix += self.cons.number

        return prefix + b"".join(map(lambda k: k.get_flat_bytes() if isinstance(k, Flags) else k, self._data))


class Structure:
    __slots__ = ("constructor_name", "_fields")

    constructor_name: str
    _fields: dict

    def __init__(self, constructor_name: str):
        self.constructor_name = constructor_name
        self._fields = dict()

    def __eq__(self, other):
        if isinstance(other, str):
            return self.constructor_name == other

    def __repr__(self):
        return repr(self.get_dict())

    def __getattr__(self, name):
        try:
            return self._fields[name]
        except KeyError as parent_key_error:
            raise KeyError(f"key `{name}` not found in `{self!r}`") from parent_key_error

    def get_dict(self):
        return Structure._get_dict(self)

    @staticmethod
    def _get_dict(anything: typing.Any) -> typing.Any:
        if isinstance(anything, Structure):
            ret = dict(_cons=anything.constructor_name)

            ret.update(
                {
                    key: Structure._get_dict(value)
                    for key, value in anything._fields.items()
                }
            )

            return ret

        elif isinstance(anything, (list, tuple)):
            return [Structure._get_dict(value) for value in anything]

        elif isinstance(anything, bytes):
            return anything

        else:
            return anything


class Parameter:
    __slots__ = ("name", "type", "flag_number", "is_vector", "is_boxed", "element_parameter", "is_flag", "flag_name")

    name: str
    type: str | None
    flag_number: int | None
    flag_name: int | None
    is_vector: bool
    is_boxed: bool
    is_flag: bool
    element_parameter: "Parameter | None"

    def __init__(
            self,
            pname: str,
            ptype: str | None,
            is_boxed: bool,
            flag_number: int | None = None,
            is_vector: bool = False,
            is_flag: bool = False,
            flag_name: int | None = None,
            element_parameter: "Parameter | None" = None
    ):
        self.name = pname
        self.type = ptype
        self.flag_number = flag_number
        self.is_vector = is_vector
        self.is_boxed = is_boxed
        self.element_parameter = element_parameter
        self.is_flag = is_flag
        self.flag_name = flag_name

    def __repr__(self):
        if self.flag_number is not None:
            return f"{self.name}:flags.{self.flag_number:d}?{self.type}"
        else:
            return f"{self.name}:{self.type}"


class Constructor:
    __slots__ = ("schema", "type", "name", "number", "_parameters", "flags")

    schema: Schema
    type: str
    name: str
    number: bytes
    _parameters: list[Parameter]
    flags: set[int] | None

    def __init__(
            self,
            schema: Schema,
            ptype: str,
            name: str,
            number: bytes,
            parameters: list[Parameter],
            flags: set[int] | None
    ):
        self.schema = schema
        self.name = name
        self.number = number
        self.type = ptype
        self._parameters = parameters
        self.flags = flags

    def __repr__(self):
        return f"{self.name} {''.join('%r ' % p for p in self._parameters)}= {self.type};"

    def _serialize_argument(self, data: Value, parameter: Parameter, argument: typing.Any) -> bytes | typing.NoReturn:
        if isinstance(argument, str):
            argument = argument.encode("utf-8")

        if argument is False:
            argument = {"_cons": "boolFalse"}

        if argument is True and parameter.type == "true":
            argument = {"_cons": "true"}

        if argument is True and parameter.type == "Bool":
            argument = {"_cons": "boolTrue"}

        if isinstance(argument, Structure):
            argument = argument.get_dict()

        if isinstance(argument, dict):
            argument = self.schema.serialize(boxed=parameter.is_boxed, **argument)

        if argument is not None and parameter.flag_number is not None:
            data.set_flag(parameter.flag_number, parameter.flag_name)

        match parameter.type:
            case "int":
                return data.append_serialized_tl(int(argument).to_bytes(4, "little", signed=True))

            case "uint":
                return data.append_serialized_tl(int(argument).to_bytes(4, "little", signed=False))

            case "long":
                return data.append_serialized_tl(int(argument).to_bytes(8, "little", signed=True))

            case "ulong":
                return data.append_serialized_tl(int(argument).to_bytes(8, "little", signed=False))

            case "int128":
                return data.append_serialized_tl(argument)

            case "sha1":
                return data.append_serialized_tl(argument)

            case "int256":
                return data.append_serialized_tl(argument)

            case "double":
                return data.append_serialized_tl(struct.pack(b"<d", float(argument)))

            case "string":
                return data.append_serialized_tl(pack_binary_string(argument))

            case "bytes":
                return data.append_serialized_tl(pack_binary_string(argument))

            case "object":
                return data.append_serialized_tl(pack_long_binary_string(argument.get_flat_bytes()))

            case "padded_object":
                return data.append_serialized_tl(pack_long_binary_string_padded(argument.get_flat_bytes()))

            case "rawobject":
                argument.boxed = True
                return data.append_serialized_tl(argument)

            case "encrypted":
                return data.append_serialized_tl(argument)

            case "gzip":
                argument.boxed = True
                return data.append_serialized_tl(pack_binary_string(gzip.compress(argument.get_flat_bytes())))

        if parameter.is_vector:
            if parameter.is_boxed:
                data.append_serialized_tl(_compile_cons_number(b"vector t:Type # [ t ] = Vector t"))

            data.append_serialized_tl(len(argument).to_bytes(4, "little", signed=False))

            for element_argument in argument:
                self._serialize_argument(data, parameter.element_parameter, element_argument)

        else:
            self.schema.typecheck(parameter, argument)
            data.append_serialized_tl(argument)

    def serialize(self, boxed: bool, **arguments) -> Value:
        data = Value(self, boxed=boxed)

        for parameter in self._parameters:
            if parameter.is_flag:
                data.append_serializable_flag(parameter.flag_name)

            elif parameter.name not in arguments:
                if parameter.flag_number is None:
                    raise TypeError(f"required `{parameter}` not found in `{self.name}`")

            else:
                argument = arguments[parameter.name]

                if argument is None and parameter.flag_name is not None:
                    continue

                self._serialize_argument(data, parameter, argument)

        return data

    def _deserialize_argument(self, bytereader: SyncByteReader, parameter: Parameter) -> typing.Any:
        match parameter.type:
            case "int":
                return int.from_bytes(bytereader(4), "little", signed=True)

            case "uint":
                return int.from_bytes(bytereader(4), "little", signed=False)

            case "long":
                return int.from_bytes(bytereader(8), "little", signed=True)

            case "ulong":
                return int.from_bytes(bytereader(8), "little", signed=False)

            case "int128":
                return bytereader(16)

            case "sha1":
                return bytereader(20)

            case "int256":
                return bytereader(32)

            case "double":
                return struct.unpack(b"<d", bytereader(8))

            case "string":
                return unpack_binary_string(bytereader).decode()

            case "bytes":
                return unpack_binary_string(bytereader)

            case "gzip":
                string_stream = unpack_binary_string_stream(bytereader)
                gzip_stream = GzipStreamReader(string_stream)
                return self.schema.read(gzip_stream)

            case "rawobject":
                return self.schema.read(bytereader)

            case "object":
                return self.schema.read(unpack_long_binary_string_stream(bytereader))

            case "padded_object":
                return self.schema.read(unpack_long_binary_string_stream(bytereader))

            case "bytesobject":
                return bytereader(int.from_bytes(bytereader(4), "little", signed=False))

            case "flags":
                return unpack_flags(int.from_bytes(bytereader(4), "little", signed=False))

        if parameter.is_vector:
            if parameter.is_boxed:
                vcons = bytereader(4)

                if vcons != _compile_cons_number(b"vector t:Type # [ t ] = Vector t"):
                    raise ValueError(f"Not vector `{long_hex(vcons)}` in `{parameter!r}` in `{self!r}`")

            vector_len = int.from_bytes(bytereader(4), "little", signed=False)

            return [
                self._deserialize_argument(bytereader, parameter.element_parameter)
                for _ in range(vector_len)
            ]
        else:
            return self.schema.deserialize(bytereader, parameter)

    def deserialize_bare_data(self, bytereader: SyncByteReader) -> Structure:
        result = Structure(self.name)
        fields = result._fields

        if self.flags:
            flags: dict[int, set[int]] = {}

            for parameter in self._parameters:
                if parameter.is_flag:
                    flags[parameter.flag_name] = unpack_flags(int.from_bytes(bytereader(4), "little", signed=False))

                elif parameter.flag_number is not None:
                    if parameter.flag_number in flags[parameter.flag_name]:
                        fields[parameter.name] = self._deserialize_argument(bytereader, parameter)
                    else:
                        fields[parameter.name] = None

                else:
                    fields[parameter.name] = self._deserialize_argument(bytereader, parameter)
        else:
            for parameter in self._parameters:
                fields[parameter.name] = self._deserialize_argument(bytereader, parameter)

        return result
