import binascii
import functools
import gzip
import re
import struct

from .byteutils import (
    long_hex,
    pack_binary_string,
    unpack_binary_string,
    pack_long_binary_string,
    unpack_gzip_stream,
    unpack_binary_string_stream,
    unpack_long_binary_string_stream,
)
from ..typed import TlMessageBody, SyncByteReader

__all__ = ("Scheme", "Value", "Structure", "Parameter", "Constructor",)


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


_schemeRE = re.compile(
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
    r"(flags.(?P<flag_number>\d+)\?)?"
    r"(?P<type>"
    r"(?P<vector>((?P<bare_vector>vector)|(?P<boxed_vector>Vector))<)?"
    r"(?P<element_type>((?P<namespace>[a-zA-Z\d._]*)\.)?"
    r"((?P<bare>[a-z][a-zA-Z\d._]*)|(?P<boxed>[A-Z][a-zA-Z\d._]*)))"
    r"(?(vector)>)?)$"
)


# a collection of constructors
class Scheme:
    __slots__ = ("constructors", "types", "cons_numbers")

    constructors: dict[str, "Constructor"]
    types: dict[str, set]
    cons_numbers: dict[bytes, "Constructor"]

    def __init__(self, scheme_data: str):
        self.constructors = dict()
        self.types = dict()
        self.cons_numbers = dict()
        self._parse_file(scheme_data)

    def __repr__(self):
        return "\n".join(repr(cons) for cons in self.constructors.values())

    def _parse_file(self, scheme_data: str):
        for scheme_line in scheme_data.split("\n"):
            self._parse_line(scheme_line)

    @staticmethod
    def _parse_token(regex, s: str) -> None | dict[str, str]:
        match = regex.match(s)

        if not match:
            return None
        else:
            return {k: v for k, v in match.groupdict().items() if v is not None}

    def _parse_line(self, line: str):
        cons_parsed = self._parse_token(_schemeRE, line)

        if not cons_parsed:
            raise SyntaxError("Error in scheme: `%s`" % line)

        if "cons" not in cons_parsed:
            return

        parameter_tokens: list[str] = cons_parsed["parameters"].split(" ")[1:]

        has_flags = "flags:#" in parameter_tokens
        flags_offset: int | None = None

        if has_flags:
            flags_offset = parameter_tokens.index("flags:#")
            parameter_tokens.pop(flags_offset)

        parameters = []

        if "number" in cons_parsed:
            con_number_int = int(cons_parsed["number"], base=16)
            cons_number = con_number_int.to_bytes(4, "little", signed=False)
        else:
            cons_number = None

        for parameter_token in parameter_tokens:
            parameter_parsed = self._parse_token(_parameterRE, parameter_token)
            if not parameter_parsed:
                raise SyntaxError(f"Error in parameter `{parameter_token}`")

            is_vector = "vector" in parameter_parsed

            element_parameter = (
                Parameter(
                    pname="<element of vector `%s`>" % parameter_parsed["name"],
                    ptype=parameter_parsed["element_type"],
                    is_boxed="boxed" in parameter_parsed,
                )
                if is_vector
                else None
            )

            parameter = Parameter(
                pname=parameter_parsed["name"],
                ptype=parameter_parsed["type"],
                flag_number=int(parameter_parsed["flag_number"])
                if "flag_number" in parameter_parsed
                else None,
                is_vector=is_vector,
                is_boxed="boxed_vector" in parameter_parsed
                if is_vector
                else "boxed" in parameter_parsed,
                element_parameter=element_parameter,
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
            scheme=self,
            ptype=None if "xtype" in cons_parsed else cons_parsed["type"],
            name=cons_parsed["name"],
            number=cons_number,
            has_flags=has_flags,
            parameters=parameters,
            flags_offset=flags_offset
        )

        self.constructors[cons.name] = cons
        self.cons_numbers[cons.number] = cons
        self.types.setdefault(cons.type, set()).add(cons)

    def typecheck(self, parameter: "Parameter", argument: "Value"):
        if not isinstance(argument, Value):
            raise TypeError("not an object for nonbasic type")

        if parameter.is_boxed:
            if parameter.type not in self.types:
                raise TypeError("unknown type")

            if argument.cons not in self.types[parameter.type]:
                raise TypeError("type mismatch")

            if not argument.boxed:
                raise TypeError("expected boxed, found bare")

        else:
            if parameter.type not in self.constructors:
                raise TypeError("expected boxed, found bare")

            if argument.cons != self.constructors[parameter.type]:
                raise TypeError("wrong constructor")

            if argument.boxed:
                raise TypeError("expected bare, found boxed")

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

            cons = self.cons_numbers.get(cons_number, False)

            if not cons:
                raise ValueError(f"Unknown constructor {hex(int.from_bytes(cons_number, 'little'))}")

            if parameter.type is not None and cons not in self.types[parameter.type]:
                raise ValueError(f"type mismatch, constructor `{cons.name}` not in type `{parameter.type}`")
        else:
            cons = self.constructors.get(parameter.type, False)

            if not cons:
                raise ValueError(f"Unknown constructor in parameter `{parameter!r}`")

        return cons.deserialize_bare_data(bytereader)

    def serialize(self, boxed: bool, **kwargs) -> "Value":
        cons_name = kwargs["_cons"]

        if cons := self.constructors.get(cons_name, False):
            return cons.serialize(boxed=boxed, **kwargs)
        else:
            raise NotImplementedError(f"Constructor `{cons_name}` not present in scheme.")

    def bare(self, **kwargs) -> "Value":
        return self.serialize(boxed=False, **kwargs)

    def boxed(self, **kwargs) -> "Value":
        return self.serialize(boxed=True, **kwargs)

    def read(self, bytereader: SyncByteReader, is_boxed=True, parameter_type=None) -> "Structure":
        parameter = Parameter("", parameter_type, is_boxed=is_boxed)
        return self.deserialize(bytereader, parameter)


# a serialized TL Value that will be sent
class Value:
    __slots__ = ("cons", "boxed", "_flags", "_data")

    cons: "Constructor"
    boxed: bool
    _flags: set[int]
    _data: list[bytes]

    def __init__(self, cons: "Constructor", boxed: bool = False):
        self.cons = cons
        self.boxed = boxed

        if self.boxed and self.cons.number is None:
            raise RuntimeError(f"Tried to create a boxed value for a numberless constructor `{cons!r}`")

        self._flags = set()
        self._data = []

    def set_flag(self, flag_number: int):
        if not self.cons.has_flags:
            raise TypeError(f"Conditional data added to plain constructor `{self.cons!r}`")

        self._flags.add(flag_number)

    def append(self, data: bytes):
        self._data.append(data)

    def __repr__(self):
        return f'{"boxed" if self.boxed else "bare"}({self.cons!r})\n{long_hex(self.get_flat_bytes())}'

    def get_flat_bytes(self) -> bytes:
        prefix = b""

        if self.boxed:
            prefix += self.cons.number

        if self.cons.has_flags:
            prefix += _pack_flags(self._flags)

        return prefix + b"".join(map(lambda k: k.get_flat_bytes() if isinstance(k, Value) else k, self._data))


# a deserialized TL Value that was received
class Structure:
    __slots__ = ("constructor_name", "_fields")

    constructor_name: str
    _fields: dict

    __sentinel = object()

    def __init__(self, constructor_name: str):
        self.constructor_name = constructor_name
        self._fields = dict()

    def __eq__(self, other):
        if isinstance(other, str):
            return self.constructor_name == other

    def __repr__(self):
        return repr(self.get_dict())

    def __getattr__(self, name):
        if (field := self._fields.get(name, self.__sentinel)) is self.__sentinel:
            raise KeyError(f"key `{name}` not found in `{self!r}`")
        else:
            return field

    def get_dict(self):
        return Structure._get_dict(self)

    @staticmethod
    def _get_dict(anything: any):
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


# a parameter in TL Constructor or TL Function
class Parameter:
    __slots__ = ("name", "type", "flag_number", "is_vector", "is_boxed", "element_parameter")

    name: str
    type: str
    flag_number: int | None
    is_vector: bool
    is_boxed: bool
    element_parameter: "Parameter | None"

    def __init__(
            self,
            pname: str,
            ptype: str,
            is_boxed: bool,
            flag_number: int = None,
            is_vector: bool = False,
            element_parameter: "Parameter | None" = None
    ):
        self.name = pname
        self.type = ptype
        self.flag_number = flag_number
        self.is_vector = is_vector
        self.is_boxed = is_boxed
        self.element_parameter = element_parameter

    def __repr__(self):
        if self.flag_number is not None:
            return f"{self.name}:flags.{self.flag_number:d}?{self.type}"
        else:
            return f"{self.name}:{self.type}"


# a TL Constructor or TL Function
class Constructor:
    __slots__ = ("scheme", "type", "name", "number", "has_flags", "flags_offset", "_parameters")

    scheme: Scheme
    type: str
    name: str
    number: bytes
    has_flags: bool
    flags_offset: int | None
    _parameters: list[Parameter]

    def __init__(
            self,
            scheme: Scheme,
            ptype: str,
            name: str,
            number: bytes,
            has_flags: bool,
            parameters: list[Parameter],
            flags_offset: int | None
    ):
        self.scheme = scheme
        self.name = name
        self.number = number
        self.type = ptype
        self.has_flags = has_flags
        self.flags_offset = flags_offset
        self._parameters = parameters

    def __repr__(self):
        return f"{self.name} {''.join('%r ' % p for p in self._parameters)}= {self.type};"

    def _serialize_argument(self, data: Value, parameter: Parameter, argument: any):
        if isinstance(argument, str):
            argument = argument.encode("utf-8")

        if argument is False:
            argument = {"_cons": "boolFalse"}

        if argument is True and parameter.type == "true":
            argument = {"_cons": "true"}

        if argument is True and parameter.type == "Bool":
            argument = {"_cons": "boolTrue"}

        if isinstance(argument, dict):
            argument = self.scheme.serialize(boxed=parameter.is_boxed, **argument)

        match parameter.type:
            case "int":
                return data.append(int(argument).to_bytes(4, "little", signed=True))

            case "uint":
                return data.append(int(argument).to_bytes(4, "little", signed=False))

            case "long":
                return data.append(int(argument).to_bytes(8, "little", signed=True))

            case "ulong":
                return data.append(int(argument).to_bytes(8, "little", signed=False))

            case "int128":
                return data.append(argument)

            case "sha1":
                return data.append(argument)

            case "int256":
                return data.append(argument)

            case "double":
                return data.append(struct.pack(b"<d", float(argument)))

            case "string":
                return data.append(pack_binary_string(argument))

            case "bytes":
                return data.append(pack_binary_string(argument))

            case "object":
                return data.append(pack_long_binary_string(argument.get_flat_bytes()))

            case "rawobject":
                argument.boxed = True
                return data.append(argument)

            case "encrypted":
                return data.append(argument)

            case "gzip":
                argument.boxed = True
                return data.append(pack_binary_string(gzip.compress(argument.get_flat_bytes(), compresslevel=1)))

        if parameter.is_vector:
            if parameter.is_boxed:
                data.append(_compile_cons_number(b"vector t:Type # [ t ] = Vector t"))

            data.append(len(argument).to_bytes(4, "little", signed=False))

            for element_argument in argument:
                self._serialize_argument(data, parameter.element_parameter, element_argument)

        else:
            self.scheme.typecheck(parameter, argument)
            data.append(argument)

        if parameter.flag_number is not None:
            data.set_flag(parameter.flag_number)

    def serialize(self, boxed: bool, **arguments) -> Value:
        data = Value(self, boxed=boxed)

        for parameter in self._parameters:
            if parameter.name not in arguments:
                if parameter.flag_number is None:
                    raise TypeError(f"required `{parameter}` not found in `{self.name}`")

            else:
                argument = arguments[parameter.name]
                self._serialize_argument(data, parameter, argument)

        return data

    def _deserialize_argument(self, bytereader: SyncByteReader, parameter: Parameter) -> any:
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
                return unpack_binary_string(bytereader)

            case "bytes":
                return unpack_binary_string(bytereader)

            case "gzip":
                string_stream = unpack_binary_string_stream(bytereader)
                gzip_stream = unpack_gzip_stream(string_stream)
                return self.scheme.read(gzip_stream)

            case "rawobject":
                return self.scheme.read(bytereader)

            case "object":
                return self.scheme.read(unpack_long_binary_string_stream(bytereader))

            case "bytesobject":
                return bytereader(int.from_bytes(bytereader(4), "little", signed=False))

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
            return self.scheme.deserialize(bytereader, parameter)

    def deserialize_bare_data(self, bytedata: SyncByteReader) -> Structure:
        result = Structure(self.name)
        fields = result._fields

        if self.has_flags:
            for parameter in self._parameters[:self.flags_offset]:
                fields[parameter.name] = self._deserialize_argument(bytedata, parameter)

            flags = unpack_flags(int.from_bytes(bytedata(4), "little", signed=False))

            parameters = (
                p
                for p in self._parameters[self.flags_offset:]
                if p.flag_number is None or p.flag_number in flags
            )

            fields.update(
                {
                    (p.name, None)
                    for p in self._parameters
                    if p.flag_number is not None and p.flag_number not in flags
                }
            )

        else:
            parameters = self._parameters

        for parameter in parameters:
            fields[parameter.name] = self._deserialize_argument(bytedata, parameter)

        return result
