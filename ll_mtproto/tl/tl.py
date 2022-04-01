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
    Bytedata,
    unpack_gzip_stream,
    unpack_binary_string_stream,
    unpack_long_binary_string_stream,
)
from ..typed import InThread, ByteReader

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
def unpack_flags(n: int) -> list[int]:
    i = 0
    flags = []

    while n > 0:
        if n % 2 == 1:
            flags.append(i)

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
    __slots__ = ("constructors", "types", "cons_numbers", "in_thread")

    constructors: dict[str, "Constructor"]
    types: dict[str, set]
    cons_numbers: dict[bytes, "Constructor"]
    in_thread: InThread

    def __init__(self, in_thread: InThread, scheme_data: str):
        self.constructors = dict()
        self.types = dict()
        self.cons_numbers = dict()
        self._parse_file(scheme_data)
        self.in_thread = in_thread

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

        if cons.type not in self.types:
            self.types[cons.type] = set()

        self.types[cons.type].add(cons)

    def typecheck(self, parameter: "Parameter", argument: "Value") -> tuple[bool, str]:
        if not isinstance(argument, Value):
            return False, "not an object for nonbasic type"

        if parameter.is_boxed:
            if parameter.type not in self.types:
                return False, "unknown type"

            if argument.cons not in self.types[parameter.type]:
                return False, "type mismatch"

            if not argument.boxed:
                return False, "expected boxed, found bare"

        else:
            if parameter.type not in self.constructors:
                return False, "unknown constructor"

            if argument.cons != self.constructors[parameter.type]:
                return False, "wrong constructor"

            if argument.boxed:
                return False, "expected bare, found boxed"

        return True, "Ok"

    async def deserialize(self, bytereader: ByteReader, parameter: "Parameter") -> "Structure":
        if parameter.is_boxed:
            if parameter.type is not None and parameter.type not in self.types:
                raise ValueError(f"Unknown type `{parameter.type}`")

            cons_number = await bytereader(4)
            if cons_number not in self.cons_numbers:
                raise ValueError(f"Unknown constructor {hex(int.from_bytes(cons_number, 'little'))}")

            cons = self.cons_numbers[cons_number]
            if parameter.type is not None and cons not in self.types[parameter.type]:
                raise ValueError(f"type mismatch, constructor `{cons.name}` not in type `{parameter.type}`")

        else:
            if parameter.type not in self.constructors:
                raise ValueError(f"Unknown constructor in parameter `{parameter!r}`")

            cons = self.constructors[parameter.type]

        return await cons.deserialize_bare_data(bytereader)

    def serialize(self, boxed: bool, **kwargs) -> "Value":
        cons_name = kwargs["_cons"]

        if cons_name not in self.constructors:
            raise NotImplementedError(f"Constructor `{cons_name}` not present in scheme.")

        cons = self.constructors[cons_name]
        return cons.serialize(boxed=boxed, **kwargs)

    def bare(self, **kwargs) -> "Value":
        return self.serialize(boxed=False, **kwargs)

    def boxed(self, **kwargs) -> "Value":
        return self.serialize(boxed=True, **kwargs)

    async def read(self, bytereader: ByteReader, is_boxed=True, parameter_type=None) -> "Structure":
        parameter = Parameter("", parameter_type, is_boxed=is_boxed)
        return await self.deserialize(bytereader, parameter)

    async def read_from_string(self, string: bytes, *args, **kwargs) -> "Structure":
        bytedata = Bytedata(string)
        return await self.read(bytedata.cororead, *args, **kwargs)


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

        if flag_number in self._flags:
            raise ValueError(f"Data with flag `{flag_number:d}` is already present in constructor `{self.cons}`")

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
    __slots__ = ("constructor_name", "fields")

    constructor_name: str
    fields: dict

    def __init__(self, constructor_name: str):
        self.constructor_name = constructor_name
        self.fields = dict()

    def __eq__(self, other):
        if isinstance(other, str):
            return self.constructor_name == other

    def __repr__(self):
        return repr(self.get_dict())

    def __getattr__(self, name):
        if (field := self.fields.get(name, ...)) is ...:
            raise AttributeError(f"Attribute `{name}` not found in `{self!r}`")
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
                    for key, value in anything.fields.items()
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

        if isinstance(argument, dict):
            argument = self.scheme.serialize(boxed=parameter.is_boxed, **argument)

        if parameter.type == "int":
            data.append(int(argument).to_bytes(4, "little", signed=True))

        elif parameter.type == "uint":
            data.append(int(argument).to_bytes(4, "little", signed=False))

        elif parameter.type == "long":
            data.append(int(argument).to_bytes(8, "little", signed=True))

        elif parameter.type == "ulong":
            data.append(int(argument).to_bytes(8, "little", signed=False))

        elif parameter.type == "int128":
            # it's more convenient to handle long ints as bytes
            if len(argument) != 16:
                raise ValueError(f"Expected 16 bytes, got {len(argument):d} bytes")

            data.append(argument)

        elif parameter.type == "sha1":
            # it's more convenient to handle long ints as bytes
            if len(argument) != 20:
                raise ValueError(f"Expected 20 bytes, got {len(argument):d} bytes")

            data.append(argument)

        elif parameter.type == "int256":
            # it's more convenient to handle long ints as bytes
            if len(argument) != 32:
                raise ValueError(f"Expected 32 bytes, got {len(argument):d} bytes")

            data.append(argument)

        elif parameter.type == "double":
            data.append(struct.pack(b"<d", float(argument)))

        elif parameter.type == "string":
            if isinstance(argument, str):
                argument = argument.encode("utf-8")

            if not isinstance(argument, bytes):
                raise TypeError(f"Wrong argument `{argument!r}` for parameter `{parameter!r}` in `{self.name}`")

            data.append(pack_binary_string(argument))

        elif parameter.type == "bytes":
            data.append(pack_binary_string(argument))

        elif parameter.type == "object":
            data.append(pack_long_binary_string(argument.get_flat_bytes()))

        elif parameter.type == "rawobject":
            argument.boxed = True
            data.append(argument)

        elif parameter.type == "encrypted":
            data.append(argument)

        elif parameter.type == "gzip":
            argument.boxed = True
            data.append(pack_binary_string(gzip.compress(argument.get_flat_bytes(), compresslevel=1)))

        elif parameter.is_vector:
            if parameter.is_boxed:
                data.append(_compile_cons_number(b"vector t:Type # [ t ] = Vector t"))

            data.append(len(argument).to_bytes(4, "little", signed=False))

            for element_argument in argument:
                self._serialize_argument(data, parameter.element_parameter, element_argument)

        else:
            typecheck, error = self.scheme.typecheck(parameter, argument)

            if not typecheck:
                raise TypeError(f"Bad argument `{argument!r}` for parameter `{parameter!r}` in `{self.name}`, {error}")

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

    async def _deserialize_argument(self, bytereader: ByteReader, parameter: Parameter) -> any:
        if parameter.type == "int":
            return int.from_bytes(await bytereader(4), "little", signed=True)

        elif parameter.type == "uint":
            return int.from_bytes(await bytereader(4), "little", signed=False)

        elif parameter.type == "long":
            return int.from_bytes(await bytereader(8), "little", signed=True)

        elif parameter.type == "ulong":
            return int.from_bytes(await bytereader(8), "little", signed=False)

        elif parameter.type == "int128":
            return await bytereader(16)

        elif parameter.type == "sha1":
            return await bytereader(20)

        elif parameter.type == "int256":
            return await bytereader(32)

        elif parameter.type == "double":
            return struct.unpack(b"<d", await bytereader(8))

        elif parameter.type == "string":
            return await unpack_binary_string(bytereader)

        elif parameter.type == "bytes":
            return await unpack_binary_string(bytereader)

        elif parameter.type == "gzip":
            string_stream = await unpack_binary_string_stream(bytereader)
            gzip_stream = unpack_gzip_stream(string_stream, self.scheme.in_thread)
            return await self.scheme.read(gzip_stream)

        elif parameter.type == "rawobject":
            return await self.scheme.read(bytereader)

        elif parameter.type == "object":
            return await self.scheme.read(await unpack_long_binary_string_stream(bytereader))

        elif parameter.is_vector:
            if parameter.is_boxed:
                vcons = await bytereader(4)

                if vcons != _compile_cons_number(b"vector t:Type # [ t ] = Vector t"):
                    raise ValueError(f"Not vector `{long_hex(vcons)}` in `{parameter!r}` in `{self!r}`")

            vector_len = int.from_bytes(await bytereader(4), "little", signed=False)

            return [
                await self._deserialize_argument(bytereader, parameter.element_parameter)
                for _ in range(vector_len)
            ]

        else:
            return await self.scheme.deserialize(bytereader, parameter)

    async def deserialize_bare_data(self, bytedata: ByteReader) -> Structure:
        result = Structure(self.name)

        if self.has_flags:
            for parameter in self._parameters[:self.flags_offset]:
                argument = await self._deserialize_argument(bytedata, parameter)
                result.fields[parameter.name] = argument

            flags = unpack_flags(int.from_bytes(await bytedata(4), "little", signed=False))

            parameters = [
                p
                for p in self._parameters[self.flags_offset:]
                if p.flag_number is None or p.flag_number in flags
            ]

            result.fields.update(
                {
                    (p.name, None)
                    for p in self._parameters
                    if p.flag_number is not None and p.flag_number not in flags
                }
            )

        else:
            parameters = self._parameters

        for parameter in parameters:
            argument = await self._deserialize_argument(bytedata, parameter)
            result.fields[parameter.name] = argument

        return result
