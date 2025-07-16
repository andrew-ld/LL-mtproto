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


import argparse
import dataclasses
import operator
import typing

from ll_mtproto.tl.structure import Structure, TypedStructure, TypedStructureObjectType
from ll_mtproto.tl.tl import Schema, Parameter, Constructor, Value, TlBodyData

DISALLOWED_CONSTRUCTORS = {"gzip_packed", "true", "boolTrue", "boolFalse", "null"}
DISALLOWED_TYPES = {"Bool", "True", "Null"}


def from_snake_to_pascal_case(snake_case_text: str) -> str:
    parts = snake_case_text.replace(".", "_").split("_")
    return "".join(word[0].upper() + word[1:] for word in parts)


def parameter_to_python_type(p: Parameter | None, is_wrapper: bool) -> str:
    if p is None:
        return "TypedStructureObjectType" if is_wrapper else "None"

    inner_type = p
    vector_depth = 0

    while inner_type.is_vector:
        if not inner_type.element_parameter:
            raise TypeError(f"Type {inner_type!r} is a vector but element parameter is not present")
        inner_type = inner_type.element_parameter
        vector_depth += 1

    output_text = "typing.List[" * vector_depth

    if not inner_type.type:
        raise TypeError(f"Type {inner_type!r} type definition is not present")

    if inner_type.is_primitive:
        if inner_type.name == "_wrapped" and inner_type.type == "rawobject" and is_wrapper:
            output_text += "TypedStructure[TypedStructureObjectType] | TlBodyData | Value"
        else:
            output_text += f"_{inner_type.type}"
    else:
        output_text += f"_{from_snake_to_pascal_case(inner_type.type)}"

    if p.parameter_flag is not None:
        output_text += " | None"

    output_text += "]" * vector_depth
    return output_text


def _load_schema(schema_file: str) -> Schema:
    schema = Schema()
    with open(schema_file) as schema_fd:
        schema.extend_from_raw_schema(schema_fd.read())
    return schema


def _generate_file_header(schema_file: str) -> str:
    return f"""#  Auto-generated code from types_generator.py using {schema_file}

import typing
import dataclasses
from ll_mtproto.tl.structure import Structure, TypedStructure, TypedStructureObjectType
from ll_mtproto.tl.tl import Value, TlBodyData

_int128 = bytes
_string = str
_int256 = bytes
_ulong = int
_long = int
_PaddedObject = Structure
_PlainObject = Structure
_encrypted = bytes
_rawobject = bytes | Value
_sha1 = bytes
_uint = int
_true = bool | None
_double = float
_Bool = bool
_bytes = bytes
_int = int
"""


def _generate_all_variable(constructors: typing.List[typing.Tuple[str, Constructor]]) -> str:
    lines = ["__all__ = ("]
    for cons_name, _ in constructors:
        if cons_name in DISALLOWED_CONSTRUCTORS:
            continue
        lines.append(f'\t"{from_snake_to_pascal_case(cons_name)}",')
    lines.append(")\n")
    return "\n".join(lines)


def _generate_type_unions(types: typing.List[typing.Tuple[str, typing.List[Constructor]]]) -> str:
    output_lines = []
    for cons_type, cons_list in types:
        if cons_type in DISALLOWED_TYPES:
            continue

        valid_constructors = [c for c in cons_list if not c.is_function and not c.is_gzip_container]
        valid_constructors.sort(key=lambda c: c.name)

        if not valid_constructors:
            continue

        union_lines = [f"_{from_snake_to_pascal_case(cons_type)} = typing.Union["]
        union_lines.extend(f'\n\t"{from_snake_to_pascal_case(cons.name)}",' for cons in valid_constructors)
        union_lines.append("\n]")
        output_lines.append("".join(union_lines))

    return "\n".join(output_lines)


def _generate_constructor_classes(constructors: typing.List[typing.Tuple[str, Constructor]]) -> str:
    output_lines = []
    for cons_name, cons in constructors:
        if cons_name in DISALLOWED_CONSTRUCTORS:
            continue

        ptype = parameter_to_python_type(cons.ptype_parameter, cons.is_function)
        class_generics = "[TypedStructureObjectType]" if cons.ptype_parameter is None else ""

        class_def = [
            "\n",
            "@dataclasses.dataclass",
            f"class {from_snake_to_pascal_case(cons_name)}{class_generics}(Structure, TypedStructure[{ptype}]):",
            f'\tCONS: typing.ClassVar[str] = "{cons_name}"',
        ]

        for p in cons.parameters:
            if p.is_flag:
                continue
            param_type = parameter_to_python_type(p, cons.is_function)
            class_def.append(f"\t{p.name}: {param_type}")

        output_lines.append("\n".join(class_def))

    return "\n".join(output_lines)


def generate_schema_types(schema_file: str, output_file: str) -> None:
    schema = _load_schema(schema_file)

    types_list = [(key, list(value)) for key, value in schema.types.items()]
    types: list[tuple[str, list[Constructor]]] = sorted(types_list, key=operator.itemgetter(0))

    constructors: list[tuple[str, Constructor]] = sorted(list(schema.constructors.items()), key=operator.itemgetter(0))

    parts = [
        _generate_file_header(schema_file),
        _generate_all_variable(constructors),
        _generate_type_unions(types),
        _generate_constructor_classes(constructors),
    ]

    output_text = "\n".join(filter(None, parts)) + "\n"

    with open(output_file, "w") as output:
        output.write(output_text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Python types from an MTProto schema.")
    parser.add_argument("--schema-file", type=str, required=True, help="Path to the input schema file.")
    parser.add_argument("--output-file", type=str, required=True, help="Path for the generated output file.")

    args = parser.parse_args()

    generate_schema_types(args.schema_file, args.output_file)


if __name__ == "__main__":
    main()
