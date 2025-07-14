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
import operator

from ll_mtproto.tl.tl import Schema


def from_snake_to_pascal_case(snake_case_text: str) -> str:
    s = snake_case_text.replace(".", "_").split("_")
    return "".join(word[0].upper() + word[1:] for word in s)


def generate_schema_types(schema_file: str, output_file: str) -> None:
    schema = Schema()

    with open(schema_file) as schema_fd:
        schema.extend_from_raw_schema(schema_fd.read())

    output_text = f"""#  Auto-generated code from types_generator.py using {schema_file}

import typing
import dataclasses
from ll_mtproto.tl.structure import Structure, TypedStructure
from ll_mtproto.tl.tl import Value

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

    types = list(schema.types.items())
    types.sort(key=operator.itemgetter(0))

    constructors = list(schema.constructors.items())
    constructors.sort(key=operator.itemgetter(0))

    output_text += "__all__ = (\n"

    disallowed_cons = ("gzip_packed", "true", "boolTrue", "boolFalse", "null")

    for cons_name, _ in constructors:
        if cons_name in disallowed_cons:
            continue

        output_text += f"\t\"{from_snake_to_pascal_case(cons_name)}\",\n"

    output_text += ")\n\n"

    for (cons_type, cons_list) in types:
        if cons_type in ("Bool", "True", "Null"):
            continue

        valid_constructors = [c for c in cons_list if not c.is_function and not c.is_gzip_container]
        valid_constructors.sort(key=lambda c: c.name)

        if not valid_constructors:
            continue

        output_text += f"_{from_snake_to_pascal_case(cons_type)} = typing.Union["

        for cons in valid_constructors:
            output_text += f"\n\t\"{from_snake_to_pascal_case(cons.name)}\","

        output_text += "\n]\n"

    for (cons_name, cons) in constructors:
        if cons_name in disallowed_cons:
            continue

        output_text += f"\n\n@dataclasses.dataclass\nclass {from_snake_to_pascal_case(cons_name)}(Structure, TypedStructure):\n"
        output_text += f"\tCONS: typing.ClassVar[str] = \"{cons_name}\"\n"

        for p in cons.parameters:
            if p.is_flag:
                continue

            inner_type = p
            vector_depth = 0

            while inner_type.is_vector:
                if not inner_type.element_parameter:
                    raise TypeError(f"Type {inner_type!r} is a vector but element parameter is not present")

                inner_type = inner_type.element_parameter
                vector_depth += 1

            output_text += f"\t{p.name}: "
            output_text += "typing.List[" * vector_depth
            output_text += "_"

            if not inner_type.type:
                raise TypeError(f"Type {inner_type!r} type definition is not present")

            if inner_type.is_primitive:
                output_text += inner_type.type
            else:
                output_text += from_snake_to_pascal_case(inner_type.type)

            output_text += "]" * vector_depth
            output_text += "\n"

    with open(output_file, "w") as output:
        output.write(output_text)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema-file", type=str, required=True)
    parser.add_argument("--output-file", type=str, required=True)

    args = parser.parse_args()

    generate_schema_types(args.schema_file, args.output_file)


if __name__ == "__main__":
    main()
