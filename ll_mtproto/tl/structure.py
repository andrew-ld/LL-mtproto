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


import dataclasses
import typing

from ll_mtproto.tl.tl import TlBodyData, TlBodyDataValue, TlPrimitiveValue, extract_cons_from_tl_body

__all__ = ("Structure", "TypedStructure", "TypedStructureObjectType", "StructureValue")


TypedStructureObjectType = typing.TypeVar("TypedStructureObjectType")


@dataclasses.dataclass
class TypedStructure[TypedStructureObjectType]:
    CONS: typing.ClassVar[str]

    def as_tl_body_data(self) -> TlBodyData:
        data: TlBodyData = {'_cons': self.CONS}

        for key, value in vars(self).items():
            if isinstance(value, TypedStructure):
                data[key] = value.as_tl_body_data()
            else:
                data[key] = value

        return data


class StructureMeta(type):
    @typing.no_type_check
    def __instancecheck__(cls, instance: "Structure") -> bool:
        if issubclass(cls, TypedStructure):
            return bool(instance.constructor_name == cls.CONS)
        return False


StructureValue = typing.Union[
    typing.Iterable["StructureValue"],
    TlPrimitiveValue,
    "Structure"
]


class Structure(metaclass=StructureMeta):
    __slots__ = ("constructor_name", "_fields")

    constructor_name: typing.Final[str]
    _fields: TlBodyData

    def __init__(self, constructor_name: str, fields: TlBodyData):
        self.constructor_name = constructor_name
        self._fields = fields

    def __eq__(self, other: typing.Any) -> bool:
        if isinstance(other, str):
            return self.constructor_name == other
        return super().__eq__(other)

    def __repr__(self) -> str:
        return repr(self._fields)

    def __getattr__(self, name: str) -> StructureValue:
        try:
            return Structure.from_obj(self._fields[name])
        except KeyError as parent_key_error:
            raise KeyError(f"key `{name}` not found in `{self!r}`") from parent_key_error

    def get_dict(self) -> TlBodyData:
        return self._fields

    @staticmethod
    def from_tl_obj(obj: TlBodyData) -> "Structure":
        return Structure(constructor_name=extract_cons_from_tl_body(obj), fields=obj)

    @staticmethod
    def from_obj(obj: TlBodyDataValue) -> StructureValue:
        if isinstance(obj, dict):
            return Structure(extract_cons_from_tl_body(obj), obj)

        elif isinstance(obj, (list, tuple)):
            return [Structure.from_obj(x) for x in obj]

        else:
            return obj
