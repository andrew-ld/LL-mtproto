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
import abc

from ll_mtproto.tl.tl import TlBodyData, TlBodyDataValue, TlPrimitiveValue, extract_cons_from_tl_body

__all__ = ("StructureMeta", "BaseStructure", "DynamicStructure", "TypedStructure", "TypedStructureObjectType", "StructureValue")


TypedStructureObjectType = typing.TypeVar("TypedStructureObjectType")

StructureValue = typing.Union[
    typing.Iterable["StructureValue"],
    TlPrimitiveValue,
    "BaseStructure"
]


class StructureMeta(abc.ABCMeta):
    @typing.no_type_check
    def __instancecheck__(cls, instance: "BaseStructure") -> bool:
        if hasattr(cls, 'CONS') and isinstance(instance, BaseStructure):
            return bool(instance.constructor_name == cls.CONS)
        return super().__instancecheck__(instance)


class BaseStructure(abc.ABC, metaclass=StructureMeta):
    __slots__ = ("constructor_name",)

    constructor_name: typing.Final[str]

    def __init__(self, constructor_name: str):
        self.constructor_name = constructor_name

    def __eq__(self, other: typing.Any) -> bool:
        if isinstance(other, str):
            return self.constructor_name == other
        return super().__eq__(other)

    @abc.abstractmethod
    def as_tl_body_data(self) -> TlBodyData:
        raise NotImplementedError


class DynamicStructure(BaseStructure):
    __slots__ = ("_fields",)

    _fields: TlBodyData

    def __init__(self, constructor_name: str, fields: TlBodyData):
        super().__init__(constructor_name)
        self._fields = fields

    def __repr__(self) -> str:
        return f"{self.constructor_name}({self._fields!r})"

    def __getattr__(self, name: str) -> StructureValue:
        fields = object.__getattribute__(self, "_fields")
        return DynamicStructure.from_obj(fields[name])

    def get_dict(self) -> TlBodyData:
        return self._fields

    def as_tl_body_data(self) -> TlBodyData:
        return self._fields

    @staticmethod
    def from_tl_obj(obj: TlBodyData) -> "DynamicStructure":
        return DynamicStructure(constructor_name=extract_cons_from_tl_body(obj), fields=obj)

    @staticmethod
    def from_obj(obj: TlBodyDataValue) -> StructureValue:
        if isinstance(obj, dict):
            return DynamicStructure.from_tl_obj(obj)
        elif isinstance(obj, (list, tuple)):
            return [DynamicStructure.from_obj(x) for x in obj]
        else:
            return obj


@dataclasses.dataclass(eq=False)
class TypedStructure(BaseStructure, typing.Generic[TypedStructureObjectType]):
    CONS: typing.ClassVar[str]

    def __post_init__(self) -> None:
        super().__init__(self.CONS)

    def as_tl_body_data(self) -> TlBodyData:
        data: TlBodyData = {'_cons': self.CONS}
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if isinstance(value, TypedStructure):
                data[field.name] = value.as_tl_body_data()
            elif isinstance(value, (list, tuple)):
                data[field.name] = [
                    v.as_tl_body_data() if isinstance(v, TypedStructure) else v
                    for v in value
                ]
            else:
                data[field.name] = value
        return data
