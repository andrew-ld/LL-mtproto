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


import typing

__all__ = ("Structure", "StructureBody")

class Structure:
    __slots__ = ("constructor_name", "_fields")

    constructor_name: str
    _fields: dict[str, typing.Any]

    def __init__(self, constructor_name: str, fields: dict[str, typing.Any]):
        self.constructor_name = constructor_name
        self._fields = fields

    def __eq__(self, other: typing.Any) -> bool:
        if isinstance(other, str):
            return self.constructor_name == other

        raise NotImplementedError()

    def __repr__(self) -> str:
        return repr(self.get_dict())

    def __getattr__(self, name: str) -> typing.Any:
        try:
            return self._fields[name]
        except KeyError as parent_key_error:
            raise KeyError(f"key `{name}` not found in `{self!r}`") from parent_key_error

    def get_dict(self) -> dict[str, typing.Any]:
        # _get_dict_inner from Structure always return dict
        return typing.cast(dict[str, typing.Any], Structure._get_dict_inner(self))

    @staticmethod
    def from_dict(obj: dict[str, typing.Any]) -> "Structure":
        # _from_obj_inner from dict always return Structure
        return typing.cast(Structure, Structure.from_obj(obj))

    @staticmethod
    def from_obj(obj: typing.Any) -> typing.Any:
        if isinstance(obj, (list, tuple)):
            return [Structure.from_obj(x) for x in obj]

        if not isinstance(obj, dict):
            return obj

        fields = dict(
            (k, Structure.from_obj(v))
            for k, v in obj.items()
            if k != "_cons"
        )

        return Structure(obj["_cons"], fields)

    @staticmethod
    def _get_dict_inner(obj: typing.Any) -> typing.Any:
        if isinstance(obj, Structure):
            return {
                "_cons": obj.constructor_name,
                **{
                    key: Structure._get_dict_inner(value)
                    for key, value in obj._fields.items()
                }
            }

        elif isinstance(obj, (list, tuple)):
            return [Structure._get_dict_inner(value) for value in obj]

        else:
            return obj


StructureBody = typing.Union[Structure, typing.List['StructureBody']]
