# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2024 (andrew) https://github.com/andrew-ld/LL-mtproto

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


__all__ = ("RpcError",)

from ll_mtproto.tl.structure import Structure


class RpcError(BaseException):
    __slots__ = ("code", "message", "error_description")

    code: int
    message: str
    error_description: str | None

    def __init__(self, code: int, message: str, error_description: str | None):
        self.code = code
        self.message = message
        self.error_description = error_description

    @staticmethod
    def from_rpc_error(error: Structure) -> "RpcError":
        if error != "rpc_error":
            raise TypeError(f"Expected `rpc_error` Found `{error!r}`")

        return RpcError(error.error_code, error.error_message, None)

    def __str__(self) -> str:
        return f"RpcError {self.code} {repr(self.message)} {repr(self.error_description) if self.error_description is not None else ''}"

    def __repr__(self) -> str:
        return f"RpcError({self.code}, {repr(self.message)}, {repr(self.error_description)})"
