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


import abc

__all__ = ("TransportLinkBase",)


class TransportLinkBase(abc.ABC):
    @abc.abstractmethod
    async def read(self) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    async def readn(self, n: int) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def discard_packet(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def write(self, data: bytes) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def stop(self) -> None:
        raise NotImplementedError
