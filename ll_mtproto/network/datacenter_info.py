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


import time

from ll_mtproto.crypto.public_rsa import PublicRSA
from ll_mtproto.tl.tl import Schema

__all__ = ("DatacenterInfo",)


class DatacenterInfo:
    __slots__ = (
        "default_direct_address",
        "default_direct_port",
        "public_rsa",
        "schema",
        "datacenter_id",
        "is_media",
        "_time_difference",
        "is_test"
    )

    default_direct_address: str
    default_direct_port: int
    public_rsa: PublicRSA
    schema: Schema
    datacenter_id: int
    is_media: bool
    is_test: bool

    _time_difference: int

    def __init__(self, address: str, port: int, public_rsa: PublicRSA, schema: Schema, datacenter_id: int, is_media: bool, is_test: bool):
        self.default_direct_address = address
        self.default_direct_port = port
        self.public_rsa = public_rsa
        self.schema = schema
        self.datacenter_id = datacenter_id
        self.is_media = is_media
        self._time_difference = 0
        self.is_test = is_test

    def set_synchronized_time(self, synchronized_now: int) -> None:
        self._time_difference = synchronized_now - int(time.time())

    def get_synchronized_time(self) -> int:
        return int(time.time()) + self._time_difference

    def __copy__(self) -> "DatacenterInfo":
        return DatacenterInfo(
            self.default_direct_address,
            self.default_direct_port,
            self.public_rsa,
            self.schema,
            self.datacenter_id,
            self.is_media,
            self.is_test
        )

    def __str__(self) -> str:
        return f"{'media' if self.is_media else 'main'} {'test' if self.is_test else 'prod'} datacenter {self.datacenter_id} with layer {self.schema.layer}"
