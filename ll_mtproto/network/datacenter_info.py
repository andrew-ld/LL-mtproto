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
        "is_test",
        "_sync_server_time",
        "_sync_uptime",
    )

    default_direct_address: str
    default_direct_port: int
    public_rsa: PublicRSA
    schema: Schema
    datacenter_id: int
    is_media: bool
    is_test: bool

    _sync_server_time: int
    _sync_uptime: float

    def __init__(
        self,
        address: str,
        port: int,
        public_rsa: PublicRSA,
        schema: Schema,
        datacenter_id: int,
        is_media: bool,
        is_test: bool,
        time_sync: tuple[int, float] | None = None,
    ):
        self.default_direct_address = address
        self.default_direct_port = port
        self.public_rsa = public_rsa
        self.schema = schema
        self.datacenter_id = datacenter_id
        self.is_media = is_media
        self.is_test = is_test

        if time_sync is None:
            self._sync_server_time = int(time.time())
            self._sync_uptime = time.monotonic()
        else:
            self._sync_server_time, self._sync_uptime = time_sync


    def set_synchronized_time(self, synchronized_now: int) -> None:
        self._sync_server_time = synchronized_now
        self._sync_uptime = time.monotonic()

    def get_synchronized_time(self) -> int:
        elapsed = time.monotonic() - self._sync_uptime
        return int(self._sync_server_time + elapsed)

    def __copy__(self) -> "DatacenterInfo":
        return DatacenterInfo(
            self.default_direct_address,
            self.default_direct_port,
            self.public_rsa,
            self.schema,
            self.datacenter_id,
            self.is_media,
            self.is_test,
            time_sync=(self._sync_server_time, self._sync_uptime),
        )

    def __str__(self) -> str:
        return f"{'media' if self.is_media else 'main'} {'test' if self.is_test else 'prod'} datacenter {self.datacenter_id} with layer {self.schema.layer}"
