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


import copy
import random

from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.network.transport.transport_address_resolver_base import TransportAddressResolverBase
from ll_mtproto.tl.tl import Structure

__all__ = ("CachedTransportAddressResolver",)


class CachedTransportAddressResolver(TransportAddressResolverBase):
    __slots__ = ("_cached_resolved",)

    _cached_resolved: dict[DatacenterInfo, list[tuple[str, int]]]

    def __init__(self):
        self._cached_resolved = dict()

    def on_new_address(self, datacenter_info: DatacenterInfo, direct_address: str, direct_port: int):
        self._cached_resolved.setdefault(datacenter_info, []).append((direct_address, direct_port))

    def get_cache_copy(self) -> dict[DatacenterInfo, list[tuple[str, int]]]:
        return copy.deepcopy(self._cached_resolved)

    def apply_telegram_config(
            self,
            datacenters: frozenset[DatacenterInfo],
            config: Structure,
            allow_ipv6: bool = False
    ):
        if config.constructor_name != "config":
            raise TypeError(f"Expected: config, Found: {config!r}")

        supported_dc_options = config.dc_options

        if not allow_ipv6:
            supported_dc_options = filter(lambda option: not option.ipv6, supported_dc_options)

        for datacenter in datacenters:
            self._cached_resolved.pop(datacenter, None)

        for dc_option in supported_dc_options:
            found_datacenter = next(
                datacenter
                for datacenter in datacenters
                if datacenter.datacenter_id == dc_option.id and datacenter.is_media == bool(dc_option.media_only)
            )

            self.on_new_address(found_datacenter, dc_option.ip_address, dc_option.port)

    async def get_address(self, datacenter_info: DatacenterInfo) -> tuple[str, int]:
        if cached_address := self._cached_resolved.get(datacenter_info, None):
            return random.choice(cached_address)
        else:
            return datacenter_info.default_direct_address, datacenter_info.default_direct_port
