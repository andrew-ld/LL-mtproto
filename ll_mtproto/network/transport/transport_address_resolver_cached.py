import copy
import random

from ...network import DatacenterInfo
from ...network.transport import TransportAddressResolverBase
from ...typed import Structure

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

    def apply_telegram_config(self, datacenters: list[DatacenterInfo], config: Structure, allow_ipv6: bool = False):
        if config.constructor_name != "config":
            raise TypeError(f"Expected: config, Found: {config!r}")

        supported_dc_options = config.dc_options

        if not allow_ipv6:
            supported_dc_options = filter(lambda dc_option: not dc_option.ipv6, supported_dc_options)

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
