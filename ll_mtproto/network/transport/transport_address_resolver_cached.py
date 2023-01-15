from ...network import DatacenterInfo
from ...network.transport import TransportAddressResolverBase
from ...typed import Structure

__all__ = ("CachedTransportAddressResolver",)


class CachedTransportAddressResolver(TransportAddressResolverBase):
    __slots__ = ("_cached_resolved",)

    _cached_resolved: dict[DatacenterInfo, tuple[str, int]]

    def __init__(self):
        self._cached_resolved = dict()

    def on_new_address(self, datacenter_info: DatacenterInfo, direct_address: str, direct_port: int):
        self._cached_resolved[datacenter_info] = (direct_address, direct_port)

    def apply_telegram_config(self, datacenters: list[DatacenterInfo], config: Structure):
        if config.constructor_name != "config":
            raise TypeError(f"Expected: config, Found: {config!r}")

        for dc_option in filter(lambda dc_option: not dc_option.ipv6, config.dc_options):
            found_dc = next(
                datacenter
                for datacenter in datacenters
                if datacenter.datacenter_id == dc_option.id and datacenter.is_media == bool(dc_option.media_only)
            )

            self.on_new_address(found_dc, dc_option.ip_address, dc_option.port)

    async def get_address(self, datacenter_info: DatacenterInfo) -> tuple[str, int]:
        if cached_address := self._cached_resolved.get(datacenter_info, None):
            return cached_address
        else:
            return datacenter_info.default_direct_address, datacenter_info.default_direct_port
