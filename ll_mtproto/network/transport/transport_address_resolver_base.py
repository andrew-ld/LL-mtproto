import abc

from ll_mtproto.network import DatacenterInfo


__all__ = ("TransportAddressResolverBase",)

class TransportAddressResolverBase(abc.ABC):
    @abc.abstractmethod
    async def get_address(self, datacenter_info: DatacenterInfo) -> tuple[str, int]:
        raise NotImplementedError()
