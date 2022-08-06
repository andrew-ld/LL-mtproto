import abc

from . import TransportLinkBase
from ..datacenter_info import DatacenterInfo

__all__ = ("TransportLinkFactory",)


class TransportLinkFactory(abc.ABC):
    @abc.abstractmethod
    def new_transport_link(self, datacenter: "DatacenterInfo") -> TransportLinkBase:
        raise NotImplementedError
