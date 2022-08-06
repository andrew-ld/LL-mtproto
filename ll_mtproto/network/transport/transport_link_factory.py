import abc
import typing

from .transport_link_base import TransportLinkBase

__all__ = ("TransportLinkFactory",)


if typing.TYPE_CHECKING:
    from ..datacenter_info import DatacenterInfo


class TransportLinkFactory(abc.ABC):
    @abc.abstractmethod
    def new_transport_link(self, datacenter: "DatacenterInfo") -> TransportLinkBase:
        raise NotImplementedError
