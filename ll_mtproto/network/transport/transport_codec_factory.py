import abc
from . import TransportCodecBase

__all__ = ("TransportCodecFactory",)


class TransportCodecFactory(abc.ABC):
    @abc.abstractmethod
    def new_codec(self) -> TransportCodecBase:
        raise NotImplementedError()
