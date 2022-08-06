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
    async def write(self, data: bytes):
        raise NotImplementedError

    @abc.abstractmethod
    def stop(self):
        raise NotImplementedError

