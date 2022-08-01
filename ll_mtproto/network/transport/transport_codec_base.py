import abc
import asyncio

__all__ = ("TransportCodecBase",)


class TransportCodecBase(abc.ABC):
    @abc.abstractmethod
    async def read_packet(self, reader: asyncio.StreamReader) -> bytes:
        raise NotImplementedError()

    @abc.abstractmethod
    async def write_packet(self, writer: asyncio.StreamWriter, data: bytes):
        raise NotImplementedError()

    @abc.abstractmethod
    async def write_header(self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader):
        raise NotImplementedError()
