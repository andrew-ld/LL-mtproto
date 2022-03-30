import asyncio
import typing

__all__ = ("InThread", "ByteReader", "PartialByteReader", "Loop", "ByteConsumer", "RpcError")

InThread = typing.Callable[..., typing.Awaitable[any]]
ByteReader = typing.Callable[[int], typing.Awaitable[bytes]]
PartialByteReader = typing.Callable[[], typing.Awaitable[bytes]]
Loop = asyncio.AbstractEventLoop
ByteConsumer = typing.Callable[[bytes], None]


class RpcError(BaseException):
    __slots__ = ("code", "message")

    code: int
    message: bytes

    def __init__(self, code: int, message: bytes):
        self.code = code
        self.message = message
