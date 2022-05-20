import asyncio
import typing

if typing.TYPE_CHECKING:
    from .tl.tl import Structure
else:
    Structure = None

__all__ = ("InThread", "ByteReader", "PartialByteReader", "Loop", "ByteConsumer", "RpcError", "TlMessageBody")

InThread = typing.Callable[..., typing.Awaitable[any]]
ByteReader = typing.Callable[[int], typing.Awaitable[bytes]]
SyncByteReader = typing.Callable[[int], bytes]
PartialByteReader = typing.Callable[[], typing.Awaitable[bytes]]
Loop = asyncio.AbstractEventLoop
ByteConsumer = typing.Callable[[bytes], None]
TlMessageBody = Structure | list[Structure]


class RpcError(BaseException):
    __slots__ = ("code", "message")

    code: int
    message: str

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
