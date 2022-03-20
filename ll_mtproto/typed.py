import asyncio
import typing

__all__ = ("InThread", "ByteReader", "PartialByteReader", "Loop", "ByteConsumer")

InThread = typing.Callable[..., typing.Awaitable[any]]
ByteReader = typing.Callable[[int], typing.Awaitable[bytes]]
PartialByteReader = typing.Callable[[], typing.Awaitable[bytes]]
Loop = asyncio.AbstractEventLoop
ByteConsumer = typing.Callable[[bytes], None]
