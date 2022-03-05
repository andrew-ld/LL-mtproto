import asyncio
import typing

InThread = typing.Callable[..., typing.Awaitable[any]]
ByteReader = typing.Callable[[int], typing.Awaitable[bytes]]
Loop = asyncio.AbstractEventLoop
