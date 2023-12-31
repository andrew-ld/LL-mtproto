import asyncio
import concurrent.futures
import logging
import typing

from ll_mtproto import TelegramDatacenter
from ll_mtproto.crypto.auth_key import DhGenKey
from ll_mtproto.crypto.providers.crypto_provider_cryptg import CryptoProviderCryptg
from ll_mtproto.network.dh.mtproto_key_creator_dispatcher import initialize_key_creator_dispatcher
from ll_mtproto.network.dispatcher import dispatch_event
from ll_mtproto.network.mtproto import MTProto
from ll_mtproto.network.transport.transport_address_resolver_cached import CachedTransportAddressResolver
from ll_mtproto.network.transport.transport_codec_abridged import TransportCodecAbridgedFactory
from ll_mtproto.network.transport.transport_link_tcp import TransportLinkTcpFactory


async def main() -> typing.NoReturn:
    blocking_executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    datacenter = TelegramDatacenter.VESTA
    crypto_provider = CryptoProviderCryptg()

    async def in_thread(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        return await asyncio.get_running_loop().run_in_executor(blocking_executor, *args, **kwargs)

    mtproto = MTProto(
        datacenter,
        TransportLinkTcpFactory(TransportCodecAbridgedFactory(), CachedTransportAddressResolver()),
        in_thread,
        crypto_provider,
    )

    while True:
        dispatcher, result = await initialize_key_creator_dispatcher(
            False,
            mtproto,
            in_thread,
            TelegramDatacenter.VESTA,
            crypto_provider
        )

        while not result.done():
            await dispatch_event(dispatcher, mtproto, None)

        print("key generated", result.result().auth_key_id)


if __name__ == "__main__":
    logging.getLogger().setLevel(level=logging.DEBUG)
    asyncio.run(main())
