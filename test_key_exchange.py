import asyncio
import concurrent.futures
import logging
import typing

from ll_mtproto import TelegramDatacenter
from ll_mtproto.client.client import Client
from ll_mtproto.client.connection_info import ConnectionInfo
from ll_mtproto.crypto.auth_key import AuthKey
from ll_mtproto.crypto.providers.crypto_provider_openssl.crypto_provider_openssl import CryptoProviderOpenSSL
from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.network.dh.mtproto_key_creator_dispatcher import initialize_key_creator_dispatcher
from ll_mtproto.network.dispatcher import dispatch_event
from ll_mtproto.network.mtproto import MTProto
from ll_mtproto.network.transport.transport_address_resolver_cached import CachedTransportAddressResolver
from ll_mtproto.network.transport.transport_codec_abridged import TransportCodecAbridgedFactory
from ll_mtproto.network.transport.transport_link_tcp import TransportLinkTcpFactory

blocking_executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
crypto_provider = CryptoProviderOpenSSL()
resolver = CachedTransportAddressResolver()
link = TransportLinkTcpFactory(TransportCodecAbridgedFactory(), resolver)


async def in_thread(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
    return await asyncio.get_running_loop().run_in_executor(blocking_executor, *args, **kwargs)


async def main():
    tasks = []

    async def configure_resolver():
        tmp_connection_info = ConnectionInfo.generate_from_os_info(6)
        tmp_datacenter_info = TelegramDatacenter.VENUS

        tmp_auth_key = AuthKey()
        tmp_auth_key.set_content_change_callback(lambda: None)

        tmp_client = Client(tmp_datacenter_info, tmp_auth_key, tmp_connection_info, link, blocking_executor, crypto_provider)

        try:
            resolver.apply_telegram_config(TelegramDatacenter.ALL_DATACENTERS, await tmp_client.rpc_call({"_cons": "help.getConfig"}))
        finally:
            tmp_client.disconnect()

    await configure_resolver()

    for dc in TelegramDatacenter.ALL_DATACENTERS:
        for _ in range(2):
            tasks.append(test_exchange(dc, True))

        for _ in range(2):
            tasks.append(test_exchange(dc, False))

    await asyncio.gather(*tasks)


async def test_exchange(datacenter: DatacenterInfo, temp_key: bool) -> None:
    mtproto = MTProto(
        datacenter,
        link,
        in_thread,
        crypto_provider,
    )

    while True:
        dispatcher, result = await initialize_key_creator_dispatcher(
            temp_key,
            mtproto,
            in_thread,
            datacenter,
            crypto_provider
        )

        while not result.done():
            await dispatch_event(dispatcher, mtproto, None)

        print("key generated", result.result().auth_key_id)


if __name__ == "__main__":
    logging.getLogger().setLevel(level=logging.DEBUG)
    asyncio.run(main())
