import asyncio
import concurrent.futures
import logging

from ll_mtproto import TelegramDatacenter
from ll_mtproto.client.client import Client
from ll_mtproto.client.connection_info import ConnectionInfo
from ll_mtproto.crypto.auth_key import AuthKey
from ll_mtproto.crypto.providers.crypto_provider_openssl.crypto_provider_openssl import CryptoProviderOpenSSL
from ll_mtproto.network.transport.transport_address_resolver_cached import CachedTransportAddressResolver
from ll_mtproto.network.transport.transport_codec_intermediate import TransportCodecIntermediateFactory
from ll_mtproto.network.transport.transport_link_tcp import TransportLinkTcpFactory


# noinspection PyProtectedMember
async def main():
    logging.getLogger().setLevel(level=logging.DEBUG)

    connection_info = ConnectionInfo.generate_from_os_info(6)
    auth_key = AuthKey()
    datacenter_info = TelegramDatacenter.VESTA
    address_resolver = CachedTransportAddressResolver()
    transport_link_factory = TransportLinkTcpFactory(TransportCodecIntermediateFactory(), address_resolver)
    blocking_executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    crypto_provider = CryptoProviderOpenSSL()

    session = Client(
        datacenter_info,
        auth_key,
        connection_info,
        transport_link_factory,
        blocking_executor,
        crypto_provider,
        use_perfect_forward_secrecy=True,
        no_updates=True,
    )

    print(await session.rpc_call_container([{"_cons": "help.getConfig"}, {"_cons": "help.getConfig"}]))

    # I deliberately break the auth_key status to see if the client can restore it
    session._used_session_key.session.seqno = 0
    session._used_session_key.server_salt = 0
    print(await session.rpc_call_container([{"_cons": "help.getConfig"}, {"_cons": "help.getConfig"}]))

    # I deliberately break the auth_key status to see if the client can restore it
    session._used_session_key.session.seqno = 6969
    session._used_session_key.server_salt = -1
    print(await session.rpc_call_container([{"_cons": "help.getConfig"}, {"_cons": "help.getConfig"}]))

    session.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
