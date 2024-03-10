import asyncio
import concurrent.futures
import logging
import time
import traceback

from ll_mtproto import *
from ll_mtproto.network.transport.transport_codec_abridged import TransportCodecAbridgedFactory
from ll_mtproto.network.transport.transport_codec_base import TransportCodecBase
from ll_mtproto.network.transport.transport_codec_factory import TransportCodecFactory


class TransportCodecPerformanceTrack(TransportCodecBase):
    _parent_codec: TransportCodecBase
    _first_write_time: float | None
    _first_read: bool

    def __init__(self, parent_codec: TransportCodecBase):
        self._parent_codec = parent_codec
        self._first_write_time = None
        self._first_read = True

    async def write_packet(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        try:
            return await self._parent_codec.write_packet(writer, data)
        finally:
            if self._first_write_time is None:
                self._first_write_time = time.time()

    async def read_packet(self, reader: asyncio.StreamReader) -> bytes:
        try:
            return await self._parent_codec.read_packet(reader)
        finally:
            if self._first_read:
                self._first_read = False
                print("difference: ", time.time() - self._first_write_time)


class TransportCodecPerformanceTrackFactory(TransportCodecFactory):
    _parent_factory: TransportCodecFactory

    def __init__(self, parent_factory: TransportCodecFactory):
        self._parent_factory = parent_factory

    def new_codec(self) -> TransportCodecBase:
        return TransportCodecPerformanceTrack(self._parent_factory.new_codec())


async def test():
    connection_info = ConnectionInfo(
        api_id=6,
        device_model="test",
        system_version="test",
        app_version="1.0",
        lang_code="de",
        system_lang_code="de",
        lang_pack=""
    )

    auth_key = AuthKey()
    auth_key.set_content_change_callback(lambda: None)

    datacenter_info = TelegramDatacenter.VESTA
    address_resolver = CachedTransportAddressResolver()
    transport_link_factory = TransportLinkTcpFactory(TransportCodecPerformanceTrackFactory(TransportCodecAbridgedFactory()), address_resolver)
    blocking_executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    crypto_provider = CryptoProviderCryptg()

    session = Client(
        datacenter_info,
        auth_key,
        connection_info,
        transport_link_factory,
        blocking_executor,
        crypto_provider,
        use_perfect_forward_secrecy=True,
        no_updates=False,
        error_description_resolver=None
    )

    configuration = await session.rpc_call({"_cons": "help.getConfig"})
    address_resolver.apply_telegram_config(TelegramDatacenter.ALL_DATACENTERS, configuration)
    session.disconnect()

    while True:
        # noinspection PyBroadException
        try:
            _ = await session.rpc_call({"_cons": "help.getConfig"})
        except:
            traceback.print_exc()
        finally:
            session.disconnect()


if __name__ == "__main__" or __name__ == "uwsgi_file_test":
    logging.getLogger().setLevel(level=logging.ERROR)
    asyncio.run(test())
