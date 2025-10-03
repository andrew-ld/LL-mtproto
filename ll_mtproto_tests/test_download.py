import traceback
import argparse
import asyncio
import concurrent.futures
import logging

from ll_mtproto import *
from ll_mtproto.crypto.providers.crypto_provider_openssl.crypto_provider_openssl import CryptoProviderOpenSSL


async def get_updates(client: Client):
    while True:
        update = await client.get_update()

        if update:
            print("received", update.update.as_tl_body_data())


async def test(api_id: int, api_hash: str, bot_token: str):
    logging.getLogger().setLevel(level=logging.DEBUG)

    connection_info = ConnectionInfo.generate_from_os_info(api_id)

    auth_key = AuthKey()

    def on_auth_key_updated():
        print("auth key updated:", auth_key)

    auth_key.set_content_change_callback(on_auth_key_updated)

    datacenter_info = TelegramDatacenter.VESTA

    address_resolver = CachedTransportAddressResolver()

    transport_link_factory = TransportLinkTcpFactory(TransportCodecIntermediateFactory(), address_resolver)

    blocking_executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)

    crypto_provider = CryptoProviderOpenSSL()

    error_description_resolver = PwrTelegramErrorDescriptionResolver()

    try:
        error_description_resolver.synchronous_fetch_database()
    except:
        traceback.print_exc()
        error_description_resolver = None

    session = Client(
        datacenter_info,
        auth_key,
        connection_info,
        transport_link_factory,
        blocking_executor,
        crypto_provider,
        use_perfect_forward_secrecy=True,
        no_updates=False,
        error_description_resolver=error_description_resolver
    )

    get_updates_task = asyncio.get_event_loop().create_task(get_updates(session))

    configuration = await session.rpc_call({"_cons": "help.getConfig"})

    address_resolver.apply_telegram_config(TelegramDatacenter.ALL_DATACENTERS, configuration)

    session.disconnect()

    await session.rpc_call({
        "_cons": "auth.importBotAuthorization",
        "api_id": api_id,
        "api_hash": api_hash,
        "flags": 0,
        "bot_auth_token": bot_token
    })

    peer = await session.rpc_call({
        "_cons": "contacts.resolveUsername",
        "username": "eqf3wefwe"
    })

    # I deliberately break the auth_key status to see if the client can restore it
    session._used_session_key.session.seqno = 0
    session._used_session_key.server_salt = 0
    await session.rpc_call({"_cons": "help.getConfig"})

    # I deliberately break the auth_key status to see if the client can restore it
    session._used_session_key.session.seqno = 6969
    session._used_session_key.server_salt = -1
    await session.rpc_call({"_cons": "help.getConfig"})

    # I deliberately write a non-serializable message to check if the error is propagated correctly
    try:
        await session.rpc_call({"_cons": "lol"})
    except:
        print("ok serialization error received")
    else:
        raise asyncio.InvalidStateError("error not received")

    messages = await session.rpc_call({
        "_cons": "channels.getMessages",
        "channel": {
            "_cons": "inputChannel",
            "channel_id": peer.peer.channel_id,
            "access_hash": peer.chats[0].access_hash
        },
        "id": [{"_cons": "inputMessageID", "id": 5}]
    })

    media = messages.messages[0].media.document
    media_auth_key = AuthKey(persistent_key=auth_key.persistent_key)

    def on_media_auth_key_updated():
        print("media auth key updated:", media_auth_key)

    media_auth_key.set_content_change_callback(on_media_auth_key_updated)

    media_session = Client(
        TelegramDatacenter.VESTA_MEDIA,
        media_auth_key,
        connection_info,
        transport_link_factory,
        blocking_executor,
        crypto_provider,
        use_perfect_forward_secrecy=True,
        no_updates=True
    )

    get_file_request = {
        "_cons": "upload.getFile",
        "offset": 0,
        "limit": 1024 * 1024,
        "location": {
            "_cons": "inputDocumentFileLocation",
            "id": media.id,
            "access_hash": media.access_hash,
            "file_reference": media.file_reference,
            "thumb_size": ""
        }
    }

    while get_file_request["offset"] < media.size:
        await media_session.rpc_call(get_file_request)
        get_file_request["offset"] += get_file_request["limit"]

    media_session.disconnect()
    get_updates_task.cancel()
    session.disconnect()


if __name__ == "__main__" or __name__ == "uwsgi_file_test":
    _parser = argparse.ArgumentParser()
    _parser.add_argument("--api-id", type=int, required=True)
    _parser.add_argument("--api-hash", type=str, required=True)
    _parser.add_argument("--bot-token", type=str, required=True)

    _parsed_arguments = _parser.parse_args()

    asyncio.run(test(_parsed_arguments.api_id, _parsed_arguments.api_hash, _parsed_arguments.bot_token))
