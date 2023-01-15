import argparse
import asyncio
import concurrent.futures
import copy
import logging

from ll_mtproto import Client, AuthKey, TelegramDatacenter, ConnectionInfo
from ll_mtproto.network.transport import CachedTransportAddressResolver
from ll_mtproto.network.transport.transport_codec_intermediate import TransportCodecIntermediate
from ll_mtproto.network.transport.transport_link_tcp import TransportLinkTcpFactory


async def get_updates(client: Client):
    while True:
        update = await client.get_update()

        if update:
            print("received", update.update.get_dict())


async def test(api_id: int, api_hash: str, bot_token: str):
    logging.getLogger().setLevel(level=logging.DEBUG)

    auth_key = AuthKey()
    datacenter_info = TelegramDatacenter.VESTA

    connection_info = ConnectionInfo(
        api_id=api_id,
        device_model="enterprise desktop computer 2",
        system_version="linux 5.777",
        app_version="1.1",
        lang_code="de",
        system_lang_code="de",
        lang_pack=""
    )

    address_resolver = CachedTransportAddressResolver()
    transport_link_factory = TransportLinkTcpFactory(TransportCodecIntermediate(), address_resolver)

    blocking_executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)

    session = Client(
        datacenter_info,
        auth_key,
        connection_info,
        transport_link_factory,
        blocking_executor,
        use_perfect_forward_secrecy=True,
        no_updates=False
    )

    get_updates_task = asyncio.get_event_loop().create_task(get_updates(session))

    config = await session.rpc_call({"_cons": "help.getConfig"})

    CachedTransportAddressResolver.apply_help_getconfig(address_resolver, TelegramDatacenter.ALL_DATACENTERS, config)

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
    session._bound_auth_key.seq_no = -1
    session._bound_auth_key.server_salt = -1
    await session.rpc_call({"_cons": "help.getConfig"})

    # I voluntarily write a non-serializable message to check if the error is propagated correctly
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

    media_session = Client(
        TelegramDatacenter.VESTA_MEDIA,
        copy.copy(auth_key),
        connection_info,
        transport_link_factory,
        blocking_executor,
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
