import asyncio
import collections
import copy
import logging
import argparse

from ll_mtproto import Client, AuthKey, TelegramDatacenter, ConnectionInfo
from ll_mtproto.network.transport.transport_codec_abridged import TransportCodecAbridged
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

    init_info = ConnectionInfo(
        api_id=api_id,
        device_model="enterprise desktop computer 2",
        system_version="linux 5.777",
        app_version="1.1",
        lang_code="de",
        system_lang_code="de",
        lang_pack=""
    )

    transport_link_factory = TransportLinkTcpFactory(TransportCodecAbridged())

    session = Client(datacenter_info, auth_key, init_info, transport_link_factory)

    get_updates_task = asyncio.get_event_loop().create_task(get_updates(session))

    await session.rpc_call({
        "_cons": "auth.importBotAuthorization",
        "api_id": api_id,
        "api_hash": api_hash,
        "flags": 0,
        "bot_auth_token": bot_token
    })

    multiple_requests_test = await session.rpc_call_multi([
        {
            "_cons": "contacts.resolveUsername",
            "username": "hackernews"
        },
        {
            "_cons": "contacts.resolveUsername",
            "username": "linuxita"
        },
        {
            "_cons": "contacts.resolveUsername",
            "username": "infosecita"
        },
    ])

    print(multiple_requests_test)

    peer = await session.rpc_call({
        "_cons": "contacts.resolveUsername",
        "username": "eqf3wefwe"
    })

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

    media_sessions = collections.deque()

    for _ in range(2):
        media_sessions.append(Client(TelegramDatacenter.VESTA_MEDIA, copy.copy(auth_key), init_info, transport_link_factory, True))

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

    pending_results = []

    while get_file_request["offset"] < media.size:
        media_sessions.rotate(1)
        media_session = media_sessions[0]

        get_file_task = asyncio.ensure_future(media_session.rpc_call(get_file_request))
        get_file_request["offset"] += get_file_request["limit"]

        pending_results.append(get_file_task)

        if len(pending_results) == len(media_sessions):
            completed, _ = await asyncio.wait(pending_results, return_when=asyncio.FIRST_COMPLETED)

            for task in completed:
                pending_results.remove(task)
                task.exception()

    if pending_results:
        await asyncio.gather(*pending_results, return_exceptions=True)

    for media_session in media_sessions:
        media_session.disconnect()

    get_updates_task.cancel()
    session.disconnect()


if __name__ == "__main__":
    _parser = argparse.ArgumentParser()
    _parser.add_argument("--api-id", type=int, required=True)
    _parser.add_argument("--api-hash", type=str, required=True)
    _parser.add_argument("--bot-token", type=str, required=True)

    _parsed_arguments = _parser.parse_args()

    asyncio.run(test(_parsed_arguments.api_id, _parsed_arguments.api_hash, _parsed_arguments.bot_token))
