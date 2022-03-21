import asyncio
import logging
import argparse

from ll_mtproto import Client, TelegramSchema, AuthKey, TelegramDatacenter


async def get_updates(client: Client):
    while True:
        update = await client.get_update()

        if update:
            print("received", update.update.get_dict())


async def test(api_id: int, api_hash: str, bot_token: str):
    logging.getLogger().setLevel(level=logging.DEBUG)

    auth_key = AuthKey()
    session = Client(TelegramDatacenter.VESTA, auth_key)

    asyncio.get_event_loop().create_task(get_updates(session))

    await session.rpc_call({
        "_cons": "invokeWithLayer",
        "layer": TelegramSchema.SCHEME_LAYER,
        "_wrapped": {
            "_cons": "initConnection",
            "api_id": api_id,
            "device_model": "1",
            "system_version": "1",
            "app_version": "1",
            "lang_code": "it",
            "system_lang_code": "it",
            "lang_pack": "",
            "_wrapped": {
                "_cons": "invokeWithoutUpdates",
                "_wrapped": {
                    "_cons": "auth.importBotAuthorization",
                    "api_id": api_id,
                    "api_hash": api_hash,
                    "flags": 0,
                    "bot_auth_token": bot_token
                }
            },
        },
    })

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
        "id": [{"_cons": "inputMessageID", "id": 4}]
    })

    media = messages.messages[0].media.document

    media_session = Client(TelegramDatacenter.VESTA_MEDIA, auth_key)

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
    session.disconnect()


if __name__ == "__main__":
    _parser = argparse.ArgumentParser()
    _parser.add_argument("--api-id", type=int, required=True)
    _parser.add_argument("--api-hash", type=str, required=True)
    _parser.add_argument("--bot-token", type=str, required=True)

    _parsed_arguments = _parser.parse_args()

    asyncio.run(test(_parsed_arguments.api_id, _parsed_arguments.api_hash, _parsed_arguments.bot_token))
