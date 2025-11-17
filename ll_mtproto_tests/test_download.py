import traceback
import argparse
import asyncio
import concurrent.futures
import logging

from ll_mtproto import *
from ll_mtproto.crypto.providers.crypto_provider_openssl.crypto_provider_openssl import CryptoProviderOpenSSL


MEDIA_SESSION_POOL_SIZE = 10
BATCH_SIZE = 4
CHUNK_SIZE = 512 * 1024


async def test(api_id: int, api_hash: str, bot_token: str):
    connection_info = ConnectionInfo.generate_from_os_info(api_id)
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

    media_sessions = []

    print(f"Creating a pool of {MEDIA_SESSION_POOL_SIZE} media sessions...")

    for i in range(MEDIA_SESSION_POOL_SIZE):
        media_auth_key = AuthKey(persistent_key=auth_key.persistent_key)

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
        media_sessions.append(media_session)

    for i, s in enumerate(media_sessions):
        print("Initializing session", i)
        configuration = await s.rpc_call({"_cons": "help.getConfig"})
        address_resolver.apply_telegram_config(TelegramDatacenter.ALL_DATACENTERS, configuration)
    print("All media sessions initialized and ready.")

    current_offset = 0
    session_index = 0

    print(f"Starting file download... (Total size: {media.size} bytes)")

    requests_batch = []

    while current_offset < media.size:
        while len(requests_batch) < BATCH_SIZE:
            if current_offset >= media.size:
                break

            get_file_request = {
                "_cons": "upload.getFile",
                "offset": current_offset,
                "limit": CHUNK_SIZE,
                "location": {
                    "_cons": "inputDocumentFileLocation",
                    "id": media.id,
                    "access_hash": media.access_hash,
                    "file_reference": media.file_reference,
                    "thumb_size": ""
                }
            }
            requests_batch.append(get_file_request)
            current_offset += CHUNK_SIZE

        if not requests_batch:
            break

        active_media_session = media_sessions[session_index % MEDIA_SESSION_POOL_SIZE]
        session_index += 1

        print(
            f"Sending batch of {len(requests_batch)} requests (up to offset {min(current_offset, media.size)}) "
            f"using media session {session_index % MEDIA_SESSION_POOL_SIZE}..."
        )

        results = await active_media_session.rpc_call_container(requests_batch)
        downloaded_bytes_in_batch = 0
        failed_requests = 0

        for req, res in zip(requests_batch, results):
            if isinstance(res, RpcErrorException):
                failed_requests += 1
            else:
                downloaded_bytes_in_batch += len(res.bytes)
                requests_batch.remove(req)

        print(f"Downloaded a batch of {downloaded_bytes_in_batch} bytes, Failed {failed_requests} requests.")

    print("File download complete.")

    print("Disconnecting all sessions...")
    for media_session in media_sessions:
        media_session.disconnect()

    session.disconnect()

    print("Done.")


if __name__ == "__main__" or __name__ == "uwsgi_file_test":
    logging.getLogger().setLevel(level=logging.ERROR)

    _parser = argparse.ArgumentParser()
    _parser.add_argument("--api-id", type=int, required=True)
    _parser.add_argument("--api-hash", type=str, required=True)
    _parser.add_argument("--bot-token", type=str, required=True)

    _parsed_arguments = _parser.parse_args()

    asyncio.run(test(_parsed_arguments.api_id, _parsed_arguments.api_hash, _parsed_arguments.bot_token))
