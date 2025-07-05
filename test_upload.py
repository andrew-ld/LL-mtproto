import argparse
import asyncio
import concurrent.futures
import logging
import multiprocessing
import os
import secrets
import time

from ll_mtproto import *


async def test(api_id: int, api_hash: str, bot_token: str):
    logging.getLogger().setLevel(level=logging.ERROR)

    connection_info = ConnectionInfo.generate_from_os_info(api_id)
    auth_key = AuthKey()
    auth_key.set_content_change_callback(lambda: None)
    datacenter_info = TelegramDatacenter.VESTA
    address_resolver = CachedTransportAddressResolver()
    transport_link_factory = TransportLinkTcpFactory(TransportCodecAbridgedFactory(), address_resolver)
    blocking_executor = concurrent.futures.ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())
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
        error_description_resolver=None
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

    media_sessions = []

    for _ in range(10):
        new_media_auth_key = AuthKey(persistent_key=auth_key.persistent_key)
        new_media_auth_key.set_content_change_callback(lambda: None)

        new_media_session = Client(
            TelegramDatacenter.VESTA_MEDIA,
            new_media_auth_key,
            connection_info,
            transport_link_factory,
            blocking_executor,
            crypto_provider,
            use_perfect_forward_secrecy=True,
            no_updates=True
        )

        media_sessions.append(new_media_session)

    media_sessions_tasks = []

    file_block_size = 524288
    file_part = os.urandom(file_block_size)
    assert len(file_part) == file_block_size
    file_id = secrets.randbits(63)
    file_size = 1048576000
    file_parts = file_size // file_block_size

    requests_queue = asyncio.Queue()

    for file_part_number in range(file_parts):
        request = {
            "_cons": "upload.saveBigFilePart",
            "file_id": file_id,
            "bytes": file_part,
            "file_total_parts": file_parts,
            "file_part": file_part_number
        }
        requests_queue.put_nowait((request, file_part_number))

    print("starting upload")
    current_time = time.time()

    for media_session in media_sessions:
        async def upload_task():
            while requests_queue.qsize():
                (pending_request, pending_request_part_number) = requests_queue.get_nowait()
                if pending_request_part_number % 100 == 0:
                    print("uploading part", pending_request_part_number, "elapsed time", time.time() - current_time)
                while True:
                    try:
                        await media_session.rpc_call(pending_request)
                        break
                    except RpcError as rpc_error:
                        if rpc_error.code == 420:
                            continue
                        raise rpc_error from rpc_error

        media_sessions_tasks.append(upload_task())

    await asyncio.gather(*media_sessions_tasks)

    for media_session in media_sessions:
        media_session.disconnect()

    session.disconnect()

    print("upload done in", time.time() - current_time, "seconds")


if __name__ == "__main__" or __name__ == "uwsgi_file_test":
    _parser = argparse.ArgumentParser()
    _parser.add_argument("--api-id", type=int, required=True)
    _parser.add_argument("--api-hash", type=str, required=True)
    _parser.add_argument("--bot-token", type=str, required=True)

    _parsed_arguments = _parser.parse_args()

    asyncio.run(test(_parsed_arguments.api_id, _parsed_arguments.api_hash, _parsed_arguments.bot_token))
