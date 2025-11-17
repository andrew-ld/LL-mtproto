import os.path
import pickle
import traceback
import argparse
import asyncio
import concurrent.futures
import logging
import time

from ll_mtproto import *
from ll_mtproto.crypto.providers.crypto_provider_openssl.crypto_provider_openssl import CryptoProviderOpenSSL

MEDIA_SESSION_POOL_SIZE = 4
BATCH_SIZE = 4
CHUNK_SIZE = 512 * 1024


async def test_download(api_id: int, api_hash: str, bot_token: str, session_name: str):
    connection_info = ConnectionInfo.generate_from_os_info(api_id)
    datacenter_info = TelegramDatacenter.VESTA
    address_resolver = CachedTransportAddressResolver()
    transport_link_factory = TransportLinkTcpFactory(TransportCodecIntermediateFactory(), address_resolver)
    blocking_executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    crypto_provider = CryptoProviderOpenSSL()

    if os.path.exists(session_name):
        with open(session_name, "rb") as session_rb_fd:
            auth_key = pickle.load(session_rb_fd)
    else:
        auth_key = AuthKey()

    def _auth_key_content_change_callback():
        with open(session_name, "wb") as session_wb_fd:
            pickle.dump(auth_key, session_wb_fd)

    auth_key.set_content_change_callback(_auth_key_content_change_callback)

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
        "username": "big_habesha"
    })

    messages = await session.rpc_call({
        "_cons": "channels.getMessages",
        "channel": {
            "_cons": "inputChannel",
            "channel_id": peer.peer.channel_id,
            "access_hash": peer.chats[0].access_hash
        },
        "id": [{"_cons": "inputMessageID", "id": 328}]
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

    print(f"Starting file download... (Total size: {media.size / (1024 * 1024):.2f} MB)")

    requests_batch = []

    start_time = time.time()
    total_downloaded_bytes = 0
    total_requests_sent = 0
    total_failed_requests = 0
    batch_timings = []

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
            total_requests_sent += 1
            current_offset += CHUNK_SIZE

        if not requests_batch:
            break

        active_media_session = media_sessions[session_index % MEDIA_SESSION_POOL_SIZE]
        session_index += 1

        print(
            f"Sending batch of {len(requests_batch)} requests (up to offset {min(current_offset, media.size)}) "
            f"using media session {session_index % MEDIA_SESSION_POOL_SIZE}..."
        )

        batch_start_time = time.time()
        results = await active_media_session.rpc_call_container(requests_batch)
        batch_end_time = time.time()
        batch_timings.append((batch_end_time - batch_start_time, len(requests_batch)))

        downloaded_bytes_in_batch = 0
        failed_requests_in_batch = 0

        for req, res in zip(requests_batch.copy(), results):
            if isinstance(res, RpcErrorException):
                failed_requests_in_batch += 1
            else:
                downloaded_bytes_in_batch += len(res.bytes)
                requests_batch.remove(req)

        total_failed_requests += failed_requests_in_batch
        total_downloaded_bytes += downloaded_bytes_in_batch
        elapsed_time = time.time() - start_time
        speed = total_downloaded_bytes / elapsed_time if elapsed_time > 0 else 0
        speed_in_mbps = speed / (1024 * 1024)
        progress_percent = (total_downloaded_bytes * 100) / media.size

        print(
            f"Downloaded {downloaded_bytes_in_batch / (1024 * 1024):.2f} MB in this batch. "
            f"Progress: {progress_percent:.1f}%. "
            f"Average speed: {speed_in_mbps:.2f} MB/s. "
            f"Failed requests: {failed_requests_in_batch}."
        )

    end_time = time.time()
    print("File download complete.")

    total_time_taken = end_time - start_time
    average_speed_mbps = (total_downloaded_bytes / (1024 * 1024)) / total_time_taken
    total_successful_requests = total_requests_sent - total_failed_requests
    success_rate = (total_successful_requests / total_requests_sent) * 100

    print("\n--- Download Statistics ---")
    print(f"Total File Size: {media.size / (1024 * 1024):.2f} MB")
    print(f"Total Time Taken: {total_time_taken:.2f} seconds")
    print(f"Average Speed: {average_speed_mbps:.2f} MB/s")
    print("-" * 25)
    print("Request Counts:")
    print(f"  Total Chunks (Requests Sent): {total_requests_sent}")
    print(f"  - Successful: {total_successful_requests}")
    print(f"  - Failed: {total_failed_requests}")
    print(f"  Success Rate: {success_rate:.2f}%")
    print("-" * 25)

    total_rpc_time = sum(duration for duration, count in batch_timings)
    avg_batch_time = total_rpc_time / len(batch_timings)
    min_batch_time = min(duration for duration, count in batch_timings)
    max_batch_time = max(duration for duration, count in batch_timings)
    avg_request_time = total_rpc_time / total_requests_sent

    print("Request Timings:")
    print(f"  Average Time per Request: {avg_request_time * 1000:.2f} ms")
    print(f"  Average Time per Batch: {avg_batch_time:.3f} s")
    print(f"  Fastest Batch: {min_batch_time:.3f} s")
    print(f"  Slowest Batch: {max_batch_time:.3f} s")

    print("-" * 25)

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
    _parser.add_argument("--session-name", type=str, required=False, default="media_download_test")

    _parsed_arguments = _parser.parse_args()

    asyncio.run(test_download(_parsed_arguments.api_id, _parsed_arguments.api_hash, _parsed_arguments.bot_token, _parsed_arguments.session_name))