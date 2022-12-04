import asyncio
import collections
import hashlib
import hmac
import logging
import secrets

from .datacenter_info import DatacenterInfo
from .transport import TransportLinkBase, TransportLinkFactory
from ..crypto import AuthKey
from ..crypto.aes_ige import AesIge, AesIgeAsyncStream
from ..tl import tl
from ..tl.byteutils import sha256, ByteReaderApply, to_reader, reader_discard, sha1
from ..tl.tl import Structure
from ..typed import InThread

__all__ = ("MTProto",)


class MTProto:
    __slots__ = (
        "_loop",
        "_link",
        "_read_message_lock",
        "_last_message_id",
        "_last_msg_ids",
        "_datacenter",
        "_in_thread"
    )

    @staticmethod
    def prepare_key_v2(auth_key: bytes, msg_key: bytes, read: bool) -> AesIge:
        x = 0 if read else 8

        sha256a = sha256(msg_key + auth_key[x: x + 36])
        sha256b = sha256(auth_key[x + 40:x + 76] + msg_key)

        aes_key = sha256a[:8] + sha256b[8:24] + sha256a[24:32]
        aes_iv = sha256b[:8] + sha256a[8:24] + sha256b[24:32]

        return AesIge(aes_key, aes_iv)

    @staticmethod
    def prepare_key_v1_write(auth_key: bytes, msg_key: bytes) -> AesIge:
        sha1_a = sha1(msg_key + auth_key[:32])
        sha1_b = sha1(auth_key[32:48] + msg_key + auth_key[48:64])
        sha1_c = sha1(auth_key[64:96] + msg_key)
        sha1_d = sha1(msg_key + auth_key[96:128])

        aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]
        aes_iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]

        return AesIge(aes_key, aes_iv)

    _loop: asyncio.AbstractEventLoop
    _link: TransportLinkBase
    _read_message_lock: asyncio.Lock
    _auth_key_lock: asyncio.Lock
    _last_message_id: int
    _last_msg_ids: collections.deque[int]
    _datacenter: DatacenterInfo
    _in_thread: InThread

    def __init__(self, datacenter: DatacenterInfo, transport_link_factory: TransportLinkFactory, in_thread: InThread):
        self._loop = asyncio.get_running_loop()
        self._link = transport_link_factory.new_transport_link(datacenter)
        self._read_message_lock = asyncio.Lock()
        self._last_message_id = 0
        self._last_msg_ids = collections.deque(maxlen=64)
        self._datacenter = datacenter
        self._in_thread = in_thread

    def get_next_message_id(self) -> int:
        message_id = self._datacenter.get_synchronized_time() * 4294967296

        if message_id <= self._last_message_id:
            message_id = self._last_message_id + 1

        while message_id % 4 != 0:
            message_id += 1

        self._last_message_id = message_id

        return message_id

    async def read_unencrypted_message(self) -> Structure:
        async with self._read_message_lock:
            unencrypted_message_header_envelope = await self._link.readn(8 + 8)

            body_len_envelope = await self._link.readn(4)
            body_len = int.from_bytes(body_len_envelope, signed=False, byteorder="little")
            body_envelope = await self._link.readn(body_len)

            full_message = unencrypted_message_header_envelope + body_len_envelope + body_envelope
            full_message_reader = to_reader(full_message)

            try:
                return await self._in_thread(self._datacenter.schema.read, full_message_reader, False, "unencrypted_message")
            finally:
                reader_discard(full_message_reader)

    async def write_unencrypted_message(self, **kwargs):
        message = self._datacenter.schema.bare(
            _cons="unencrypted_message",
            auth_key_id=0,
            message_id=0,
            body=self._datacenter.schema.boxed(**kwargs),
        )

        await self._link.write(message.get_flat_bytes())

    async def write_encrypted(self, message: tl.Value, auth_key: AuthKey):
        auth_key_key, auth_key_id = auth_key.get_or_assert_empty()

        message_inner_data = self._datacenter.schema.bare(
            _cons="message_inner_data",
            salt=auth_key.server_salt,
            session_id=auth_key.session_id,
            message=message,
        )

        message_inner_data_envelope = await self._in_thread(message_inner_data.get_flat_bytes)

        padding = await self._in_thread(secrets.token_bytes, (-(len(message_inner_data_envelope) + 12) % 16 + 12))
        msg_key = (await self._in_thread(sha256, auth_key_key[88:88 + 32] + message_inner_data_envelope + padding))[8:24]
        aes = await self._in_thread(self.prepare_key_v2, auth_key_key, msg_key, True)
        encrypted_message = await self._in_thread(aes.encrypt, message_inner_data_envelope + padding)

        full_message = self._datacenter.schema.bare(
            _cons="encrypted_message",
            auth_key_id=auth_key_id,
            msg_key=msg_key,
            encrypted_data=encrypted_message,
        )

        await self._link.write(full_message.get_flat_bytes())

    async def read_encrypted(self, auth_key: AuthKey) -> Structure:
        auth_key_key, auth_key_id = auth_key.get_or_assert_empty()

        auth_key_part = auth_key_key[88 + 8:88 + 8 + 32]

        async with self._read_message_lock:
            server_auth_key_id = await self._link.readn(8)

            if server_auth_key_id == b"l\xfe\xff\xffl\xfe\xff\xff":
                raise ValueError("Received a message with corrupted authorization!")

            if server_auth_key_id == b'S\xfe\xff\xffS\xfe\xff\xff':
                raise ValueError("Too many requests!")

            server_auth_key_id = int.from_bytes(server_auth_key_id, "little", signed=False)

            if server_auth_key_id != auth_key_id:
                raise ValueError("Received a message with unknown auth key id!", server_auth_key_id)

            msg_key = await self._link.readn(16)
            msg_aes = await self._in_thread(self.prepare_key_v2, auth_key_key, msg_key, False)
            msg_aes_stream = AesIgeAsyncStream(msg_aes, self._in_thread, self._link.read)

            plain_sha256 = hashlib.sha256()
            await self._in_thread(plain_sha256.update, auth_key_part)
            msg_aes_stream_with_hash = ByteReaderApply(msg_aes_stream, plain_sha256.update, self._in_thread)

            message_inner_data_reader = to_reader(await msg_aes_stream_with_hash(8 + 8 + 8 + 4))

            try:
                message = self._datacenter.schema.read(message_inner_data_reader, False, "message_inner_data_from_server")
            finally:
                reader_discard(message_inner_data_reader)

            message_body_len = int.from_bytes(await msg_aes_stream_with_hash(4), signed=False, byteorder="little")
            message_body_envelope = await msg_aes_stream_with_hash(message_body_len)

            if len(msg_aes_stream.remaining_plain_buffer()) not in range(12, 1024):
                raise ValueError("Received a message with wrong padding length!")

            await self._in_thread(plain_sha256.update, msg_aes_stream.remaining_plain_buffer())
            msg_key_computed = (await self._in_thread(plain_sha256.digest))[8:24]

            if not hmac.compare_digest(msg_key, msg_key_computed):
                raise ValueError("Received a message with unknown msg key!", msg_key, msg_key_computed)

            if (msg_session_id := message.session_id) != auth_key.session_id:
                raise ValueError("Received a message with unknown session id!", msg_session_id)

            if (msg_msg_id := message.message.msg_id) % 2 != 1:
                raise ValueError("Received message from server to client need odd parity!", msg_msg_id)

            if (msg_msg_id := message.message.msg_id) in self._last_msg_ids:
                raise ValueError("Received duplicated message from server to client", msg_msg_id)
            else:
                self._last_msg_ids.append(msg_msg_id)

            if (int(message.message.msg_id / 4294967296) - self._datacenter.get_synchronized_time()) not in range(-300, 30):
                raise RuntimeError("Time is not synchronised with telegram time!")

            if (msg_salt := message.salt) != auth_key.server_salt:
                logging.error("received a message with unknown salt! %d", msg_salt)

            message_body_reader = to_reader(message_body_envelope)

            try:
                message.message._fields["body"] = await self._in_thread(self._datacenter.schema.read, message_body_reader)
            finally:
                reader_discard(message_body_reader)

            return message.message

    def prepare_message_for_write(self, seq_no: int, **kwargs) -> tuple[tl.Value, int]:
        boxed_message_id = self.get_next_message_id()

        boxed_message = self._datacenter.schema.bare(
            _cons="message",
            msg_id=boxed_message_id,
            seqno=seq_no,
            body=self._datacenter.schema.boxed(**kwargs),
        )

        return boxed_message, boxed_message_id

    def stop(self):
        self._link.stop()
        logging.debug("disconnected from Telegram")
