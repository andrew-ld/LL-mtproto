# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2025 (andrew) https://github.com/andrew-ld/LL-mtproto
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import asyncio
import hashlib
import hmac
import logging

from ll_mtproto.crypto.aes_ige import AesIge, AesIgeAsyncStream
from ll_mtproto.crypto.auth_key import Key, DhGenKey
from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase
from ll_mtproto.in_thread import InThread
from ll_mtproto.network.auth_key_not_found_exception import AuthKeyNotFoundException
from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.network.transport.transport_link_base import TransportLinkBase
from ll_mtproto.network.transport.transport_link_factory import TransportLinkFactory
from ll_mtproto.network.transport_error import TransportError
from ll_mtproto.tl.byteutils import sha256, ByteReaderApply, sha1
from ll_mtproto.tl.structure import DynamicStructure, BaseStructure
from ll_mtproto.tl.tl import TlBodyDataValue, Value, TlBodyData, NativeByteReader, extract_cons_from_tl_body
from ll_mtproto.tl.tl_utils import TypedSchemaConstructor
from ll_mtproto.tl.tls_system import MessageInnerDataFromServer, UnencryptedMessage, MessageFromServer

__all__ = ("MTProto",)


class MTProto:
    __slots__ = (
        "_loop",
        "_link",
        "_read_message_lock",
        "_last_message_id",
        "_datacenter",
        "_in_thread",
        "_crypto_provider",
        "_unencrypted_message_constructor",
        "_message_inner_data_from_server_constructor"
    )

    @staticmethod
    def prepare_key_v2(auth_key: bytes, msg_key: bytes, read: bool, crypto_provider: CryptoProviderBase) -> AesIge:
        x = 0 if read else 8

        sha256a = sha256(msg_key, auth_key[x: x + 36])
        sha256b = sha256(auth_key[x + 40:x + 76], msg_key)

        aes_key = sha256a[:8] + sha256b[8:24] + sha256a[24:32]
        aes_iv = sha256b[:8] + sha256a[8:24] + sha256b[24:32]

        return AesIge(aes_key, aes_iv, crypto_provider)

    @staticmethod
    def prepare_key_v1_write(auth_key: bytes, msg_key: bytes, crypto_provider: CryptoProviderBase) -> AesIge:
        sha1_a = sha1(msg_key, auth_key[:32])
        sha1_b = sha1(auth_key[32:48], msg_key + auth_key[48:64])
        sha1_c = sha1(auth_key[64:96], msg_key)
        sha1_d = sha1(msg_key, auth_key[96:128])

        aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]
        aes_iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]

        return AesIge(aes_key, aes_iv, crypto_provider)

    _loop: asyncio.AbstractEventLoop
    _link: TransportLinkBase
    _read_message_lock: asyncio.Lock
    _auth_key_lock: asyncio.Lock
    _last_message_id: int
    _datacenter: DatacenterInfo
    _in_thread: InThread
    _crypto_provider: CryptoProviderBase

    _unencrypted_message_constructor: TypedSchemaConstructor[UnencryptedMessage]
    _message_inner_data_from_server_constructor: TypedSchemaConstructor[MessageInnerDataFromServer]

    def __init__(
            self,
            datacenter: DatacenterInfo,
            transport_link_factory: TransportLinkFactory,
            in_thread: InThread,
            crypto_provider: CryptoProviderBase
    ):
        self._loop = asyncio.get_running_loop()
        self._link = transport_link_factory.new_transport_link(datacenter)
        self._read_message_lock = asyncio.Lock()
        self._last_message_id = 0
        self._datacenter = datacenter
        self._in_thread = in_thread
        self._crypto_provider = crypto_provider
        self._unencrypted_message_constructor = TypedSchemaConstructor(datacenter.schema, UnencryptedMessage)
        self._message_inner_data_from_server_constructor = TypedSchemaConstructor(datacenter.schema, MessageInnerDataFromServer)

    def get_next_message_id(self) -> int:
        message_id = self._datacenter.get_synchronized_time() << 32

        if message_id <= self._last_message_id:
            message_id = self._last_message_id + 1

        while message_id % 4 != 0:
            message_id += 1

        self._last_message_id = message_id

        return message_id

    async def read_unencrypted_message(self) -> tuple[UnencryptedMessage, BaseStructure]:
        async with self._read_message_lock:
            server_auth_key_id = await self._link.readn(8)

            if server_auth_key_id != b"\0\0\0\0\0\0\0\0":
                raise ValueError("Received a message with unknown auth key id!", server_auth_key_id)

            message_id = await self._link.readn(8)

            body_len_envelope = await self._link.readn(4)
            body_len = int.from_bytes(body_len_envelope, signed=False, byteorder="little")
            body_envelope = await self._link.readn(body_len)

            full_message_reader = NativeByteReader(b"".join((server_auth_key_id, message_id, body_len_envelope, body_envelope)))

            try:
                message = await self._in_thread(lambda: self._unencrypted_message_constructor.deserialize_bare_data(full_message_reader))
            finally:
                del full_message_reader

            self._link.discard_packet()

            return message, message.body

    async def write_unencrypted_message(self, **body: TlBodyDataValue) -> None:
        message_id = self.get_next_message_id()

        logging.debug("writing plain message %d (%s)", message_id, extract_cons_from_tl_body(body))

        message = self._datacenter.schema.bare_kwargs(
            _cons="unencrypted_message",
            auth_key_id=0,
            msg_id=message_id,
            body=body,
        )

        await self._link.write(message.get_flat_bytes())

    async def write_encrypted(self, message: Value, key: Key | DhGenKey) -> None:
        auth_key_key, auth_key_id, session = key.get_or_assert_empty()

        message_inner_data = self._datacenter.schema.bare_kwargs(
            _cons="message_inner_data",
            salt=key.server_salt,
            session_id=session.id,
            message=message,
        )

        message_inner_data_envelope = await self._in_thread(message_inner_data.get_flat_bytes)

        padding = await self._in_thread(lambda: self._crypto_provider.secure_random((-(len(message_inner_data_envelope) + 12) % 16 + 12)))
        msg_key = (await self._in_thread(lambda: sha256(auth_key_key[88:88 + 32], message_inner_data_envelope, padding)))[8:24]
        aes = await self._in_thread(lambda: self.prepare_key_v2(auth_key_key, msg_key, True, self._crypto_provider))
        encrypted_message = await self._in_thread(lambda: aes.encrypt(message_inner_data_envelope + padding))

        full_message = self._datacenter.schema.bare_kwargs(
            _cons="encrypted_message",
            auth_key_id=auth_key_id,
            msg_key=msg_key,
            encrypted_data=encrypted_message,
        )

        await self._link.write(full_message.get_flat_bytes())

    async def read_encrypted(self, key: Key | DhGenKey) -> tuple[MessageFromServer, BaseStructure]:
        auth_key_key, auth_key_id, session = key.get_or_assert_empty()

        auth_key_part = auth_key_key[88 + 8:88 + 8 + 32]

        async with self._read_message_lock:
            try:
                server_auth_key_id_bytes = await self._link.readn(8)
            except TransportError as transport_error:
                if transport_error.code == -404:
                    raise AuthKeyNotFoundException() from transport_error
                raise transport_error from transport_error

            server_auth_key_id = int.from_bytes(server_auth_key_id_bytes, "little", signed=True)

            if server_auth_key_id != auth_key_id:
                raise ValueError("Received a message with unknown auth key id!", server_auth_key_id)

            msg_key = await self._link.readn(16)
            msg_aes = await self._in_thread(lambda: self.prepare_key_v2(auth_key_key, msg_key, False, self._crypto_provider))
            msg_aes_stream = AesIgeAsyncStream(msg_aes, self._in_thread, self._link.read)

            plain_sha256 = hashlib.sha256()
            await self._in_thread(lambda: plain_sha256.update(auth_key_part))
            msg_aes_stream_with_hash = ByteReaderApply(msg_aes_stream, plain_sha256.update, self._in_thread)

            message_inner_data_reader = NativeByteReader(await msg_aes_stream_with_hash(8 + 8 + 8 + 4))

            try:
                message = await self._in_thread(lambda: self._message_inner_data_from_server_constructor.deserialize_bare_data(message_inner_data_reader))
            finally:
                del message_inner_data_reader

            message_body_len = int.from_bytes(await msg_aes_stream_with_hash(4), signed=False, byteorder="little")
            message_body_envelope = await msg_aes_stream_with_hash(message_body_len)

            remaining_plain_buffer = msg_aes_stream.remaining_plain_buffer()

            if len(remaining_plain_buffer) not in range(12, 1024):
                raise ValueError("Received a message with wrong padding length!")

            await self._in_thread(lambda: plain_sha256.update(remaining_plain_buffer))
            msg_key_computed = (await self._in_thread(plain_sha256.digest))[8:24]

            if not hmac.compare_digest(msg_key, msg_key_computed):
                raise ValueError("Received a message with unknown msg key!", msg_key, msg_key_computed)

            if (msg_session_id := message.session_id) != session.id:
                raise ValueError("Received a message with unknown session id!", msg_session_id)

            if (msg_msg_id := message.message.msg_id) % 2 != 1:
                raise ValueError("Received message from server to client need odd parity!", msg_msg_id)

            if ((message.message.msg_id >> 32) - self._datacenter.get_synchronized_time()) not in range(-300, 30):
                raise RuntimeError("Time is not synchronised with telegram time!")

            message_body_reader = NativeByteReader(message_body_envelope)

            try:
                message_body = DynamicStructure.from_tl_obj(await self._in_thread(lambda: self._datacenter.schema.read_by_boxed_data(message_body_reader)))
            finally:
                del message_body_reader

            return message.message, message_body

    def prepare_message_for_write(self, seq_no: int, body: TlBodyData | Value) -> tuple[Value, int]:
        if not isinstance(body, Value):
            body = self._datacenter.schema.boxed(body)

        boxed_message_id = self.get_next_message_id()

        boxed_message = self._datacenter.schema.bare_kwargs(
            _cons="message_from_client",
            msg_id=boxed_message_id,
            seqno=seq_no,
            body=body,
        )

        return boxed_message, boxed_message_id

    def close(self) -> None:
        self._link.close()
