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

from ll_mtproto.client.rpc_error import RpcErrorException
from ll_mtproto.crypto.auth_key import Key
from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase
from ll_mtproto.in_thread import InThread
from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.network.dispatcher import Dispatcher, SignalingMessage
from ll_mtproto.network.mtproto import MTProto
from ll_mtproto.tl.byteutils import sha1
from ll_mtproto.tl.structure import Structure
from ll_mtproto.tl.tl import NativeByteReader
from ll_mtproto.tl.tl_utils import flat_value_buffer, TypedSchemaConstructor
from ll_mtproto.tl.tls_system import RpcResult, RpcError, NewSessionCreated, MsgsAck

__all__ = ("MTProtoKeyBinderDispatcher",)


class MTProtoKeyBinderDispatcher(Dispatcher):
    __slots__ = ("_persistent_key", "_used_key", "_result", "_req_msg_id", "_parent_dispatcher", "_datacenter")

    _persistent_key: Key
    _used_key: Key
    _result: asyncio.Future[None]
    _req_msg_id: int
    _parent_dispatcher: Dispatcher
    _datacenter: DatacenterInfo

    @staticmethod
    async def initialize(
            persistent_key: Key,
            used_key: Key,
            in_thread: InThread,
            datacenter: DatacenterInfo,
            mtproto: MTProto,
            crypto_provider: CryptoProviderBase,
            parent_dispatcher: Dispatcher,
            expire_at: int
    ) -> tuple["MTProtoKeyBinderDispatcher", asyncio.Future[None]]:
        req_msg_id = mtproto.get_next_message_id()

        perm_auth_key_key, perm_auth_key_id, _ = persistent_key.get_or_assert_empty()
        used_auth_key_key, used_auth_key_id, used_key_session = used_key.get_or_assert_empty()

        bind_temp_auth_nonce = int.from_bytes(await in_thread(lambda: crypto_provider.secure_random(8)), "big", signed=True)

        bind_temp_auth_inner = datacenter.schema.boxed_kwargs(
            _cons="bind_auth_key_inner",
            nonce=bind_temp_auth_nonce,
            temp_auth_key_id=used_auth_key_id,
            perm_auth_key_id=perm_auth_key_id,
            temp_session_id=used_key_session.id,
            expires_at=expire_at
        )

        bind_temp_auth_inner_data = datacenter.schema.bare_kwargs(
            _cons="message_inner_data",
            salt=int.from_bytes(await in_thread(lambda: crypto_provider.secure_random(8)), "big", signed=True),
            session_id=int.from_bytes(await in_thread(lambda: crypto_provider.secure_random(8)), "big", signed=False),
            message=dict(
                _cons="message_from_client",
                msg_id=req_msg_id,
                seqno=0,
                body=bind_temp_auth_inner
            ),
        ).get_flat_bytes()

        bind_temp_auth_inner_data_sha1 = await in_thread(lambda: sha1(bind_temp_auth_inner_data))
        bind_temp_auth_inner_data_msg_key = bind_temp_auth_inner_data_sha1[4:20]

        bind_temp_auth_inner_data_aes = await in_thread(lambda: MTProto.prepare_key_v1_write(
            perm_auth_key_key,
            bind_temp_auth_inner_data_msg_key,
            crypto_provider
        ))

        bind_temp_auth_inner_data_encrypted = await in_thread(lambda: bind_temp_auth_inner_data_aes.encrypt(bind_temp_auth_inner_data))

        bind_temp_auth_inner_data_encrypted_boxed = datacenter.schema.bare_kwargs(
            _cons="encrypted_message",
            auth_key_id=perm_auth_key_id,
            msg_key=bind_temp_auth_inner_data_msg_key,
            encrypted_data=bind_temp_auth_inner_data_encrypted,
        )

        bind_temp_auth_boxed_message = datacenter.schema.bare_kwargs(
            _cons="message_from_client",
            msg_id=req_msg_id,
            seqno=used_key_session.get_next_odd_seqno(),
            body=dict(
                _cons="auth.bindTempAuthKey",
                perm_auth_key_id=perm_auth_key_id,
                nonce=bind_temp_auth_nonce,
                expires_at=expire_at,
                encrypted_message=bind_temp_auth_inner_data_encrypted_boxed.get_flat_bytes()
            ),
        )

        await mtproto.write_encrypted(bind_temp_auth_boxed_message, used_key)

        result = asyncio.get_running_loop().create_future()
        return MTProtoKeyBinderDispatcher(persistent_key, used_key, result, req_msg_id, parent_dispatcher, datacenter), result

    def __init__(
            self,
            persistent_key: Key,
            used_key: Key,
            result: asyncio.Future[None],
            req_msg_id: int,
            parent_dispatcher: Dispatcher,
            datacenter: DatacenterInfo,
    ) -> None:
        self._persistent_key = persistent_key
        self._used_key = used_key
        self._result = result
        self._req_msg_id = req_msg_id
        self._parent_dispatcher = parent_dispatcher
        self._datacenter = datacenter

    async def process_telegram_message_body(self, body: Structure, crypto_flag: bool) -> None:
        if not crypto_flag:
            raise TypeError(f"Expected an encrypted message, found `{body!r}`")

        if isinstance(body, NewSessionCreated) or isinstance(body, MsgsAck):
            return await self._parent_dispatcher.process_telegram_message_body(body, True)

        if not isinstance(body, RpcResult):
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`, unexpected message", body)

        if body.req_msg_id != self._req_msg_id:
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`, unexpected req_msg_id", body)

        bool_true_cons = self._datacenter.schema.constructors["boolTrue"]

        if bool_true_cons.boxed_buffer_match(body.result):
            return self._result.set_result(None)

        rpc_error_cons = TypedSchemaConstructor(self._datacenter.schema, RpcError)

        if rpc_error_cons.boxed_buffer_match(body.result):
            error_reader = NativeByteReader(flat_value_buffer(body.result))
            error = rpc_error_cons.deserialize_boxed_data(error_reader)
            raise RpcErrorException.from_rpc_error(error)

        raise RuntimeError("Diffie–Hellman exchange failed: `%r`, expected response", body)

    async def process_telegram_signaling_message(self, signaling: SignalingMessage, crypto_flag: bool) -> None:
        if not crypto_flag:
            raise TypeError(f"Expected an encrypted signaling, found `{signaling!r}`")

        await self._parent_dispatcher.process_telegram_signaling_message(signaling, crypto_flag)
