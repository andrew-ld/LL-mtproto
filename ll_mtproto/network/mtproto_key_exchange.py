# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2023 (andrew) https://github.com/andrew-ld/LL-mtproto

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
import secrets
import typing

from . import Dispatcher, dispatch_event
from ..crypto import AesIge, Key, DhGenKey
from ..crypto.providers import CryptoProviderBase
from ..math import primes
from ..network import MTProto, DatacenterInfo
from ..tl import Structure
from ..tl.byteutils import to_bytes, sha1, to_reader, xor, SyncByteReaderApply
from ..typed import InThread

__all__ = ("MTProtoKeyExchange",)


class _KeyExchangeStateWaitingResPq:
    __slots__ = ("nonce",)

    def __init__(self, *, nonce: bytes):
        self.nonce = nonce


class _KeyExchangeStateWaitingDhParams:
    __slots__ = ("nonce", "new_nonce", "server_nonce", "temp_key_expires_in")

    nonce: bytes
    new_nonce: bytes
    server_nonce: bytes
    temp_key_expires_in: int

    def __init__(self, *, nonce: bytes, new_nonce: bytes, server_nonce: bytes, temp_key_expires_in: int):
        self.nonce = nonce
        self.new_nonce = new_nonce
        self.server_nonce = server_nonce
        self.temp_key_expires_in = temp_key_expires_in


class _KeyExchangeStateWaitingDhGenOk:
    __slots__ = ("key", "temp_key_expires_in")

    key: DhGenKey
    temp_key_expires_in: int

    def __init__(self, *, key: DhGenKey, temp_key_expires_in: int):
        self.key = key
        self.temp_key_expires_in = temp_key_expires_in


class _KeyExchangeStateCompleted:
    __slots__ = ("key",)

    key: DhGenKey

    def __init__(self, *, key: DhGenKey):
        self.key = key


class _KeyExchangeStateBindCompleted:
    __slots__ = ("key",)

    key: DhGenKey

    def __init__(self, *, key: DhGenKey):
        self.key = key


class _KeyExchangeStateBindParentKey:
    __slots__ = ("key", "temp_key_expires_in", "req_msg_id")

    key: DhGenKey
    temp_key_expires_in: int
    req_msg_id: int

    def __init__(self, *, key: DhGenKey, temp_key_expires_in: int, req_msg_id: int):
        self.key = key
        self.temp_key_expires_in = temp_key_expires_in
        self.req_msg_id = req_msg_id


class MTProtoKeyExchange(Dispatcher):
    __slots__ = (
        "_mtproto",
        "_in_thread",
        "_datacenter",
        "_crypto_provider",
        "_parent_dispatcher",
        "_parent_key",
        "_exchange_state"
    )

    TEMP_AUTH_KEY_EXPIRE_TIME = 24 * 60 * 60

    _in_thread: InThread
    _mtproto: MTProto
    _datacenter: DatacenterInfo
    _crypto_provider: CryptoProviderBase
    _parent_key: Key | None
    _exchange_state: object | None

    def __init__(
            self,
            mtproto: MTProto,
            in_thread: InThread,
            datacenter: DatacenterInfo,
            crypto_provider: CryptoProviderBase,
            parent_dispatcher: Dispatcher,
            parent_key: Key | None
    ):
        self._mtproto = mtproto
        self._in_thread = in_thread
        self._datacenter = datacenter
        self._crypto_provider = crypto_provider
        self._parent_dispatcher = parent_dispatcher
        self._parent_key = parent_key
        self._exchange_state = None

    async def process_telegram_signaling_message(self, signaling: Structure, crypto_flag: bool):
        if crypto_flag:
            await self._parent_dispatcher.process_telegram_signaling_message(signaling, crypto_flag)
        else:
            await self._mtproto.write_unencrypted_message(_cons="msgs_ack", msg_ids=[signaling.msg_id])

    async def process_telegram_message_body(self, body: Structure, crypto_flag: bool):
        match (state := self._exchange_state):
            case _KeyExchangeStateWaitingResPq():
                await self._process_res_pq(body, state)

            case _KeyExchangeStateWaitingDhParams():
                await self._process_dh_params(body, state)

            case _KeyExchangeStateWaitingDhGenOk():
                await self._process_dh_gen_ok(body, state)

            case _KeyExchangeStateBindParentKey():
                assert crypto_flag
                await self._process_bind_parent_key(body, state)

            case _:
                raise TypeError("Unknown exchange state `%r`", state)

    async def _process_bind_parent_key(self, body: Structure, state: _KeyExchangeStateBindParentKey):
        if body == "new_session_created" or body == "msgs_ack":
            return await self._parent_dispatcher.process_telegram_message_body(body, True)

        if body != "rpc_result":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`, unexpected message", body)

        if body.req_msg_id != state.req_msg_id:
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`, unexpected req_msg_id", body)

        bool_true = self._datacenter.schema.constructors.get("boolTrue", None)

        if bool_true is None:
            raise TypeError(f"Unable to find bool_true constructor")

        if body.result != bool_true.number:
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`, expected response", body)

        self._exchange_state = _KeyExchangeStateBindCompleted(key=state.key)

    async def _process_dh_gen_ok(self, params3: Structure, state: _KeyExchangeStateWaitingDhGenOk):
        if params3 != "dh_gen_ok":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params3)

        if self._parent_key is None:
            self._exchange_state = _KeyExchangeStateCompleted(key=state.key)
        else:
            self._exchange_state = _KeyExchangeStateBindParentKey(
                key=state.key,
                temp_key_expires_in=state.temp_key_expires_in,
                req_msg_id=self._mtproto.get_next_message_id()
            )

    async def _process_dh_params(self, params: Structure, state: _KeyExchangeStateWaitingDhParams):
        if params != "server_DH_params_ok":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params)

        if not hmac.compare_digest(params.nonce, state.nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params nonce mismatch")

        if not hmac.compare_digest(params.server_nonce, state.server_nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params server nonce mismatch")

        tmp_aes_key_1, tmp_aes_key_2, tmp_aes_iv_1, tmp_aes_iv_2 = await asyncio.gather(
            self._in_thread(sha1, state.new_nonce + state.server_nonce),
            self._in_thread(sha1, state.server_nonce + state.new_nonce),
            self._in_thread(sha1, state.server_nonce + state.new_nonce),
            self._in_thread(sha1, state.new_nonce + state.new_nonce)
        )

        tmp_aes_key = tmp_aes_key_1 + tmp_aes_key_2[:12]
        tmp_aes_iv = tmp_aes_iv_1[12:] + tmp_aes_iv_2 + state.new_nonce[:4]
        tmp_aes = AesIge(tmp_aes_key, tmp_aes_iv, self._crypto_provider)

        (answer_hash, answer), b = await asyncio.gather(
            self._in_thread(tmp_aes.decrypt_with_hash, params.encrypted_answer),
            self._in_thread(secrets.randbits, 2048),
        )

        answer_reader = to_reader(answer)
        answer_reader_sha1 = hashlib.sha1()
        answer_reader_with_hash = SyncByteReaderApply(answer_reader, answer_reader_sha1.update)

        params2 = await self._in_thread(self._datacenter.schema.read_by_boxed_data, answer_reader_with_hash)
        answer_hash_computed = await self._in_thread(answer_reader_sha1.digest)

        if not hmac.compare_digest(answer_hash_computed, answer_hash):
            raise RuntimeError("Diffie–Hellman exchange failed: params2 hash mismatch")

        if params2 != "server_DH_inner_data":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params2)

        if not hmac.compare_digest(params2.nonce, state.nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params2 nonce mismatch")

        if not hmac.compare_digest(params2.server_nonce, state.server_nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params2 server nonce mismatch")

        self._datacenter.set_synchronized_time(params2.server_time)

        dh_prime = int.from_bytes(params2.dh_prime, "big")
        g = params2.g
        g_a = int.from_bytes(params2.g_a, "big")

        if not await self._in_thread(primes.is_safe_dh_prime, g, dh_prime):
            raise RuntimeError("Diffie–Hellman exchange failed: unknown dh_prime")

        if g_a <= 1:
            raise RuntimeError("Diffie–Hellman exchange failed: g_a <= 1")

        if g_a >= (dh_prime - 1):
            raise RuntimeError("Diffie–Hellman exchange failed: g_a >= (dh_prime - 1)")

        if g_a < 2 ** (2048 - 64):
            raise RuntimeError("Diffie–Hellman exchange failed: g_a < 2 ** (2048 - 64)")

        if g_a > dh_prime - (2 ** (2048 - 64)):
            raise RuntimeError("Diffie–Hellman exchange failed: g_a > dh_prime - (2 ** (2048 - 64))")

        g_b, auth_key = await asyncio.gather(
            self._in_thread(pow, g, b, dh_prime),
            self._in_thread(pow, g_a, b, dh_prime),
        )

        if g_b <= 1:
            raise RuntimeError("Diffie–Hellman exchange failed: g_b <= 1")

        if g_b >= (dh_prime - 1):
            raise RuntimeError("Diffie–Hellman exchange failed: g_b >= (dh_prime - 1)")

        if g_b < 2 ** (2048 - 64):
            raise RuntimeError("Diffie–Hellman exchange failed: g_b < 2 ** (2048 - 64)")

        if g_b > dh_prime - (2 ** (2048 - 64)):
            raise RuntimeError("Diffie–Hellman exchange failed: g_b > dh_prime - (2 ** (2048 - 64))")

        server_salt = int.from_bytes(xor(state.new_nonce[:8], state.server_nonce[:8]), "little", signed=True)

        new_auth_key = DhGenKey()
        new_auth_key.auth_key = to_bytes(auth_key)
        new_auth_key.auth_key_id = Key.generate_auth_key_id(new_auth_key.auth_key)
        new_auth_key.server_salt = server_salt

        client_dh_inner_data = self._datacenter.schema.boxed(
            _cons="client_DH_inner_data",
            nonce=state.nonce,
            server_nonce=state.server_nonce,
            retry_id=0,
            g_b=to_bytes(g_b),
        ).get_flat_bytes()

        tmp_aes = AesIge(tmp_aes_key, tmp_aes_iv, self._crypto_provider)

        await self._mtproto.write_unencrypted_message(
            _cons="set_client_DH_params",
            nonce=state.nonce,
            server_nonce=state.server_nonce,
            encrypted_data=await self._in_thread(tmp_aes.encrypt_with_hash, client_dh_inner_data),
        )

        self._exchange_state = _KeyExchangeStateWaitingDhGenOk(key=new_auth_key, temp_key_expires_in=state.temp_key_expires_in)

    async def _process_res_pq(self, res_pq: Structure, state: _KeyExchangeStateWaitingResPq):
        if res_pq != "resPQ":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", res_pq)

        if self._datacenter.public_rsa.fingerprint not in res_pq.server_public_key_fingerprints:
            raise ValueError("Our certificate is not supported by the server")

        server_nonce = res_pq.server_nonce
        pq = int.from_bytes(res_pq.pq, "big", signed=False)

        new_nonce, (p, q) = await asyncio.gather(
            self._in_thread(secrets.token_bytes, 32),
            self._in_thread(self._crypto_provider.factorize_pq, pq),
        )

        p_string = to_bytes(p)
        q_string = to_bytes(q)

        if len(p_string) + len(q_string) != 8:
            raise RuntimeError("Diffie–Hellman exchange failed: p q length is invalid, `%r`", pq)

        temp = self._parent_key is not None

        temp_key_expires_in = self.TEMP_AUTH_KEY_EXPIRE_TIME + self._datacenter.get_synchronized_time()

        p_q_inner_data = self._datacenter.schema.boxed(
            _cons="p_q_inner_data_temp_dc" if temp else "p_q_inner_data_dc",
            pq=res_pq.pq,
            p=p_string,
            q=q_string,
            nonce=state.nonce,
            server_nonce=server_nonce,
            new_nonce=new_nonce,
            expires_in=temp_key_expires_in,
            dc=-self._datacenter.datacenter_id if self._datacenter.is_media else self._datacenter.datacenter_id
        )

        p_q_inner_data_rsa_pad = await self._in_thread(
            self._datacenter.public_rsa.rsa_pad,
            p_q_inner_data.get_flat_bytes(),
            self._crypto_provider
        )

        p_q_inner_data_encrypted = await self._in_thread(self._datacenter.public_rsa.encrypt, p_q_inner_data_rsa_pad)

        await self._mtproto.write_unencrypted_message(
            _cons="req_DH_params",
            nonce=state.nonce,
            server_nonce=server_nonce,
            p=p_string,
            q=q_string,
            public_key_fingerprint=self._datacenter.public_rsa.fingerprint,
            encrypted_data=p_q_inner_data_encrypted,
        )

        self._exchange_state = _KeyExchangeStateWaitingDhParams(
            nonce=state.nonce,
            new_nonce=new_nonce,
            server_nonce=server_nonce,
            temp_key_expires_in=temp_key_expires_in
        )

    async def _write_bind_parent_key_request(self, state: _KeyExchangeStateBindParentKey):
        parent_key = self._parent_key

        if parent_key is None:
            raise RuntimeError("Diffie–Hellman exchange failed: parent key become None WTF")

        perm_auth_key_key, perm_auth_key_id, _ = parent_key.get_or_assert_empty()

        bind_temp_auth_nonce = int.from_bytes(await self._in_thread(secrets.token_bytes, 8), "big", signed=True)

        bind_temp_auth_inner = self._datacenter.schema.boxed(
            _cons="bind_auth_key_inner",
            nonce=bind_temp_auth_nonce,
            temp_auth_key_id=state.key.auth_key_id,
            perm_auth_key_id=perm_auth_key_id,
            temp_session_id=state.key.session.id,
            expires_at=state.temp_key_expires_in
        )

        bind_temp_auth_inner_data = self._datacenter.schema.bare(
            _cons="message_inner_data",
            salt=int.from_bytes(await self._in_thread(secrets.token_bytes, 8), "big", signed=True),
            session_id=int.from_bytes(await self._in_thread(secrets.token_bytes, 8), "big", signed=False),
            message=self._datacenter.schema.bare(
                _cons="message",
                msg_id=state.req_msg_id,
                seqno=0,
                body=bind_temp_auth_inner
            ),
        ).get_flat_bytes()

        bind_temp_auth_inner_data_sha1 = await self._in_thread(sha1, bind_temp_auth_inner_data)
        bind_temp_auth_inner_data_msg_key = bind_temp_auth_inner_data_sha1[4:20]

        bind_temp_auth_inner_data_aes: AesIge = await self._in_thread(
            MTProto.prepare_key_v1_write,
            perm_auth_key_key,
            bind_temp_auth_inner_data_msg_key,
            self._crypto_provider
        )

        bind_temp_auth_inner_data_encrypted = await self._in_thread(
            bind_temp_auth_inner_data_aes.encrypt,
            bind_temp_auth_inner_data
        )

        bind_temp_auth_inner_data_encrypted_boxed = self._datacenter.schema.bare(
            _cons="encrypted_message",
            auth_key_id=perm_auth_key_id,
            msg_key=bind_temp_auth_inner_data_msg_key,
            encrypted_data=bind_temp_auth_inner_data_encrypted,
        )

        bind_temp_auth_message = self._datacenter.schema.boxed(
            _cons="auth.bindTempAuthKey",
            perm_auth_key_id=perm_auth_key_id,
            nonce=bind_temp_auth_nonce,
            expires_at=state.temp_key_expires_in,
            encrypted_message=bind_temp_auth_inner_data_encrypted_boxed.get_flat_bytes()
        )

        bind_temp_auth_boxed_message = self._datacenter.schema.bare(
            _cons="message",
            msg_id=state.req_msg_id,
            seqno=state.key.session.get_next_odd_seqno(),
            body=bind_temp_auth_message,
        )

        await self._mtproto.write_encrypted(bind_temp_auth_boxed_message, state.key)

    async def _write_req_pq_multi(self, nonce: bytes):
        await self._mtproto.write_unencrypted_message(_cons="req_pq_multi", nonce=nonce)

    async def generate_key(self) -> DhGenKey:
        nonce = await self._in_thread(secrets.token_bytes, 16)
        await self._write_req_pq_multi(nonce)

        self._exchange_state = _KeyExchangeStateWaitingResPq(nonce=nonce)

        while not isinstance(self._exchange_state, (_KeyExchangeStateCompleted, _KeyExchangeStateBindParentKey)):
            await dispatch_event(self, self._mtproto, None)

        generated_key = typing.cast(_KeyExchangeStateCompleted | _KeyExchangeStateBindParentKey, self._exchange_state).key

        if isinstance(self._exchange_state, _KeyExchangeStateBindParentKey):
            await self._write_bind_parent_key_request(self._exchange_state)

            while not isinstance(self._exchange_state, _KeyExchangeStateBindCompleted):
                await dispatch_event(self, self._mtproto, generated_key)

        return generated_key
