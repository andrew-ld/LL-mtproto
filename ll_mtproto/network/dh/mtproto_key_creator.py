# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2024 (andrew) https://github.com/andrew-ld/LL-mtproto

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

from ll_mtproto.crypto.aes_ige import AesIge
from ll_mtproto.crypto.auth_key import Key, DhGenKey
from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase
from ll_mtproto.math import primes
from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.network.mtproto import MTProto
from ll_mtproto.tl.byteutils import to_bytes, sha1, to_reader, xor, SyncByteReaderApply
from ll_mtproto.tl.structure import Structure
from ll_mtproto.typed import InThread

__all__ = ("MTProtoKeyCreator",)


class _KeyExchangeStateWaitingResPq:
    def __init__(self) -> None:
        pass


class _KeyExchangeStateWaitingDhParams:
    __slots__ = ("new_nonce", "server_nonce", "temp_key_expires_in")

    new_nonce: bytes
    server_nonce: bytes
    temp_key_expires_in: int

    def __init__(self, *, new_nonce: bytes, server_nonce: bytes, temp_key_expires_in: int):
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


class MTProtoKeyCreator:
    __slots__ = (
        "_mtproto",
        "_in_thread",
        "_datacenter",
        "_crypto_provider",
        "_exchange_state",
        "_temp_key",
        "_nonce",
        "_result"
    )

    TEMP_AUTH_KEY_EXPIRE_TIME = 24 * 60 * 60

    _in_thread: InThread
    _mtproto: MTProto
    _datacenter: DatacenterInfo
    _crypto_provider: CryptoProviderBase
    _temp_key: bool
    _exchange_state: _KeyExchangeStateWaitingResPq | _KeyExchangeStateWaitingDhParams | _KeyExchangeStateWaitingDhGenOk | _KeyExchangeStateCompleted
    _nonce: bytes
    _result: asyncio.Future[DhGenKey]

    @staticmethod
    async def initializate(
            mtproto: MTProto,
            in_thread: InThread,
            datacenter: DatacenterInfo,
            crypto_provider: CryptoProviderBase,
            temp_key: bool,
            result: asyncio.Future[DhGenKey]
    ) -> "MTProtoKeyCreator":
        nonce = await in_thread(lambda: secrets.token_bytes(16))
        await mtproto.write_unencrypted_message(_cons="req_pq_multi", nonce=nonce)
        return MTProtoKeyCreator(mtproto, in_thread, datacenter, crypto_provider, temp_key, nonce, result)

    def __init__(
            self,
            mtproto: MTProto,
            in_thread: InThread,
            datacenter: DatacenterInfo,
            crypto_provider: CryptoProviderBase,
            temp_key: bool,
            nonce: bytes,
            result: asyncio.Future[DhGenKey]
    ):
        self._mtproto = mtproto
        self._in_thread = in_thread
        self._datacenter = datacenter
        self._crypto_provider = crypto_provider
        self._temp_key = temp_key
        self._nonce = nonce
        self._exchange_state = _KeyExchangeStateWaitingResPq()
        self._result = result

    async def process_telegram_message_body(self, body: Structure) -> None:
        match (state := self._exchange_state):
            case _KeyExchangeStateWaitingResPq():
                await self._process_res_pq(body)

            case _KeyExchangeStateWaitingDhParams():
                await self._process_dh_params(body, state)

            case _KeyExchangeStateWaitingDhGenOk():
                await self._process_dh_gen_ok(body, state)

            case _KeyExchangeStateCompleted():
                pass

            case _:
                raise TypeError("Unknown exchange state `%r`", state)

        if isinstance(self._exchange_state, _KeyExchangeStateCompleted):
            self._result.set_result(self._exchange_state.key)

    async def _process_dh_gen_ok(self, params3: Structure, state: _KeyExchangeStateWaitingDhGenOk) -> None:
        if params3 != "dh_gen_ok":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params3)

        if not hmac.compare_digest(params3.nonce, self._nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: nonce mismatch: `%r`", params3)

        self._exchange_state = _KeyExchangeStateCompleted(key=state.key)

    async def _process_dh_params(self, params: Structure, state: _KeyExchangeStateWaitingDhParams) -> None:
        if params != "server_DH_params_ok":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params)

        if not hmac.compare_digest(params.nonce, self._nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: nonce mismatch: `%r`", params)

        if not hmac.compare_digest(params.server_nonce, state.server_nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params server nonce mismatch")

        tmp_aes_key_1, tmp_aes_key_2, tmp_aes_iv_1, tmp_aes_iv_2 = await asyncio.gather(
            self._in_thread(lambda: sha1(state.new_nonce + state.server_nonce)),
            self._in_thread(lambda: sha1(state.server_nonce + state.new_nonce)),
            self._in_thread(lambda: sha1(state.server_nonce + state.new_nonce)),
            self._in_thread(lambda: sha1(state.new_nonce + state.new_nonce))
        )

        tmp_aes_key = tmp_aes_key_1 + tmp_aes_key_2[:12]
        tmp_aes_iv = tmp_aes_iv_1[12:] + tmp_aes_iv_2 + state.new_nonce[:4]
        tmp_aes = AesIge(tmp_aes_key, tmp_aes_iv, self._crypto_provider)

        (answer_hash, answer), b = await asyncio.gather(
            self._in_thread(lambda: tmp_aes.decrypt_with_hash(params.encrypted_answer)),
            self._in_thread(lambda: secrets.randbits(2048)),
        )

        answer_reader = to_reader(answer)
        answer_reader_sha1 = hashlib.sha1()
        answer_reader_with_hash = SyncByteReaderApply(answer_reader, answer_reader_sha1.update)

        params2 = Structure.from_dict(await self._in_thread(lambda: self._datacenter.schema.read_by_boxed_data(answer_reader_with_hash)))
        answer_hash_computed = await self._in_thread(answer_reader_sha1.digest)

        if not hmac.compare_digest(answer_hash_computed, answer_hash):
            raise RuntimeError("Diffie–Hellman exchange failed: params2 hash mismatch")

        if params2 != "server_DH_inner_data":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params2)

        if not hmac.compare_digest(params2.nonce, self._nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params2 nonce mismatch")

        if not hmac.compare_digest(params2.server_nonce, state.server_nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params2 server nonce mismatch")

        self._datacenter.set_synchronized_time(params2.server_time)

        dh_prime = int.from_bytes(params2.dh_prime, "big")
        g = params2.g
        g_a = int.from_bytes(params2.g_a, "big")

        if not await self._in_thread(lambda: primes.is_safe_dh_prime(g, dh_prime)):
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
            self._in_thread(lambda: pow(g, b, dh_prime)),
            self._in_thread(lambda: pow(g_a, b, dh_prime)),
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

        if self._temp_key:
            new_auth_key.expire_at = state.temp_key_expires_in

        client_dh_inner_data = self._datacenter.schema.boxed_kwargs(
            _cons="client_DH_inner_data",
            nonce=self._nonce,
            server_nonce=state.server_nonce,
            retry_id=0,
            g_b=to_bytes(g_b),
        ).get_flat_bytes()

        tmp_aes = AesIge(tmp_aes_key, tmp_aes_iv, self._crypto_provider)

        await self._mtproto.write_unencrypted_message(
            _cons="set_client_DH_params",
            nonce=self._nonce,
            server_nonce=state.server_nonce,
            encrypted_data=await self._in_thread(lambda: tmp_aes.encrypt_with_hash(client_dh_inner_data)),
        )

        self._exchange_state = _KeyExchangeStateWaitingDhGenOk(key=new_auth_key, temp_key_expires_in=state.temp_key_expires_in)

    async def _process_res_pq(self, res_pq: Structure) -> None:
        if res_pq != "resPQ":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", res_pq)

        if not hmac.compare_digest(res_pq.nonce, self._nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: nonce mismatch: `%r`", res_pq)

        if self._datacenter.public_rsa.fingerprint not in res_pq.server_public_key_fingerprints:
            raise ValueError(f"Our certificate is not supported by the server: `%r`", res_pq)

        server_nonce = res_pq.server_nonce
        pq = int.from_bytes(res_pq.pq, "big", signed=False)

        new_nonce, (p, q) = await asyncio.gather(
            self._in_thread(lambda: secrets.token_bytes(32)),
            self._in_thread(lambda: self._crypto_provider.factorize_pq(pq)),
        )

        p_string = to_bytes(p)
        q_string = to_bytes(q)

        if len(p_string) + len(q_string) != 8:
            raise RuntimeError("Diffie–Hellman exchange failed: p q length is invalid, `%r`", pq)

        temp_key_expires_in = self.TEMP_AUTH_KEY_EXPIRE_TIME + self._datacenter.get_synchronized_time()

        p_q_inner_data = self._datacenter.schema.boxed_kwargs(
            _cons="p_q_inner_data_temp_dc" if self._temp_key else "p_q_inner_data_dc",
            pq=res_pq.pq,
            p=p_string,
            q=q_string,
            nonce=self._nonce,
            server_nonce=server_nonce,
            new_nonce=new_nonce,
            expires_in=temp_key_expires_in,
            dc=-self._datacenter.datacenter_id if self._datacenter.is_media else self._datacenter.datacenter_id
        )

        p_q_inner_data_rsa_pad = await self._in_thread(lambda: self._datacenter.public_rsa.rsa_pad(p_q_inner_data.get_flat_bytes(), self._crypto_provider))
        p_q_inner_data_encrypted = await self._in_thread(lambda: self._datacenter.public_rsa.encrypt(p_q_inner_data_rsa_pad))

        await self._mtproto.write_unencrypted_message(
            _cons="req_DH_params",
            server_nonce=server_nonce,
            p=p_string,
            q=q_string,
            nonce=self._nonce,
            public_key_fingerprint=self._datacenter.public_rsa.fingerprint,
            encrypted_data=p_q_inner_data_encrypted,
        )

        self._exchange_state = _KeyExchangeStateWaitingDhParams(
            new_nonce=new_nonce,
            server_nonce=server_nonce,
            temp_key_expires_in=temp_key_expires_in
        )
