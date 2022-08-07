import asyncio
import hashlib
import hmac
import secrets
import time
import typing

from ..crypto import AesIge
from ..math import primes
from ..network import MTProto, DatacenterInfo
from ..tl.byteutils import to_bytes, sha1, to_reader, xor
from ..typed import InThread
from ..crypto import AuthKey


class MTProtoKeyExchange:
    __slots__ = ("_mtproto", "_in_thread", "_datacenter")

    TEMP_AUTH_KEY_EXPIRE_TIME = 24 * 60 * 60

    _in_thread: InThread
    _mtproto: MTProto
    _datacenter: DatacenterInfo

    def __init__(self, mtproto: MTProto, in_thread: InThread, datacenter: DatacenterInfo):
        self._mtproto = mtproto
        self._in_thread = in_thread
        self._datacenter = datacenter

    async def create_temp_auth_key(self, perm_auth_key: AuthKey) -> AuthKey:
        return await self._create_auth_key(True, perm_auth_key)

    async def create_perm_auth_key(self) -> AuthKey:
        return await self._create_auth_key(False, None)

    async def _create_auth_key(self, temp: bool, perm_auth_key: AuthKey | None) -> AuthKey:
        if temp and perm_auth_key is None:
            raise ValueError("You can't get a temporary key without having the permanent one")

        nonce = await self._in_thread(secrets.token_bytes, 16)

        await self._mtproto.write_unencrypted_message(_cons="req_pq", nonce=nonce)

        res_pq = (await self._mtproto.read_unencrypted_message()).body

        if res_pq != "resPQ":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", res_pq)

        if self._datacenter.public_rsa.fingerprint not in res_pq.server_public_key_fingerprints:
            raise ValueError("Our certificate is not supported by the server")

        server_nonce = res_pq.server_nonce
        pq = int.from_bytes(res_pq.pq, "big", signed=False)

        new_nonce, (p, q) = await asyncio.gather(
            self._in_thread(secrets.token_bytes, 32),
            self._in_thread(primes.factorize, pq),
        )

        p_string = to_bytes(p)
        q_string = to_bytes(q)

        if temp:
            temp_key_expires_in = self.TEMP_AUTH_KEY_EXPIRE_TIME + int(time.time())
        else:
            temp_key_expires_in = None

        p_q_inner_data = self._datacenter.schema.boxed(
            _cons="p_q_inner_data_temp" if temp else "p_q_inner_data",
            pq=res_pq.pq,
            p=p_string,
            q=q_string,
            nonce=nonce,
            server_nonce=server_nonce,
            new_nonce=new_nonce,
            expires_in=temp_key_expires_in
        ).get_flat_bytes()

        await self._mtproto.write_unencrypted_message(
            _cons="req_DH_params",
            nonce=nonce,
            server_nonce=server_nonce,
            p=p_string,
            q=q_string,
            public_key_fingerprint=self._datacenter.public_rsa.fingerprint,
            encrypted_data=await self._in_thread(self._datacenter.public_rsa.encrypt_with_hash, p_q_inner_data),
        )

        params = (await self._mtproto.read_unencrypted_message()).body

        if params != "server_DH_params_ok":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params)

        if not hmac.compare_digest(params.nonce, nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params nonce mismatch")

        if not hmac.compare_digest(params.server_nonce, server_nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params server nonce mismatch")

        tmp_aes_key_1, tmp_aes_key_2, tmp_aes_iv_1, tmp_aes_iv_2 = await asyncio.gather(
            self._in_thread(sha1, new_nonce + server_nonce),
            self._in_thread(sha1, server_nonce + new_nonce),
            self._in_thread(sha1, server_nonce + new_nonce),
            self._in_thread(sha1, new_nonce + new_nonce)
        )

        tmp_aes_key = tmp_aes_key_1 + tmp_aes_key_2[:12]
        tmp_aes_iv = tmp_aes_iv_1[12:] + tmp_aes_iv_2 + new_nonce[:4]
        tmp_aes = AesIge(tmp_aes_key, tmp_aes_iv)

        (answer_hash, answer), b = await asyncio.gather(
            self._in_thread(tmp_aes.decrypt_with_hash, params.encrypted_answer),
            self._in_thread(secrets.randbits, 2048),
        )

        answer_reader = to_reader(answer)
        answer_hash_performer = hashlib.sha1()

        def answer_reader_hasher(nbytes: int) -> bytes:
            reader_result = answer_reader(nbytes)
            answer_hash_performer.update(reader_result)
            return reader_result

        params2 = await self._in_thread(self._datacenter.schema.read, answer_reader_hasher)
        answer_hash_computed = await self._in_thread(answer_hash_performer.digest)

        if not hmac.compare_digest(answer_hash_computed, answer_hash):
            raise RuntimeError("Diffie–Hellman exchange failed: params2 hash mismatch")

        if params2 != "server_DH_inner_data":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params2)

        if not hmac.compare_digest(params2.nonce, nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params2 nonce mismatch")

        if not hmac.compare_digest(params2.server_nonce, server_nonce):
            raise RuntimeError("Diffie–Hellman exchange failed: params2 server nonce mismatch")

        dh_prime = int.from_bytes(params2.dh_prime, "big")
        g = params2.g
        g_a = int.from_bytes(params2.g_a, "big")

        if not primes.is_safe_dh_prime(g, dh_prime):
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

        server_salt = int.from_bytes(xor(new_nonce[:8], server_nonce[:8]), "little", signed=True)

        new_auth_key = AuthKey(auth_key=to_bytes(auth_key), server_salt=server_salt)

        client_dh_inner_data = self._datacenter.schema.boxed(
            _cons="client_DH_inner_data",
            nonce=nonce,
            server_nonce=server_nonce,
            retry_id=0,
            g_b=to_bytes(g_b),
        ).get_flat_bytes()

        tmp_aes = AesIge(tmp_aes_key, tmp_aes_iv)

        await self._mtproto.write_unencrypted_message(
            _cons="set_client_DH_params",
            nonce=nonce,
            server_nonce=server_nonce,
            encrypted_data=await self._in_thread(tmp_aes.encrypt_with_hash, client_dh_inner_data),
        )

        params3 = (await self._mtproto.read_unencrypted_message()).body

        if params3 != "dh_gen_ok":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params3)

        if temp:
            perm_auth_key = typing.cast(AuthKey, perm_auth_key)
            temp_key_expires_in = typing.cast(int, temp_key_expires_in)

            bind_temp_auth_nonce = int.from_bytes(await self._in_thread(secrets.token_bytes, 8), "big", signed=True)

            bind_temp_auth_inner = self._datacenter.schema.boxed(
                _cons="bind_auth_key_inner",
                nonce=bind_temp_auth_nonce,
                temp_auth_key_id=new_auth_key.auth_key_id,
                perm_auth_key_id=perm_auth_key.auth_key_id,
                temp_session_id=new_auth_key.session_id,
                expires_at=temp_key_expires_in
            )

            bind_temp_auth_msg_id = self._mtproto.get_next_message_id()

            bind_temp_auth_inner_data = self._datacenter.schema.bare(
                _cons="message_inner_data",
                salt=int.from_bytes(await self._in_thread(secrets.token_bytes, 8), "big", signed=True),
                session_id=int.from_bytes(await self._in_thread(secrets.token_bytes, 8), "big", signed=False),
                message=self._datacenter.schema.bare(
                    _cons="message",
                    msg_id=bind_temp_auth_msg_id,
                    seqno=0,
                    body=bind_temp_auth_inner
                ),
            ).get_flat_bytes()

            bind_temp_auth_inner_data_sha1 = await self._in_thread(sha1, bind_temp_auth_inner_data)
            bind_temp_auth_inner_data_msg_key = bind_temp_auth_inner_data_sha1[4:20]

            bind_temp_auth_inner_data_aes: AesIge = await self._in_thread(
                MTProto.prepare_key_v1_write,
                perm_auth_key.auth_key,
                bind_temp_auth_inner_data_msg_key
            )

            bind_temp_auth_inner_data_encrypted = await self._in_thread(
                bind_temp_auth_inner_data_aes.encrypt,
                bind_temp_auth_inner_data
            )

            bind_temp_auth_inner_data_encrypted_boxed = self._datacenter.schema.bare(
                _cons="encrypted_message",
                auth_key_id=perm_auth_key.auth_key_id,
                msg_key=bind_temp_auth_inner_data_msg_key,
                encrypted_data=bind_temp_auth_inner_data_encrypted,
            )

            new_auth_key.seq_no = ((new_auth_key.seq_no + 1) // 2) * 2 + 1

            bind_temp_auth_message = self._datacenter.schema.boxed(
                _cons="auth.bindTempAuthKey",
                perm_auth_key_id=perm_auth_key.auth_key_id,
                nonce=bind_temp_auth_nonce,
                expires_at=temp_key_expires_in,
                encrypted_message=bind_temp_auth_inner_data_encrypted_boxed.get_flat_bytes()
            )

            bind_temp_auth_boxed_message = self._datacenter.schema.bare(
                _cons="message",
                msg_id=bind_temp_auth_msg_id,
                seqno=new_auth_key.seq_no,
                body=bind_temp_auth_message,
            )

            await self._mtproto.write_encrypted(bind_temp_auth_boxed_message, new_auth_key)

            for _ in range(10):
                message = await asyncio.wait_for(self._mtproto.read_encrypted(new_auth_key), 10)
                new_auth_key.seq_no = max(new_auth_key.seq_no, message.seqno)

                if message.body != "rpc_result":
                    continue

                if message.body.req_msg_id != bind_temp_auth_msg_id:
                    continue

                if message.body.result == "boolTrue":
                    return new_auth_key

                raise RuntimeError("Diffie–Hellman exchange failed: `%r`", message.body.result)

            raise RuntimeError("Diffie–Hellman exchange failed: too many messages before bindTempAuthKey response")

        return new_auth_key
