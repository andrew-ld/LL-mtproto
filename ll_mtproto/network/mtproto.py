import asyncio
import collections
import concurrent.futures
import hashlib
import hmac
import logging
import secrets
import time
import typing

from .tcp import IntermediateTCP
from ..crypto.aes_ige import AesIge, AesIgeAsyncStream
from ..crypto.public_rsa import PublicRSA
from ..math import primes
from ..tl import tl
from ..tl.byteutils import to_bytes, sha1, xor, sha256, ByteReaderApply, to_reader, reader_discard
from ..tl.tl import Structure
from ..crypto import AuthKey

if typing.TYPE_CHECKING:
    from .datacenter_info import DatacenterInfo
else:
    DatacenterInfo = None

__all__ = ("MTProto",)


class MTProto:
    __slots__ = (
        "_loop",
        "_link",
        "_public_rsa_key",
        "_read_message_lock",
        "_last_message_id",
        "_auth_key",
        "_executor",
        "_schema",
        "_last_msg_ids",
    )

    @staticmethod
    def prepare_key(auth_key: bytes, msg_key: bytes, read: bool) -> AesIge:
        x = 0 if read else 8

        sha256a = sha256(msg_key + auth_key[x: x + 36])
        sha256b = sha256(auth_key[x + 40:x + 76] + msg_key)

        aes_key = sha256a[:8] + sha256b[8:24] + sha256a[24:32]
        aes_iv = sha256b[:8] + sha256a[8:24] + sha256b[24:32]

        return AesIge(aes_key, aes_iv)

    _loop: asyncio.AbstractEventLoop
    _link: IntermediateTCP
    _public_rsa_key: PublicRSA
    _read_message_lock: asyncio.Lock
    _last_message_id: int
    _auth_key: AuthKey
    _executor: concurrent.futures.Executor
    _last_msg_ids: collections.deque[int]
    _schema: tl.Schema

    def __init__(self, datacenter_info: DatacenterInfo, auth_key: AuthKey):
        self._loop = asyncio.get_event_loop()
        self._link = IntermediateTCP(datacenter_info.address, datacenter_info.port)
        self._public_rsa_key = datacenter_info.rsa
        self._auth_key = auth_key
        self._read_message_lock = asyncio.Lock()
        self._last_message_id = 0
        self._executor = datacenter_info.executor
        self._last_msg_ids = collections.deque(maxlen=64)
        self._schema = datacenter_info.schema

    async def _in_thread(self, *args, **kwargs):
        return await self._loop.run_in_executor(self._executor, *args, **kwargs)

    def _get_message_id(self) -> int:
        message_id = (int(time.time() * 2 ** 30) | secrets.randbits(12)) * 4

        if message_id <= self._last_message_id:
            message_id = self._last_message_id + 4

        self._last_message_id = message_id
        return message_id

    async def _read_unencrypted_message(self) -> Structure:
        async with self._read_message_lock:
            unencrypted_message_header_envelope = await self._link.readn(8 + 8)

            body_len_envelope = await self._link.readn(4)
            body_len = int.from_bytes(body_len_envelope, signed=False, byteorder="little")
            body_envelope = await self._link.readn(body_len)

            full_message = unencrypted_message_header_envelope + body_len_envelope + body_envelope
            full_message_reader = to_reader(full_message)

            try:
                return await self._in_thread(self._schema.read, full_message_reader, False, "unencrypted_message")
            finally:
                reader_discard(full_message_reader)

    async def _write_unencrypted_message(self, **kwargs):
        message = self._schema.bare(
            _cons="unencrypted_message",
            auth_key_id=0,
            message_id=0,
            body=self._schema.boxed(**kwargs),
        )

        await self._link.write(message.get_flat_bytes())

    async def _get_auth_key(self) -> tuple[bytes, bytes]:
        async with self._auth_key.auth_key_lock:
            if self._auth_key.auth_key is None:
                await self._create_auth_key()

        return self._auth_key.auth_key, self._auth_key.auth_key_id

    async def _create_auth_key(self):
        nonce = await self._in_thread(secrets.token_bytes, 16)

        await self._write_unencrypted_message(_cons="req_pq", nonce=nonce)

        res_pq = (await self._read_unencrypted_message()).body

        if res_pq != "resPQ":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", res_pq)

        if self._public_rsa_key.fingerprint not in res_pq.server_public_key_fingerprints:
            raise ValueError("Our certificate is not supported by the server")

        server_nonce = res_pq.server_nonce
        pq = int.from_bytes(res_pq.pq, "big", signed=False)

        new_nonce, (p, q) = await asyncio.gather(
            self._in_thread(secrets.token_bytes, 32),
            self._in_thread(primes.factorize, pq),
        )

        p_string = to_bytes(p)
        q_string = to_bytes(q)

        p_q_inner_data = self._schema.boxed(
            _cons="p_q_inner_data",
            pq=res_pq.pq,
            p=p_string,
            q=q_string,
            nonce=nonce,
            server_nonce=server_nonce,
            new_nonce=new_nonce,
        ).get_flat_bytes()

        await self._write_unencrypted_message(
            _cons="req_DH_params",
            nonce=nonce,
            server_nonce=server_nonce,
            p=p_string,
            q=q_string,
            public_key_fingerprint=self._public_rsa_key.fingerprint,
            encrypted_data=await self._in_thread(self._public_rsa_key.encrypt_with_hash, p_q_inner_data),
        )

        params = (await self._read_unencrypted_message()).body

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
            result = answer_reader(nbytes)
            answer_hash_performer.update(result)
            return result

        params2 = await self._in_thread(self._schema.read, answer_reader_hasher)
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

        self._auth_key.auth_key = to_bytes(auth_key)
        self._auth_key.auth_key_id = (await self._in_thread(AuthKey.generate_auth_key_id, self._auth_key.auth_key))
        self._auth_key.server_salt = int.from_bytes(xor(new_nonce[:8], server_nonce[:8]), "little", signed=True)
        self._auth_key.session_id = await self._in_thread(AuthKey.generate_new_session_id)

        client_dh_inner_data = self._schema.boxed(
            _cons="client_DH_inner_data",
            nonce=nonce,
            server_nonce=server_nonce,
            retry_id=0,
            g_b=to_bytes(g_b),
        ).get_flat_bytes()

        tmp_aes = AesIge(tmp_aes_key, tmp_aes_iv)

        await self._write_unencrypted_message(
            _cons="set_client_DH_params",
            nonce=nonce,
            server_nonce=server_nonce,
            encrypted_data=await self._in_thread(tmp_aes.encrypt_with_hash, client_dh_inner_data),
        )

        params3 = (await self._read_unencrypted_message()).body

        if params3 != "dh_gen_ok":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params3)

    async def read(self) -> Structure:
        auth_key, auth_key_id = await self._get_auth_key()
        auth_key_part = auth_key[88 + 8:88 + 8 + 32]

        async with self._read_message_lock:
            server_auth_key_id = await self._link.readn(8)

            if server_auth_key_id == b"l\xfe\xff\xffl\xfe\xff\xff":
                raise ValueError("Received a message with corrupted authorization!")

            if server_auth_key_id == b'S\xfe\xff\xffS\xfe\xff\xff':
                raise ValueError("Too many requests!")

            if server_auth_key_id != auth_key_id:
                raise ValueError("Received a message with unknown auth key id!", server_auth_key_id)

            msg_key = await self._link.readn(16)
            msg_aes = await self._in_thread(self.prepare_key, auth_key, msg_key, False)
            msg_aes_stream = AesIgeAsyncStream(msg_aes, self._in_thread, self._link.read)

            plain_sha256 = hashlib.sha256()
            await self._in_thread(plain_sha256.update, auth_key_part)
            msg_aes_stream_with_hash = ByteReaderApply(msg_aes_stream, plain_sha256.update, self._in_thread)

            message_inner_data_reader = to_reader(await msg_aes_stream_with_hash(8 + 8 + 8 + 4))

            try:
                message = self._schema.read(message_inner_data_reader, False, "message_inner_data_from_server")
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

            if (msg_session_id := message.session_id) != self._auth_key.session_id:
                raise ValueError("Received a message with unknown session id!", msg_session_id)

            if (msg_msg_id := message.message.msg_id) % 2 != 1:
                raise ValueError("Received message from server to client need odd parity!", msg_msg_id)

            if (msg_msg_id := message.message.msg_id) in self._last_msg_ids:
                raise ValueError("Received duplicated message from server to client", msg_msg_id)
            else:
                self._last_msg_ids.append(msg_msg_id)

            if (message.message.msg_id - self._get_message_id()) not in range(-(300 * (2 ** 32)), (30 * (2 ** 32))):
                raise RuntimeError("Client time is not synchronised with telegram time!")

            if (msg_salt := message.salt) != self._auth_key.server_salt:
                logging.error("received a message with unknown salt! %d", msg_salt)

            message_body_reader = to_reader(message_body_envelope)

            try:
                message.message._fields["body"] = await self._in_thread(self._schema.read, message_body_reader)
            finally:
                reader_discard(message_body_reader)

            return message.message

    def box_message(self, seq_no: int, **kwargs) -> tuple[tl.Value, int]:
        message_id = self._get_message_id()

        message = self._schema.bare(
            _cons="message",
            msg_id=message_id,
            seqno=seq_no,
            body=self._schema.boxed(**kwargs),
        )

        return message, message_id

    async def write(self, message: tl.Value):
        auth_key, auth_key_id = await self._get_auth_key()

        message_inner_data = self._schema.bare(
            _cons="message_inner_data",
            salt=self._auth_key.server_salt,
            session_id=self._auth_key.session_id,
            message=message,
        )

        message_inner_data_envelope = await self._in_thread(message_inner_data.get_flat_bytes)

        padding = await self._in_thread(secrets.token_bytes, (-(len(message_inner_data_envelope) + 12) % 16 + 12))
        msg_key = (await self._in_thread(sha256, auth_key[88:88 + 32] + message_inner_data_envelope + padding))[8:24]
        aes = await self._in_thread(self.prepare_key, auth_key, msg_key, True)
        encrypted_message = await self._in_thread(aes.encrypt, message_inner_data_envelope + padding)

        full_message = self._schema.bare(
            _cons="encrypted_message",
            auth_key_id=int.from_bytes(auth_key_id, "little", signed=False),
            msg_key=msg_key,
            encrypted_data=encrypted_message,
        )

        await self._link.write(full_message.get_flat_bytes())

    def stop(self):
        self._link.stop()
        logging.debug("disconnected from Telegram")
