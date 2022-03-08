import asyncio
import logging
import os
import secrets
import time
import typing
from concurrent.futures import ThreadPoolExecutor

from . import encryption
from .encryption import AesIge
from .tcp import AbridgedTCP
from .. import constants
from ..math import primes
from ..tl import tl
from ..tl.byteutils import to_bytes, sha1, xor, sha256
from ..tl.tl import Structure, Value
from ..typed import InThread

_singleton_executor: ThreadPoolExecutor | None = None
_singleton_scheme: tl.Scheme | None = None


def _get_executor() -> ThreadPoolExecutor:
    global _singleton_executor

    if _singleton_executor is None:
        _singleton_executor = ThreadPoolExecutor(max_workers=3)

    return _singleton_executor


def _get_scheme(in_thread: InThread) -> tl.Scheme:
    global _singleton_scheme

    if _singleton_scheme is None:
        _singleton_scheme = tl.Scheme(
            in_thread,
            open(constants.TelegramSchema.AUTH_SCHEME, "r").read()
            + "\n"
            + open(constants.TelegramSchema.APPLICATION_SCHEME, "r").read()
            + "\n"
            + open(constants.TelegramSchema.SERVICE_SCHEME, "r").read(),
        )

    return _singleton_scheme


class AuthKey:
    auth_key: None | bytes
    auth_key_id: None | bytes
    auth_key_lock: asyncio.Lock
    session_id: None | int

    def __init__(self, auth_key: None | bytes = None, auth_key_id: None | bytes = None, session_id: None | int = None):
        self.auth_key = auth_key
        self.auth_key_id = auth_key_id
        self.session_id = session_id
        self.auth_key_lock = asyncio.Lock()


class MTProto:
    _loop: asyncio.AbstractEventLoop
    _link: AbridgedTCP
    _public_rsa_key: encryption.PublicRSA
    _read_message_lock: asyncio.Lock
    _server_salt: int
    _last_message_id: int
    _auth_key: AuthKey
    _executor: ThreadPoolExecutor
    _scheme: tl.Scheme

    def __init__(self, host: str, port: int, public_rsa_key: str, auth_key: AuthKey):
        self._loop = asyncio.get_event_loop()
        self._link = AbridgedTCP(host, port)
        self._public_rsa_key = encryption.PublicRSA(public_rsa_key)
        self._auth_key = auth_key
        self._read_message_lock = asyncio.Lock()
        self._client_salt = int.from_bytes(secrets.token_bytes(4), "little", signed=True)
        self._server_salt = 0
        self._last_message_id = 0
        self._executor = _get_executor()
        self._scheme = _get_scheme(self._in_thread)

        if self._auth_key.session_id is None:
            self._auth_key.session_id = secrets.randbits(64)

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
            return await self._scheme.read(self._link.read, is_boxed=False, parameter_type="unencrypted_message")

    def _write_unencrypted_message(self, **kwargs) -> typing.Awaitable[None]:
        message = self._scheme.bare(
            _cons="unencrypted_message",
            auth_key_id=0,
            message_id=0,
            body=self._scheme.boxed(**kwargs),
        )

        return self._loop.create_task(self._link.write(message.get_flat_bytes()))

    async def _get_auth_key(self) -> tuple[bytes, bytes]:
        async with self._auth_key.auth_key_lock:
            if self._auth_key.auth_key is None:
                await self._create_auth_key()

        return self._auth_key.auth_key, self._auth_key.auth_key_id

    async def _create_auth_key(self):
        nonce = await self._in_thread(secrets.token_bytes, 16)

        await self._write_unencrypted_message(_cons="req_pq", nonce=nonce)

        res_pq = (await self._read_unencrypted_message()).body

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

        p_q_inner_data = self._scheme.boxed(
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
            encrypted_data=self._public_rsa_key.encrypt_with_hash(p_q_inner_data),
        )

        params = (await self._read_unencrypted_message()).body

        if params != "server_DH_params_ok" or params.nonce != nonce or params.server_nonce != server_nonce:
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params)

        tmp_aes_key = sha1(new_nonce + server_nonce) + sha1(server_nonce + new_nonce)[:12]
        tmp_aes_iv = sha1(server_nonce + new_nonce)[12:] + sha1(new_nonce + new_nonce) + new_nonce[:4]
        tmp_aes = encryption.AesIge(tmp_aes_key, tmp_aes_iv)

        (answer_hash, answer), b = await asyncio.gather(
            self._in_thread(tmp_aes.decrypt_with_hash, params.encrypted_answer),
            self._in_thread(secrets.randbits, 2048),
        )

        params2 = await self._scheme.read_from_string(answer)

        if params2 != "server_DH_inner_data":
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params2)

        if sha1(self._scheme.serialize(boxed=True, **params2.get_dict()).get_flat_bytes()) != answer_hash:
            raise RuntimeError("Diffie–Hellman exchange failed: answer_hash mismatch!", answer_hash)

        dh_prime = int.from_bytes(params2.dh_prime, "big")
        g = params2.g
        g_a = int.from_bytes(params2.g_a, "big")

        if params2.nonce != nonce or params2.server_nonce != server_nonce or not primes.is_safe_dh_prime(g, dh_prime):
            raise RuntimeError("Diffie–Hellman exchange failed: `%r`", params2)

        g_b, auth_key = map(
            to_bytes,
            await asyncio.gather(
                self._in_thread(pow, g, b, dh_prime),
                self._in_thread(pow, g_a, b, dh_prime),
            ),
        )

        self._auth_key.auth_key = auth_key
        self._auth_key.auth_key_id = (await self._in_thread(sha1, self._auth_key.auth_key))[-8:]

        self._server_salt = int.from_bytes(xor(new_nonce[:8], server_nonce[:8]), "little", signed=True)

        client_dh_inner_data = self._scheme.boxed(
            _cons="client_DH_inner_data",
            nonce=nonce,
            server_nonce=server_nonce,
            retry_id=0,
            g_b=g_b,
        ).get_flat_bytes()

        tmp_aes = encryption.AesIge(tmp_aes_key, tmp_aes_iv)

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

        async with self._read_message_lock:
            self._link.clear_buffer()
            server_auth_key_id = await self._link.read(8)

            if server_auth_key_id != auth_key_id:
                raise ValueError("Received a message with unknown auth_key_id!", server_auth_key_id)

            msg_key = await self._link.read(16)

            aes: AesIge = await self._in_thread(encryption.prepare_key, auth_key, msg_key, False)

            decrypter = aes.decrypt_async_stream(self._loop, self._executor, self._link.read)
            message = await self._scheme.read(decrypter, is_boxed=False, parameter_type="message_inner_data")

            if message.session_id != self._auth_key.session_id:
                raise ValueError("Received a message with unknown session_id!", message.session_id)

            if self._server_salt != message.salt:
                logging.log(logging.ERROR, "received a message with unknown salt! %d", message.salt)

            return message.message

    def set_server_salt(self, salt: int):
        self._server_salt = salt

    def get_server_salt(self) -> int:
        return self._server_salt

    def write(self, seq_no: int, **kwargs) -> int:
        message_id = self._get_message_id()

        message = self._scheme.bare(
            _cons="message",
            msg_id=message_id,
            seqno=seq_no,
            body=self._scheme.boxed(**kwargs),
        )

        self._loop.create_task(self._write(message))
        return message_id

    async def _write(self, message: Value):
        auth_key, auth_key_id = await self._get_auth_key()

        message_inner_data = self._scheme.bare(
            _cons="message_inner_data",
            salt=self._server_salt,
            session_id=self._auth_key.session_id,
            message=message,
        ).get_flat_bytes()

        padding = os.urandom(-(len(message_inner_data) + 12) % 16 + 12)
        msg_key = (await self._in_thread(sha256, auth_key[88:88 + 32] + message_inner_data + padding))[8:24]
        aes = await self._in_thread(encryption.prepare_key, auth_key, msg_key, True)
        encrypted_message = await self._in_thread(aes.encrypt, message_inner_data + padding)

        full_message = self._scheme.bare(
            _cons="encrypted_message",
            auth_key_id=int.from_bytes(auth_key_id, "little", signed=False),
            msg_key=msg_key,
            encrypted_data=encrypted_message,
        ).get_flat_bytes()

        await self._link.write(full_message)

    def stop(self):
        self._link.stop()
        logging.log(logging.DEBUG, "disconnected from Telegram")
