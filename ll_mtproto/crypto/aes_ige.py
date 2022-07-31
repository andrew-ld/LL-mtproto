import secrets

from cryptg import cryptg

from ..tl.byteutils import short_hex, sha1
from ..typed import InThread, PartialByteReader

__all__ = ("AesIge", "AesIgeAsyncStream")


class AesIge:
    __slots__ = ("_key", "_iv")

    _key: bytes
    _iv: bytes

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 32:
            raise ValueError(f"AES key length must be 32 bytes, got {len(key):d} bytes: {short_hex(key)}")

        if len(iv) != 32:
            raise ValueError(f"AES init vector length must be 32 bytes, got {len(iv):d} bytes: {short_hex(key)}")

        self._key = key
        self._iv = iv

    def decrypt(self, cipher: bytes) -> bytes:
        if len(cipher) % 16 != 0:
            raise ValueError(f"Encrypted length must be divisible by 16 bytes")

        return cryptg.decrypt_ige(cipher, self._key, self._iv)

    def encrypt(self, plain: bytes) -> bytes:
        return cryptg.encrypt_ige(plain + secrets.token_bytes((-len(plain)) % 16), self._key, self._iv)

    def encrypt_with_hash(self, plain: bytes) -> bytes:
        return self.encrypt(sha1(plain) + plain)

    def decrypt_with_hash(self, cipher: bytes) -> tuple[bytes, bytes]:
        plain_with_hash = self.decrypt(cipher)
        return plain_with_hash[:20], plain_with_hash[20:]


class AesIgeAsyncStream:
    __slots__ = ("_plain_buffer", "_aes", "_in_thread", "_parent")

    _plain_buffer: bytearray
    _aes: AesIge
    _in_thread: InThread
    _parent: PartialByteReader

    def __init__(self, aes: AesIge, in_thread: InThread, parent: PartialByteReader):
        self._aes = aes
        self._in_thread = in_thread
        self._parent = parent
        self._plain_buffer = bytearray()

    async def __call__(self, nbytes: int):
        while len(self._plain_buffer) < nbytes:
            self._plain_buffer += await self._in_thread(self._aes.decrypt, await self._parent())

        plain = self._plain_buffer[:nbytes]
        del self._plain_buffer[:nbytes]
        return bytes(plain)

    def remaining_plain_buffer(self) -> bytes:
        return bytes(self._plain_buffer)
