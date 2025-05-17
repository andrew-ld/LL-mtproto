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


from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase
from ll_mtproto.tl.byteutils import short_hex, sha1
from ll_mtproto.typed import InThread, PartialByteReader

__all__ = ("AesIge", "AesIgeAsyncStream")


class AesIge:
    __slots__ = ("_key", "_iv", "_crypto_provider")

    _key: bytes
    _iv: bytes
    _crypto_provider: CryptoProviderBase

    def __init__(self, key: bytes, iv: bytes, crypto_provider: CryptoProviderBase):
        if len(key) != 32:
            raise ValueError(f"AES key length must be 32 bytes, got {len(key):d} bytes: {short_hex(key)}")

        if len(iv) != 32:
            raise ValueError(f"AES init vector length must be 32 bytes, got {len(iv):d} bytes: {short_hex(key)}")

        self._key = key
        self._iv = iv
        self._crypto_provider = crypto_provider

    def decrypt(self, cipher: bytes) -> bytes:
        if len(cipher) % 16 != 0:
            raise ValueError(f"Encrypted length must be divisible by 16 bytes")

        return self._crypto_provider.decrypt_aes_ige(cipher, self._key, self._iv)

    def encrypt(self, plain: bytes) -> bytes:
        padded_plain = plain + self._crypto_provider.secure_random((-len(plain)) % 16)
        return self._crypto_provider.encrypt_aes_ige(padded_plain, self._key, self._iv)

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

    async def __call__(self, nbytes: int) -> bytes:
        while len(self._plain_buffer) < nbytes:
            encrypted_buffer = await self._parent()
            self._plain_buffer += await self._in_thread(lambda: self._aes.decrypt(encrypted_buffer))

        plain = self._plain_buffer[:nbytes]
        del self._plain_buffer[:nbytes]
        return bytes(plain)

    def remaining_plain_buffer(self) -> bytes:
        return bytes(self._plain_buffer)
