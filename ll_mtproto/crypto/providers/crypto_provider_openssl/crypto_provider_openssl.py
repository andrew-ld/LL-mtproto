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
from ll_mtproto.crypto.providers.crypto_provider_openssl import _impl

__all__ = ("CryptoProviderOpenSSL",)


class CryptoProviderOpenSSL(CryptoProviderBase):
    def factorize_pq(self, pq: int) -> tuple[int, int]:
        return _impl.factorize_pq(pq)

    def secure_random(self, nbytes: int) -> bytes:
        return _impl.secure_random(nbytes)

    def encrypt_aes_ige(self, plaintext: bytes, key: bytes, iv: bytes) -> tuple[bytes, bytes]:
        return _impl.encrypt_aes_ige(plaintext, key, iv)

    def decrypt_aes_ige(self, ciphertext: bytes, key: bytes, iv: bytes) -> tuple[bytes, bytes]:
        return _impl.decrypt_aes_ige(ciphertext, key, iv)
