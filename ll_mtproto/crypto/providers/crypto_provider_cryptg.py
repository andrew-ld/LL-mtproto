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

import typing
import secrets

import cryptg

from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase

__all__ = ("CryptoProviderCryptg",)


_TYPED_decrypt_ige = typing.cast(typing.Callable[[bytes, bytes, bytes], bytes], cryptg.decrypt_ige)
_TYPED_encrypt_ige = typing.cast(typing.Callable[[bytes, bytes, bytes], bytes], cryptg.encrypt_ige)
_TYPED_factorize_pq_pair = typing.cast(typing.Callable[[int], tuple[int, int]], cryptg.factorize_pq_pair)


class CryptoProviderCryptg(CryptoProviderBase):
    def factorize_pq(self, pq: int) -> tuple[int, int]:
        return _TYPED_factorize_pq_pair(pq)

    def decrypt_aes_ige(self, data_in_out: bytes, key: bytes, iv: bytes) -> bytes:
        return _TYPED_decrypt_ige(data_in_out, key, iv)

    def encrypt_aes_ige(self, data_in_out: bytes, key: bytes, iv: bytes) -> bytes:
        return _TYPED_encrypt_ige(data_in_out, key, iv)

    def secure_random(self, nbytes: int) -> bytes:
        return secrets.token_bytes(nbytes)
