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

import secrets

import cryptg

from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase

__all__ = ("CryptoProviderCryptg",)


class CryptoProviderCryptg(CryptoProviderBase):
    def factorize_pq(self, pq: int) -> tuple[int, int]:
        return cryptg.factorize_pq_pair(pq)

    def decrypt_aes_ige(self, plaintext: bytes, key: bytes, iv: bytes) -> tuple[bytes, bytes]:
        result_iv = bytes(iv)
        result_ciphertext = cryptg.decrypt_ige(plaintext, key, result_iv)
        return result_ciphertext, result_iv

    def encrypt_aes_ige(self, ciphertext: bytes, key: bytes, iv: bytes) -> tuple[bytes, bytes]:
        result_iv = bytes(iv)
        result_plaintext = cryptg.encrypt_ige(ciphertext, key, result_iv)
        return result_plaintext, result_iv

    def secure_random(self, nbytes: int) -> bytes:
        return secrets.token_bytes(nbytes)
