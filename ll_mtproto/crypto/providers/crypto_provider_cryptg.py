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

import typing

import cryptg  # type: ignore

from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase


class CryptoProviderCryptg(CryptoProviderBase):
    def factorize_pq(self, pq: int) -> tuple[int, int]:
        # factorize_pq_pair is untyped, always return tuple[int, int]
        return typing.cast(tuple[int, int], cryptg.factorize_pq_pair(pq))

    def decrypt_aes_ige(self, data_in_out: bytes, key: bytes, iv: bytes) -> bytes:
        # decrypt_ige is untyped, always return bytes
        return typing.cast(bytes, cryptg.decrypt_ige(data_in_out, key, iv))

    def encrypt_aes_ige(self, data_in_out: bytes, key: bytes, iv: bytes) -> bytes:
        # encrypt_ige is untyped, always return bytes
        return typing.cast(bytes, cryptg.encrypt_ige(data_in_out, key, iv))
