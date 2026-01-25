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


import base64
import hashlib
import re
import typing

from ll_mtproto.crypto.aes_ige import AesIge
from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase
from ll_mtproto.tl.bytereader import SyncByteReader
from ll_mtproto.tl.byteutils import xor, sha256
from ll_mtproto.tl.tl import pack_binary_string, NativeByteReader

__all__ = ("PublicRSA",)

_rsa_public_key_RE = re.compile(
    r"-----BEGIN RSA PUBLIC KEY-----(?P<key>.*)-----END RSA PUBLIC KEY-----", re.S
)

_Asn1Field = typing.Union[bytes, typing.List['_Asn1Field']]


class PublicRSA:
    __slots__ = ("fingerprint", "n", "e")

    fingerprint: int
    n: int
    e: int

    def __init__(self, pem_data: str):
        match = _rsa_public_key_RE.match(pem_data)

        if not match:
            raise SyntaxError("Error parsing public key data")

        asn1 = base64.standard_b64decode(match.groupdict()["key"])
        n, e = self._read_asn1(NativeByteReader(asn1))

        if not isinstance(n, bytes):
            raise SyntaxError(f"Error parsing public key data, the N field is not a buffer `{n!r}`")

        if not isinstance(e, bytes):
            raise SyntaxError(f"Error parsing public key data, the E field is not a buffer `{e!r}`")

        n_int = int.from_bytes(n, "big", signed=False)
        n_clean_bytes = n_int.to_bytes(256, "big")

        self.fingerprint = int.from_bytes(
            hashlib.sha1(pack_binary_string(n_clean_bytes) + pack_binary_string(e)).digest()[-8:],
            "little",
            signed=True,
        )

        self.n = n_int
        self.e = int.from_bytes(e, "big")

    @staticmethod
    def _read_asn1(reader: SyncByteReader) -> _Asn1Field:
        field_type, field_length = reader(2)

        if field_length & 0x80:
            field_length = int.from_bytes(reader(field_length ^ 0x80), "big")

        if field_type == 0x30:
            sequence = []
            while reader:
                sequence.append(PublicRSA._read_asn1(reader))
            return sequence

        elif field_type == 0x02:
            return reader(field_length)

        else:
            raise NotImplementedError("Unknown ASN.1 field `%02X` in record")

    def encrypt(self, data: bytes, crypto_provider: CryptoProviderBase) -> bytes:
        padding_length = max(0, 255 - len(data))
        m = int.from_bytes(data + crypto_provider.secure_random(padding_length), "big")
        x = pow(m, self.e, self.n)
        return x.to_bytes(256, "big")

    def rsa_pad(self, data: bytes, crypto_provider: CryptoProviderBase) -> bytes:
        if len(data) > 144:
            raise TypeError("Plain data length is more that 144 bytes")

        data_with_padding = data + crypto_provider.secure_random(-len(data) % 192)
        data_pad_reversed = data_with_padding[::-1]

        while True:
            temp_key = crypto_provider.secure_random(32)
            temp_key_aes = AesIge(temp_key, b"\0" * 32, crypto_provider)

            data_with_hash = data_pad_reversed + sha256(temp_key, data_with_padding)
            encrypted_data_with_hash = temp_key_aes.encrypt(data_with_hash)

            temp_key_xor = xor(temp_key, sha256(encrypted_data_with_hash))
            key_aes_encrypted = temp_key_xor + encrypted_data_with_hash

            if self.n > int.from_bytes(key_aes_encrypted, "big", signed=False):
                break

        return key_aes_encrypted
