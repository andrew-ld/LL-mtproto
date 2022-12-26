import base64
import hashlib
import re
import secrets

from . import AesIge
from ..tl.byteutils import to_reader, pack_binary_string, reader_is_empty, to_bytes, sha1, xor, sha256
from ..typed import SyncByteReader

__all__ = ("PublicRSA",)

_rsa_public_key_RE = re.compile(
    r"-----BEGIN RSA PUBLIC KEY-----(?P<key>.*)-----END RSA PUBLIC KEY-----", re.S
)


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
        n, e = self._read_asn1(to_reader(asn1))

        self.fingerprint = int.from_bytes(
            hashlib.sha1(pack_binary_string(n[1:]) + pack_binary_string(e)).digest()[-8:],
            "little",
            signed=True,
        )

        self.n = int.from_bytes(n, "big", signed=False)
        self.e = int.from_bytes(e, "big")

    @staticmethod
    def _read_asn1(bytedata: SyncByteReader) -> list[bytes] | bytes:
        field_type, field_length = bytedata(2)

        if field_length & 0x80:
            field_length = int.from_bytes(bytedata(field_length ^ 0x80), "big")

        if field_type == 0x30:  # SEQUENCE
            sequence = []

            while not reader_is_empty(bytedata):
                sequence.append(PublicRSA._read_asn1(bytedata))

            return sequence

        elif field_type == 0x02:  # INTEGER
            return bytedata(field_length)

        else:
            raise NotImplementedError("Unknown ASN.1 field `%02X` in record")

    def encrypt(self, data: bytes) -> bytes:
        padding_length = max(0, 255 - len(data))
        m = int.from_bytes(data + secrets.token_bytes(padding_length), "big")
        x = pow(m, self.e, self.n)
        return to_bytes(x)

    def encrypt_with_rsa_pad(self, data: bytes) -> bytes:
        if len(data) > 144:
            raise TypeError("Plain data length is more that 144 bytes")

        data_with_padding = data + secrets.token_bytes(-len(data) % 192)
        data_pad_reversed = data_with_padding[::-1]

        while True:
            temp_key = secrets.token_bytes(32)

            if self.n > int.from_bytes(temp_key, "big", signed=False):
                break

        temp_key_aes = AesIge(temp_key, b"\0" * 32)

        data_with_hash = data_pad_reversed + sha256(temp_key + data_with_padding)
        encrypted_data_with_hash = temp_key_aes.encrypt(data_with_hash)

        temp_key_xor = xor(temp_key, sha256(encrypted_data_with_hash))
        key_aes_encrypted = temp_key_xor + encrypted_data_with_hash

        return key_aes_encrypted

    def encrypt_with_hash(self, plain: bytes) -> bytes:
        return self.encrypt(sha1(plain) + plain)
