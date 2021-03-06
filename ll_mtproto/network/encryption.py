import base64
import hashlib
import re
import secrets

import cryptg

from ..tl.byteutils import (
    to_bytes,
    pack_binary_string,
    short_hex,
    sha1,
    sha256,
    to_reader,
    reader_is_empty,
)
from ..typed import PartialByteReader, InThread, SyncByteReader

__all__ = ("PublicRSA", "AesIge", "AesIgeAsyncStream", "prepare_key")

_rsa_public_key_RE = re.compile(
    r"-----BEGIN RSA PUBLIC KEY-----(?P<key>.*)-----END RSA PUBLIC KEY-----", re.S
)


# reads a public RSA key from .pem file, encrypts strings with it
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

        self.n = int.from_bytes(n, "big")
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

    def encrypt_with_hash(self, plain: bytes) -> bytes:
        return self.encrypt(sha1(plain) + plain)


# AES encryption in IGE mode
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


def prepare_key(auth_key: bytes, msg_key: bytes, read: bool) -> AesIge:
    x = 0 if read else 8

    sha256a = sha256(msg_key + auth_key[x: x + 36])
    sha256b = sha256(auth_key[x + 40:x + 76] + msg_key)

    aes_key = sha256a[:8] + sha256b[8:24] + sha256a[24:32]
    aes_iv = sha256b[:8] + sha256a[8:24] + sha256b[24:32]

    return AesIge(aes_key, aes_iv)
