import base64
import hashlib
import re
import secrets
from concurrent.futures.thread import ThreadPoolExecutor

import Crypto.Cipher.AES

from ..tl.byteutils import (
    xor,
    long_hex,
    to_bytes,
    pack_binary_string,
    short_hex,
    sha1,
    Bytedata, sha256,
)
from ..typed import ByteReader, Loop

_rsa_public_key_RE = re.compile(
    r"-----BEGIN RSA PUBLIC KEY-----(?P<key>.*)-----END RSA PUBLIC KEY-----", re.S
)


# reads a public RSA key from .pem file, encrypts strings with it
class PublicRSA:
    fingerprint: int
    n: int
    e: int

    def __init__(self, pem_data: str):
        match = _rsa_public_key_RE.match(pem_data)

        if not match:
            raise SyntaxError("Error parsing public key data")

        asn1 = base64.standard_b64decode(match.groupdict()["key"])
        n, e = self._read_asn1(Bytedata(asn1))

        self.fingerprint = int.from_bytes(
            hashlib.sha1(pack_binary_string(n[1:]) + pack_binary_string(e)).digest()[-8:],
            "little",
            signed=True,
        )

        self.n = int.from_bytes(n, "big")
        self.e = int.from_bytes(e, "big")

    @staticmethod
    def _read_asn1(bytedata: Bytedata) -> list[bytes] | bytes:
        field_type, field_length = bytedata.read(2)

        if field_length & 0x80:
            field_length = int.from_bytes(bytedata.read(field_length ^ 0x80), "big")

        if field_type == 0x30:  # SEQUENCE
            sequence = []

            while bytedata:
                sequence.append(PublicRSA._read_asn1(bytedata))

            return sequence

        elif field_type == 0x02:  # INTEGER
            return bytedata.read(field_length)

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
    iv1: bytes
    iv2: bytes
    plain_buffer: bytes

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 32:
            raise ValueError(f"AES key length must be 32 bytes, got {len(key):d} bytes: {short_hex(key)}")

        if len(iv) != 32:
            raise ValueError(f"AES init vector length must be 32 bytes, got {len(iv):d} bytes: {short_hex(key)}")

        self.iv1, self.iv2 = iv[:16], iv[16:]
        self._aes = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
        self.plain_buffer = b""

    def decrypt_block(self, cipher_block: bytes) -> bytes:
        plain_block = xor(self.iv1, self._aes.decrypt(xor(self.iv2, cipher_block)))
        self.iv1, self.iv2 = cipher_block, plain_block
        return plain_block

    def decrypt_async_stream(self, loop: Loop, executor: ThreadPoolExecutor, reader: ByteReader) -> ByteReader:
        async def decryptor(n: int) -> bytes:
            while len(self.plain_buffer) < n:
                self.plain_buffer += await loop.run_in_executor(executor, self.decrypt_block, await reader(16))

            plain = self.plain_buffer[:n]
            self.plain_buffer = self.plain_buffer[n:]
            return plain

        return decryptor

    def decrypt(self, cipher: bytes) -> bytes:
        if len(cipher) % 16:
            raise ValueError(f"cipher length must be divisible by 16 bytes\n{long_hex(cipher)}")

        return b"".join(self.decrypt_block(plain_block) for plain_block in Bytedata(cipher).blocks(16))

    def encrypt_block(self, plain_block: bytes) -> bytes:
        if len(plain_block) != 16:
            raise RuntimeError("plain block is wrong")

        if len(self.iv1) != 16:
            raise RuntimeError("iv1 block is wrong")

        if len(self.iv2) != 16:
            raise RuntimeError("iv2 block is wrong")

        cipher_block = xor(self.iv2, self._aes.encrypt(xor(self.iv1, plain_block)))
        self.iv1, self.iv2 = cipher_block, plain_block

        return cipher_block

    def encrypt(self, plain: bytes) -> bytes:
        padding = secrets.token_bytes((-len(plain)) % 16)
        return b"".join(self.encrypt_block(plain_block) for plain_block in Bytedata(plain + padding).blocks(16))

    def encrypt_with_hash(self, plain: bytes) -> bytes:
        return self.encrypt(sha1(plain) + plain)

    def decrypt_with_hash(self, cipher: bytes) -> tuple[bytes, bytes]:
        plain_with_hash = self.decrypt(cipher)
        return plain_with_hash[:20], plain_with_hash[20:]


def prepare_key(auth_key: bytes, msg_key: bytes, read: bool) -> AesIge:
    x = 0 if read else 8

    sha256a = sha256(msg_key + auth_key[x: x + 36])
    sha256b = sha256(auth_key[x + 40:x + 76] + msg_key)

    aes_key = sha256a[:8] + sha256b[8:24] + sha256a[24:32]
    aes_iv = sha256b[:8] + sha256a[8:24] + sha256b[24:32]

    return AesIge(aes_key, aes_iv)
