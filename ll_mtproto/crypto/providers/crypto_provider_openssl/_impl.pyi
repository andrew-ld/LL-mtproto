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


def secure_random(nbytes: int) -> bytes:
    ...

def factorize_pq(pq: int) -> tuple[int, int]:
    ...

def encrypt_aes_ige(plaintext: bytes, key: bytes, iv: bytes) -> tuple[bytes, bytes]:
    ...

def decrypt_aes_ige(ciphertext: bytes, key: bytes, iv: bytes) -> tuple[bytes, bytes]:
    ...
