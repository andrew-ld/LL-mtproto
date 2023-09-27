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


import secrets
import copy
import typing

from ..tl.byteutils import sha1

__all__ = ("AuthKey", "Key")


class KeySession:
    __slots__ = ("id", "seqno")

    id: int
    seqno: int

    def __init__(self, session_id: int | None = None, seqno: int | None = None):
        self.id = session_id or self.generate_new_session_id()
        self.seqno = seqno or 0

    def __getstate__(self) -> dict[str, any]:
        return {
            "id": self.id,
            "seqno": self.seqno
        }

    def __setstate__(self, state: dict[str, any]):
        self.id = state["id"]
        self.seqno = state["seqno"]

    @staticmethod
    def generate_new_session_id() -> int:
        return 0xabcd000000000000 | (secrets.randbits(64) & 0x0000ffffffffffff)


class Key:
    __slots__ = ("auth_key", "auth_key_id", "server_salt", "session", "unused_sessions")

    auth_key: None | bytes
    auth_key_id: None | int
    server_salt: None | int
    session: KeySession
    unused_sessions: set[int]

    def __init__(self, auth_key: bytes | None = None, server_salt: int | None = None):
        self.auth_key = auth_key
        self.server_salt = server_salt

        self.session = KeySession()
        self.unused_sessions = set()

        self.auth_key_id = self.generate_auth_key_id(auth_key)

    def __copy__(self):
        return Key(auth_key=self.auth_key, server_salt=self.server_salt)

    def __getstate__(self) -> dict[str, any]:
        return {
            "auth_key": self.auth_key,
            "auth_key_id": self.auth_key_id,
            "server_salt": self.server_salt,
            "session": self.session,
            "unused_sessions": self.unused_sessions
        }

    def __setstate__(self, state: dict[str, any]):
        self.auth_key = state["auth_key"]
        self.auth_key_id = state["auth_key_id"]
        self.server_salt = state["server_salt"]
        self.session = state["session"]
        self.unused_sessions = state["unused_sessions"]

    @staticmethod
    def generate_auth_key_id(auth_key: bytes | None) -> int | None:
        auth_key_id = sha1(auth_key)[-8:] if auth_key else None
        return int.from_bytes(auth_key_id, "little", signed=False) if auth_key_id else None

    def copy_to(self, other: typing.Self):
        other.auth_key = self.auth_key
        other.auth_key_id = self.auth_key_id
        other.server_salt = self.server_salt
        other.session = self.session

    def is_empty(self) -> bool:
        return self.auth_key is None or self.auth_key_id is None

    def change_session(self):
        if self.session.seqno > 0:
            self.unused_sessions.add(self.session.id)

        self.session = KeySession()

    def get_or_assert_empty(self) -> tuple[bytes, int, KeySession]:
        auth_key, auth_key_id, session = self.auth_key, self.auth_key_id, self.session

        if auth_key is None or auth_key_id is None:
            raise AssertionError("auth key is empty")

        return auth_key, auth_key_id, session


class AuthKey:
    __slots__ = ("persistent_key", "temporary_key")

    persistent_key: Key
    temporary_key: Key

    def __init__(self, persistent_key: Key | None = None, temporary_key: Key | None = None):
        self.persistent_key = persistent_key or Key()
        self.temporary_key = temporary_key or Key()

    def __copy__(self) -> "AuthKey":
        return AuthKey(persistent_key=copy.copy(self.persistent_key), temporary_key=copy.copy(self.temporary_key))

    def __getstate__(self) -> dict[str, any]:
        return {
            "persistent_key": self.persistent_key,
            "temporary_key": self.temporary_key
        }

    def __setstate__(self, state: dict[str, any]):
        self.persistent_key = state["persistent_key"]
        self.temporary_key = state["temporary_key"]
