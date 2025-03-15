# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2024 (andrew) https://github.com/andrew-ld/LL-mtproto

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
import time
import typing

from ll_mtproto.tl.byteutils import sha1

__all__ = ("AuthKey", "Key", "AuthKeyUpdatedCallback", "DhGenKey")

AuthKeyUpdatedCallback = typing.Callable[[], typing.Any]


class AuthKeyUpdatedCallbackHolder:
    __slots__ = ("on_content_change_callback",)

    on_content_change_callback: AuthKeyUpdatedCallback

    def __init__(self, callback: AuthKeyUpdatedCallback) -> None:
        self.on_content_change_callback = callback

    def set_content_change_callback(self, callback: AuthKeyUpdatedCallback) -> None:
        self.on_content_change_callback = callback


class KeySession:
    __slots__ = ("id", "seqno", "ping_id", "stable_seqno", "seqno_increment")

    id: int
    seqno: int
    ping_id: int
    stable_seqno: bool
    seqno_increment: int

    def __init__(
            self,
            session_id: int | None = None,
            seqno: int | None = None,
            ping_id: int | None = None,
            stable_seqno: bool = True,
            seqno_increment: int = 1
    ):
        self.id = session_id or self.generate_new_session_id()
        self.seqno = seqno or 0
        self.ping_id = ping_id or 0
        self.stable_seqno = stable_seqno
        self.seqno_increment = seqno_increment

    def _get_and_increment_seqno(self) -> int:
        value = self.seqno
        self.seqno += 1
        return value

    def get_next_odd_seqno(self) -> int:
        return (self._get_and_increment_seqno()) * 2 + 1

    def get_next_even_seqno(self) -> int:
        return (self._get_and_increment_seqno()) * 2

    def __getstate__(self) -> dict[str, typing.Any]:
        return {
            "id": self.id,
            "seqno": self.seqno,
            "ping_id": self.ping_id,
            "stable_seqno": self.stable_seqno,
            "seqno_increment": self.seqno_increment
        }

    def __setstate__(self, state: dict[str, typing.Any]) -> None:
        self.id = state["id"]
        self.seqno = state.get("seqno", 0)
        self.ping_id = state.get("ping_id", 0)
        self.stable_seqno = state.get("stable_seqno", True)
        self.seqno_increment = state.get("seqno_increment", 1)

    @staticmethod
    def generate_new_session_id() -> int:
        return 0xabcd000000000000 | (secrets.randbits(64) & 0x0000ffffffffffff)


class DhGenKey:
    __slots__ = ("auth_key", "auth_key_id", "server_salt", "session", "expire_at")

    auth_key: None | bytes
    auth_key_id: None | int
    server_salt: None | int
    session: KeySession
    expire_at: None | int

    def __init__(self) -> None:
        self.auth_key = None
        self.auth_key_id = None
        self.server_salt = None
        self.expire_at = None
        self.session = KeySession()

    def get_or_assert_empty(self) -> tuple[bytes, int, KeySession]:
        auth_key, auth_key_id, session = self.auth_key, self.auth_key_id, self.session

        if auth_key is None or auth_key_id is None:
            raise AssertionError("key is empty")

        return auth_key, auth_key_id, session


class Key:
    __slots__ = (
        "auth_key",
        "auth_key_id",
        "server_salt",
        "session",
        "unused_sessions",
        "created_at",
        "expire_at",
        "_update_callback",
    )

    auth_key: None | bytes
    auth_key_id: None | int
    server_salt: None | int
    session: KeySession
    unused_sessions: set[int]
    created_at: None | float
    expire_at: None | int
    _update_callback: AuthKeyUpdatedCallbackHolder

    def __init__(
            self,
            update_callback: AuthKeyUpdatedCallbackHolder,
            auth_key: bytes | None = None,
            server_salt: int | None = None,
            created_at: int | None = None,
            expire_at: int | None = None
    ):
        self._update_callback = update_callback
        self.auth_key = auth_key
        self.server_salt = server_salt
        self.created_at = created_at
        self.expire_at = expire_at

        self.session = KeySession()
        self.unused_sessions = set()

        self.auth_key_id = self.generate_auth_key_id(auth_key)

    def __getstate__(self) -> dict[str, typing.Any]:
        return {
            "auth_key": self.auth_key,
            "auth_key_id": self.auth_key_id,
            "server_salt": self.server_salt,
            "session": self.session,
            "unused_sessions": self.unused_sessions,
            "created_at": self.created_at,
            "expire_at": self.expire_at
        }

    def __setstate__(self, state: dict[str, typing.Any]) -> None:
        self.auth_key = state["auth_key"]
        self.auth_key_id = state["auth_key_id"]
        self.server_salt = state["server_salt"]
        self.session = state["session"]
        self.unused_sessions = state["unused_sessions"]
        self.created_at = state.get("created_at", -1.)
        self.expire_at = state.get("expire_at", None)

    @staticmethod
    def generate_auth_key_id(auth_key: bytes | None) -> int | None:
        auth_key_id = sha1(auth_key)[-8:] if auth_key else None
        return int.from_bytes(auth_key_id, "little", signed=False) if auth_key_id else None

    def flush_changes(self) -> None:
        self._update_callback.on_content_change_callback()

    def is_empty(self) -> bool:
        return self.auth_key is None or self.auth_key_id is None

    def generate_new_unique_session_id(self) -> None:
        if (old_session := self.session).seqno > 0:
            self.unused_sessions.add(old_session.id)

        new_session_id = KeySession.generate_new_session_id()

        while new_session_id in self.unused_sessions:
            new_session_id = KeySession.generate_new_session_id()

        self.session = KeySession(session_id=new_session_id)

    def import_dh_gen_key(self, dh_gen_key: DhGenKey) -> None:
        self.created_at = time.time()

        self.auth_key = dh_gen_key.auth_key
        self.auth_key_id = dh_gen_key.auth_key_id
        self.server_salt = dh_gen_key.server_salt
        self.expire_at = dh_gen_key.expire_at

        if (old_session := self.session).seqno > 0:
            self.unused_sessions.add(old_session.id)

        self.session = dh_gen_key.session

    def get_or_assert_empty(self) -> tuple[bytes, int, KeySession]:
        auth_key, auth_key_id, session = self.auth_key, self.auth_key_id, self.session

        if auth_key is None or auth_key_id is None:
            raise AssertionError("key is empty")

        return auth_key, auth_key_id, session

    def is_fresh_key(self) -> bool:
        if (created_at := self.created_at) is not None:
            return (time.time() - created_at) < 60.

        return False

    def clear_key(self) -> None:
        self.auth_key = None
        self.auth_key_id = None
        self.server_salt = None
        self.session = KeySession()
        self.created_at = -1.

    def get_next_odd_seqno(self) -> int:
        return self.session.get_next_odd_seqno()

    def get_next_even_seqno(self) -> int:
        return self.session.get_next_even_seqno()


class AuthKey:
    __slots__ = ("persistent_key", "temporary_key", "_update_callback")

    _update_callback: AuthKeyUpdatedCallbackHolder
    persistent_key: Key
    temporary_key: Key

    def __init__(self, persistent_key: Key | None = None, temporary_key: Key | None = None):
        self._update_callback = AuthKeyUpdatedCallbackHolder(self._stub_on_content_change)
        self.persistent_key = persistent_key or Key(self._update_callback)
        self.temporary_key = temporary_key or Key(self._update_callback)

    def _stub_on_content_change(self) -> None:
        pass

    def set_content_change_callback(self, callback: AuthKeyUpdatedCallback) -> None:
        self._update_callback.set_content_change_callback(callback)

    def __getstate__(self) -> dict[str, typing.Any]:
        return {
            "persistent_key": self.persistent_key,
            "temporary_key": self.temporary_key
        }

    def __setstate__(self, state: dict[str, typing.Any]) -> None:
        self.persistent_key = state["persistent_key"]
        self.temporary_key = state["temporary_key"]

        self._update_callback = AuthKeyUpdatedCallbackHolder(self._stub_on_content_change)
        self.persistent_key._update_callback = self._update_callback
        self.temporary_key._update_callback = self._update_callback
