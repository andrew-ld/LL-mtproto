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


import logging
import secrets
import time
import typing

from ..tl.byteutils import sha1


__all__ = ("AuthKey", "Key", "AuthKeyUpdatedCallback", "DhGenKey")


AuthKeyUpdatedCallback = typing.Callable[[], typing.Any]


class AuthKeyUpdatedCallbackHolder:
    __slots__ = ("on_content_change_callback",)

    on_content_change_callback: AuthKeyUpdatedCallback

    def __init__(self, callback: AuthKeyUpdatedCallback):
        self.on_content_change_callback = callback

    def set_content_change_callback(self, callback: AuthKeyUpdatedCallback):
        self.on_content_change_callback = callback


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


class DhGenKey:
    __slots__ = ("auth_key", "auth_key_id", "server_salt", "session")

    auth_key: None | bytes
    auth_key_id: None | int
    server_salt: None | int
    session: KeySession

    def __init__(self):
        self.auth_key = None
        self.auth_key_id = None
        self.server_salt = None
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
        "_update_callback",
    )

    auth_key: None | bytes
    auth_key_id: None | int
    server_salt: None | int
    session: KeySession
    unused_sessions: set[int]
    created_at: None | float
    _update_callback: AuthKeyUpdatedCallbackHolder

    def __init__(
            self,
            update_callback: AuthKeyUpdatedCallbackHolder,
            auth_key: bytes | None = None,
            server_salt: int | None = None,
            created_at: int | None = None
    ):
        self._update_callback = update_callback
        self.auth_key = auth_key
        self.server_salt = server_salt
        self.created_at = created_at

        self.session = KeySession()
        self.unused_sessions = set()

        self.auth_key_id = self.generate_auth_key_id(auth_key)

    def __getstate__(self) -> dict[str, any]:
        return {
            "auth_key": self.auth_key,
            "auth_key_id": self.auth_key_id,
            "server_salt": self.server_salt,
            "session": self.session,
            "unused_sessions": self.unused_sessions,
            "created_at": self.created_at
        }

    def __setstate__(self, state: dict[str, any]):
        self.auth_key = state["auth_key"]
        self.auth_key_id = state["auth_key_id"]
        self.server_salt = state["server_salt"]
        self.session = state["session"]
        self.unused_sessions = state["unused_sessions"]
        self.created_at = state.get("created_at", 0)

    @staticmethod
    def generate_auth_key_id(auth_key: bytes | None) -> int | None:
        auth_key_id = sha1(auth_key)[-8:] if auth_key else None
        return int.from_bytes(auth_key_id, "little", signed=False) if auth_key_id else None

    def flush_changes(self):
        self._update_callback.on_content_change_callback()

    def is_empty(self) -> bool:
        return self.auth_key is None or self.auth_key_id is None

    def generate_new_unique_session_id(self):
        old_session = self.session

        if old_session.seqno > 0:
            self.unused_sessions.add(old_session.id)

        new_session_id = KeySession.generate_new_session_id()

        while (new_session_id == old_session.id) or (new_session_id in self.unused_sessions):
            new_session_id = KeySession.generate_new_session_id()

        self.session = KeySession(session_id=new_session_id)

    def import_dh_gen_key(self, dh_gen_key: DhGenKey):
        self.created_at = time.time()

        self.auth_key = dh_gen_key.auth_key
        self.auth_key_id = dh_gen_key.auth_key_id
        self.server_salt = dh_gen_key.server_salt

        old_session = self.session

        if old_session.seqno > 0:
            self.unused_sessions.add(old_session.id)

        self.session = dh_gen_key.session

    def get_or_assert_empty(self) -> tuple[bytes, int, KeySession]:
        auth_key, auth_key_id, session = self.auth_key, self.auth_key_id, self.session

        if auth_key is None or auth_key_id is None:
            raise AssertionError("key is empty")

        return auth_key, auth_key_id, session

    def is_fresh_key(self):
        created_at = self.created_at

        if created_at is None:
            return False

        return (time.time() - created_at) < 60.

    def clear_key(self):
        self.auth_key = None
        self.auth_key_id = None
        self.server_salt = None
        self.session = KeySession()
        self.created_at = -1.
        self.unused_sessions.clear()


class AuthKey:
    __slots__ = ("persistent_key", "temporary_key", "_update_callback")

    _update_callback: AuthKeyUpdatedCallbackHolder
    persistent_key: Key
    temporary_key: Key

    def __init__(self, persistent_key: Key | None = None, temporary_key: Key | None = None):
        self._update_callback = AuthKeyUpdatedCallbackHolder(self._stub_on_content_change)
        self.persistent_key = persistent_key or Key(self._update_callback)
        self.temporary_key = temporary_key or Key(self._update_callback)

    def _stub_on_content_change(self):
        logging.warning("auth key: `%r`, dont have content change callback", self)

    def set_content_change_callback(self, callback: AuthKeyUpdatedCallback):
        self._update_callback.set_content_change_callback(callback)

    def __getstate__(self) -> dict[str, any]:
        return {
            "persistent_key": self.persistent_key,
            "temporary_key": self.temporary_key
        }

    def __setstate__(self, state: dict[str, any]):
        self.persistent_key = state["persistent_key"]
        self.temporary_key = state["temporary_key"]

        self._update_callback = AuthKeyUpdatedCallbackHolder(self._stub_on_content_change)
        self.persistent_key._update_callback = self._update_callback
        self.temporary_key._update_callback = self._update_callback
