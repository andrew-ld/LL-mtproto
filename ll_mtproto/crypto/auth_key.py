import asyncio
import secrets

from ..tl.byteutils import sha1

__all__ = ("AuthKey",)


class AuthKey:
    __slots__ = ("auth_key", "auth_key_id", "auth_key_lock", "session_id", "server_salt", "seq_no")

    auth_key: None | bytes
    auth_key_id: None | bytes
    auth_key_lock: asyncio.Lock
    session_id: None | int
    server_salt: None | int
    seq_no: int

    def __init__(
            self,
            auth_key: None | bytes = None,
            auth_key_id: None | bytes = None,
            session_id: None | int = None,
            server_salt: None | int = None,
            seq_no: None | int = None
    ):
        self.auth_key = auth_key
        self.auth_key_id = auth_key_id
        self.session_id = session_id
        self.server_salt = server_salt
        self.seq_no = seq_no or -1
        self.auth_key_lock = asyncio.Lock()

    @staticmethod
    def generate_auth_key_id(auth_key: bytes) -> bytes:
        return sha1(auth_key)[-8:]

    @staticmethod
    def generate_new_session_id() -> int:
        return secrets.randbits(64)

    def clone(self) -> "AuthKey":
        return AuthKey(self.auth_key, self.auth_key_id, AuthKey.generate_new_session_id(), self.server_salt)

    def __getstate__(self) -> tuple[bytes | None, int | None]:
        return self.auth_key, self.server_salt

    def __setstate__(self, state: tuple[bytes | None, int | None] | bytes):
        self.auth_key_lock = asyncio.Lock()

        self.session_id = self.generate_new_session_id()
        self.seq_no = -1

        if isinstance(state, bytes):
            self.auth_key = state
            self.server_salt = secrets.randbits(8)
        else:
            self.auth_key, self.server_salt = state

        self.auth_key_id = AuthKey.generate_auth_key_id(self.auth_key) if self.auth_key else None
