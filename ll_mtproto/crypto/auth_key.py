import secrets

from ..tl.byteutils import sha1

__all__ = ("AuthKey",)


class AuthKey:
    __slots__ = ("auth_key", "auth_key_id", "session_id", "server_salt", "seq_no")

    auth_key: None | bytes
    auth_key_id: None | int
    session_id: None | int
    server_salt: None | int
    seq_no: int

    @staticmethod
    def generate_auth_key_id(auth_key: bytes) -> int | None:
        auth_key_id = sha1(auth_key)[-8:] if auth_key else None
        return int.from_bytes(auth_key_id, "little", signed=False) if auth_key_id else None

    @staticmethod
    def generate_new_session_id() -> int:
        return secrets.randbits(64)

    def __init__(self, auth_key: None | bytes = None, server_salt: None | int = None, seq_no: int = 0):
        self.auth_key = auth_key
        self.server_salt = server_salt
        self.seq_no = seq_no

        self.auth_key_id = self.generate_auth_key_id(auth_key)
        self.session_id = self.generate_new_session_id()

    def is_empty(self) -> bool:
        return self.auth_key is None or self.auth_key_id is None

    def get_or_assert_empty(self) -> tuple[bytes, int]:
        auth_key, auth_key_id = self.auth_key, self.auth_key_id

        if auth_key is None or auth_key_id is None:
            raise AssertionError("Auth key is empty")

        return auth_key, auth_key_id

    def copy_to(self, auth_key: "AuthKey"):
        auth_key.auth_key = self.auth_key
        auth_key.auth_key_id = self.auth_key_id
        auth_key.session_id = self.session_id
        auth_key.server_salt = self.server_salt
        auth_key.seq_no = self.seq_no

    def __copy__(self) -> "AuthKey":
        return AuthKey(auth_key=self.auth_key, server_salt=self.server_salt)

    def __getstate__(self) -> tuple[bytes | None, int | None]:
        return self.auth_key, self.server_salt

    def __setstate__(self, state: tuple[bytes | None, int | None] | bytes):
        self.seq_no = 0

        if isinstance(state, bytes):
            self.auth_key = state
            self.server_salt = secrets.randbits(8)
        else:
            self.auth_key, self.server_salt = state

        self.auth_key_id = self.generate_auth_key_id(self.auth_key)
        self.session_id = self.generate_new_session_id()
