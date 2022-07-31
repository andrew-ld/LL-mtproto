from ..typed import Structure

__all__ = ("Update",)


class Update:
    __slots__ = ("users", "chats", "update")

    users: list[Structure]
    chats: list[Structure]
    update: Structure

    def __init__(self, users: list[Structure], chats: list[Structure], update: Structure):
        self.users = users
        self.chats = chats
        self.update = update
