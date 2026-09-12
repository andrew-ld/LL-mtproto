class PendingMsgsAck:
    __slots__ = ("msg_ids",)

    msg_ids: list[int]

    def __init__(self, msg_ids: list[int]):
        self.msg_ids = msg_ids
