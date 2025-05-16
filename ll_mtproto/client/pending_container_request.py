from ll_mtproto.client.pending_request import PendingRequest


class PendingContainerRequest:
    __slots__ = ("requests", "last_message_id")

    requests: list[PendingRequest]

    def __init__(self, requests: list[PendingRequest], last_message_id: int | None = None) -> None:
        self.requests = requests
        self.last_message_id = last_message_id

    def finalize(self) -> None:
        for request in self.requests:
            request.finalize()
