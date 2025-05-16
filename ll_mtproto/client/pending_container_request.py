from ll_mtproto.client.pending_request import PendingRequest


class PendingContainerRequest:
    __slots__ = ("requests",)

    requests: list[PendingRequest]

    def __init__(self, requests: list[PendingRequest]) -> None:
        self.requests = requests

    def finalize(self) -> None:
        for request in self.requests:
            request.finalize()
