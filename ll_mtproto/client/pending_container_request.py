from ll_mtproto.client.pending_request import PendingRequest


class PendingContainerRequest:
    __slots__ = ("requests", "last_message_id")

    requests: list[PendingRequest]

    @staticmethod
    def _validate_request(request: PendingRequest):
        if not request.allow_container:
            raise TypeError(f"Pending request `{request!r}` dont allow container.")

        if not request.expect_answer:
            raise TypeError(f"Pending request `{request!r}` dont expect an answer.")

    def __init__(self, requests: list[PendingRequest], last_message_id: int | None = None) -> None:
        for request in requests:
            self._validate_request(request)
        self.requests = requests
        self.last_message_id = last_message_id

    def finalize(self) -> None:
        for request in self.requests:
            request.finalize()
