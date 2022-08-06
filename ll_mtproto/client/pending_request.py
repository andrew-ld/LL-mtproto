import asyncio

from ..typed import SeqNoGenerator, TlMessageBody, TlRequestBody

__all__ = ("PendingRequest",)


class PendingRequest:
    __slots__ = ("response", "request", "cleaner", "retries", "next_seq_no", "allow_container")

    response: asyncio.Future[TlMessageBody]
    request: TlRequestBody
    cleaner: asyncio.TimerHandle | None
    retries: int
    next_seq_no: SeqNoGenerator
    allow_container: bool

    def __init__(
            self,
            response: asyncio.Future[TlMessageBody],
            message: TlRequestBody,
            seq_no_func: SeqNoGenerator,
            allow_container: bool
    ):
        self.response = response
        self.request = message
        self.cleaner = None
        self.retries = 0
        self.next_seq_no = seq_no_func
        self.allow_container = allow_container

    def finalize(self):
        if not (response := self.response).done():
            response.set_exception(ConnectionResetError())

        if cleaner := self.cleaner:
            cleaner.cancel()

        self.cleaner = None
        self.response.exception()
