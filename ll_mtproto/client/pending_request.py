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


import asyncio

from ..tl import TlMessageBody, TlRequestBody
from .seqno_generator import SeqNoGenerator

__all__ = ("PendingRequest",)


class PendingRequest:
    __slots__ = (
        "response",
        "request",
        "cleaner",
        "retries",
        "next_seq_no",
        "allow_container",
        "expect_answer"
    )

    response: asyncio.Future[TlMessageBody]
    request: TlRequestBody
    cleaner: asyncio.TimerHandle | None
    retries: int
    next_seq_no: SeqNoGenerator
    allow_container: bool
    expect_answer: bool

    def __init__(
            self,
            *,
            response: asyncio.Future[TlMessageBody],
            message: TlRequestBody,
            seq_no_func: SeqNoGenerator,
            allow_container: bool,
            expect_answer: bool
    ):
        self.response = response
        self.request = message
        self.cleaner = None
        self.retries = 0
        self.next_seq_no = seq_no_func
        self.allow_container = allow_container
        self.expect_answer = expect_answer

    def finalize(self):
        if not (response := self.response).done():
            response.set_exception(ConnectionResetError())

        if cleaner := self.cleaner:
            cleaner.cancel()

        self.cleaner = None
        self.response.exception()
