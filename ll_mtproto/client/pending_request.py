# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2024 (andrew) https://github.com/andrew-ld/LL-mtproto

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
import typing

from ll_mtproto.tl.structure import StructureBody
from ll_mtproto.tl.tl import TlBodyData

__all__ = ("PendingRequest",)

SeqNoGenerator = typing.Callable[[], int]


class PendingRequest:
    __slots__ = (
        "response",
        "request",
        "cleaner",
        "retries",
        "next_seq_no",
        "allow_container",
        "expect_answer",
        "force_init_connection"
    )

    response: asyncio.Future[StructureBody]
    request: TlBodyData
    cleaner: asyncio.TimerHandle | None
    retries: int
    next_seq_no: SeqNoGenerator
    allow_container: bool
    expect_answer: bool
    force_init_connection: bool

    def __init__(
            self,
            *,
            response: asyncio.Future[StructureBody],
            message: TlBodyData,
            seq_no_func: SeqNoGenerator,
            allow_container: bool,
            expect_answer: bool,
            force_init_connection: bool = False
    ):
        self.response = response
        self.request = message
        self.cleaner = None
        self.retries = 0
        self.next_seq_no = seq_no_func
        self.allow_container = allow_container
        self.expect_answer = expect_answer
        self.force_init_connection = force_init_connection

    def finalize(self) -> None:
        if not (response := self.response).done():
            response.set_exception(ConnectionResetError())

        if cleaner := self.cleaner:
            cleaner.cancel()

        self.cleaner = None
        self.response.exception()
