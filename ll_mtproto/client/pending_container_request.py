# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2025 (andrew) https://github.com/andrew-ld/LL-mtproto

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

from ll_mtproto.client.pending_request import PendingRequest


class PendingContainerRequest:
    __slots__ = ("requests", "last_message_id")

    requests: list[PendingRequest]
    last_message_id: int | None

    @staticmethod
    def _validate_request(request: PendingRequest) -> None:
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
