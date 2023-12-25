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

import functools
import json
import re
import typing
import urllib.request

from ll_mtproto.client.error_description_resolver.AbstractErrorDescriptionResolver import AbstractErrorDescriptionResolver

__all__ = ("PwrTelegramRpcErrorDescriptionResolver",)

_RE_replace_number = re.compile(r"_\d+$")
_PWRTELEGRAM_database_url = "https://rpc.madelineproto.xyz/v4.json"


class PwrTelegramRpcErrorDescriptionResolver(AbstractErrorDescriptionResolver):
    __slots__ = ("_database",)

    _database: dict[str, str] | None

    def __init__(self) -> None:
        self._database = None

    @staticmethod
    @functools.lru_cache()
    def _sanitize_error_message(message: str) -> str:
        return _RE_replace_number.sub(r"_%d", message)

    def synchronous_fetch_database(self) -> None:
        with urllib.request.urlopen(_PWRTELEGRAM_database_url) as response:
            self._database = typing.cast(dict[str, str], json.loads(response.read())["human_result"])

    def resolve(self, _code: int, message: str) -> str | None:
        database = self._database

        if database is None:
            raise RuntimeError("database not initialized, must call synchronous_fetch_database")

        return database.get(self._sanitize_error_message(message), None)
