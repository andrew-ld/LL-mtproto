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

import functools
import json
import re
import typing
import urllib.request

from ll_mtproto.client.error_description_resolver.base_error_description_resolver import BaseErrorDescriptionResolver

__all__ = ("PwrTelegramErrorDescriptionResolver",)

_RE_replace_number = re.compile(r"_\d+$")
_PWRTELEGRAM_database_url = "https://rpc.madelineproto.xyz/v4.json"


class PwrTelegramErrorDescriptionResolver(BaseErrorDescriptionResolver):
    __slots__ = ("_database", "_database_url")

    _database: dict[str, str] | None
    _database_url: str

    def __init__(self, database_url: str = _PWRTELEGRAM_database_url, initial_database: dict[str, str] | None = None) -> None:
        self._database = initial_database
        self._database_url = database_url

    @staticmethod
    @functools.lru_cache()
    def _normalize_error_message(message: str) -> str:
        return _RE_replace_number.sub(r"_%d", message)

    @property
    def current_database(self) -> dict[str, str]:
        database = self._database

        if database is None:
            raise RuntimeError("database not initialized, must call synchronous_fetch_database")

        return database

    def synchronous_fetch_database(self) -> None:
        with urllib.request.urlopen(self._database_url) as response:
            self._database = typing.cast(dict[str, str], json.loads(response.read())["human_result"])

    def resolve(self, _code: int, message: str) -> str | None:
        return self.current_database.get(self._normalize_error_message(message), None)
