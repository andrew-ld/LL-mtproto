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

import locale
import logging
import platform
import functools
import traceback

from ll_mtproto.tl.tl import TlBodyData, TlBodyDataValue

__all__ = ("ConnectionInfo",)


class ConnectionInfo:
    __slots__ = (
        "api_id",
        "device_model",
        "system_version",
        "app_version",
        "lang_code",
        "system_lang_code",
        "lang_pack",
        "params"
    )

    api_id: int
    device_model: str
    system_version: str
    app_version: str
    lang_code: str
    system_lang_code: str
    lang_pack: str
    params: TlBodyData | None

    def __init__(
            self,
            *,
            api_id: int,
            device_model: str,
            system_version: str,
            app_version: str,
            lang_code: str,
            system_lang_code: str,
            lang_pack: str,
            params: TlBodyData | None = None
    ):
        self.api_id = api_id
        self.device_model = device_model
        self.system_version = system_version
        self.app_version = app_version
        self.lang_code = lang_code
        self.system_lang_code = system_lang_code
        self.lang_pack = lang_pack
        self.params = params

    @functools.cache
    def to_request_body(self) -> dict[str, TlBodyDataValue]:
        return {
            "api_id": self.api_id,
            "device_model": self.device_model,
            "system_version": self.system_version,
            "app_version": self.app_version,
            "lang_code": self.lang_code,
            "system_lang_code": self.system_lang_code,
            "lang_pack": self.lang_pack,
            "params": self.params
        }

    @staticmethod
    @functools.lru_cache()
    def generate_from_os_info(app_id: int, fallback_lang_code: str = "en") -> "ConnectionInfo":
        # noinspection PyBroadException
        try:
            current_locale = locale.getlocale()
        except:
            current_locale = None
            logging.warning("unable to get current locale: `%s`", traceback.format_exc())

        if current_locale:
            lang_code = current_locale[0]

            if not lang_code:
                lang_code = fallback_lang_code
        else:
            lang_code = fallback_lang_code

        system_version = platform.platform()

        return ConnectionInfo(
            api_id=app_id,
            device_model="ll-mtproto",
            system_version=system_version,
            app_version="1.0",
            lang_code=lang_code,
            system_lang_code=lang_code,
            lang_pack="",
            params=None
        )
