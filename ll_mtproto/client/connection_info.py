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

from ll_mtproto.tl.tl import TlRequestBody, TlRequestBodyValue

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
    params: TlRequestBody | None

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
            params: TlRequestBody | None = None
    ):
        self.api_id = api_id
        self.device_model = device_model
        self.system_version = system_version
        self.app_version = app_version
        self.lang_code = lang_code
        self.system_lang_code = system_lang_code
        self.lang_pack = lang_pack
        self.params = params

    def to_request_body(self) -> dict[str, TlRequestBodyValue]:
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
