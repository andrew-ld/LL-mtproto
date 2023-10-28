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


import os.path

from .crypto import PublicRSA
from .network import DatacenterInfo
from .tl.tl import Schema

__all__ = ("TelegramDatacenter",)


def _get_schema(resources_path: str) -> Schema:
    auth_schema = open(os.path.join(resources_path, "auth.tl")).read()
    service_schema = open(os.path.join(resources_path, "service.tl")).read()
    application_schema = open(os.path.join(resources_path, "application.tl")).read()

    result = Schema()
    result.extend_from_raw_schema(auth_schema)
    result.extend_from_raw_schema(application_schema)
    result.extend_from_raw_schema(service_schema)

    return result


def _get_public_rsa(resources_path: str) -> PublicRSA:
    telegram_rsa = open(os.path.join(resources_path, "telegram.rsa.pub")).read()
    return PublicRSA(telegram_rsa)


class TelegramDatacenter:
    __slots__ = ()

    _ll_mtproto_resources_path = os.path.join(os.path.dirname(__file__), "resources")
    _telegram_public_rsa = _get_public_rsa(_ll_mtproto_resources_path)
    _telegram_api_schema = _get_schema(_ll_mtproto_resources_path)

    PLUTO = DatacenterInfo("149.154.175.53", 443, _telegram_public_rsa, _telegram_api_schema, 1, False)
    VENUS = DatacenterInfo("149.154.167.51", 443, _telegram_public_rsa, _telegram_api_schema, 2, False)
    AURORA = DatacenterInfo("149.154.175.100", 443, _telegram_public_rsa, _telegram_api_schema, 3, False)
    VESTA = DatacenterInfo("149.154.167.91", 443, _telegram_public_rsa, _telegram_api_schema, 4, False)
    FLORA = DatacenterInfo("91.108.56.130", 443, _telegram_public_rsa, _telegram_api_schema, 5, False)

    VENUS_MEDIA = DatacenterInfo("149.154.167.151", 443, _telegram_public_rsa, _telegram_api_schema, 2, True)
    VESTA_MEDIA = DatacenterInfo("149.154.164.250", 443, _telegram_public_rsa, _telegram_api_schema, 4, True)

    ALL_MAIN_DATACENTERS = frozenset((PLUTO, VENUS, AURORA, VESTA, FLORA))
    ALL_MEDIA_DATACENTERS = frozenset((VENUS_MEDIA, VESTA_MEDIA))
    ALL_DATACENTERS = frozenset((*ALL_MAIN_DATACENTERS, *ALL_MEDIA_DATACENTERS))
