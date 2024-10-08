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


import os.path

from ll_mtproto.crypto.public_rsa import PublicRSA
from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.tl.tl import Schema

__all__ = ("TelegramDatacenter",)


def _get_schema(resources_path: str) -> Schema:
    result = Schema()
    result.extend_from_raw_schema(open(os.path.join(resources_path, "auth.tl")).read())
    result.extend_from_raw_schema(open(os.path.join(resources_path, "application.tl")).read())
    result.extend_from_raw_schema(open(os.path.join(resources_path, "service.tl")).read())

    return result


def _get_public_rsa(resources_path: str) -> PublicRSA:
    telegram_rsa = open(os.path.join(resources_path, "telegram.rsa.pub")).read()
    return PublicRSA(telegram_rsa)


class TelegramDatacenter:
    __slots__ = ()

    _ll_mtproto_resources_path = os.path.join(os.path.dirname(__file__), "resources")
    _telegram_public_rsa = _get_public_rsa(_ll_mtproto_resources_path)
    _telegram_api_schema = _get_schema(_ll_mtproto_resources_path)

    SCHEMA = _telegram_api_schema
    PUBLIC_RSA = _telegram_public_rsa

    PLUTO = DatacenterInfo("149.154.175.50", 443, _telegram_public_rsa, _telegram_api_schema, 1, False)
    VENUS = DatacenterInfo("149.154.167.51", 443, _telegram_public_rsa, _telegram_api_schema, 2, False)
    AURORA = DatacenterInfo("149.154.175.100", 443, _telegram_public_rsa, _telegram_api_schema, 3, False)
    VESTA = DatacenterInfo("149.154.167.91", 443, _telegram_public_rsa, _telegram_api_schema, 4, False)
    FLORA = DatacenterInfo("149.154.171.5", 443, _telegram_public_rsa, _telegram_api_schema, 5, False)

    VENUS_MEDIA = DatacenterInfo("149.154.167.151", 443, _telegram_public_rsa, _telegram_api_schema, 2, True)
    VESTA_MEDIA = DatacenterInfo("149.154.164.250", 443, _telegram_public_rsa, _telegram_api_schema, 4, True)

    ALL_MAIN_DATACENTERS = frozenset((PLUTO, VENUS, AURORA, VESTA, FLORA))
    ALL_MEDIA_DATACENTERS = frozenset((VENUS_MEDIA, VESTA_MEDIA))
    ALL_DATACENTERS = frozenset((*ALL_MAIN_DATACENTERS, *ALL_MEDIA_DATACENTERS))
