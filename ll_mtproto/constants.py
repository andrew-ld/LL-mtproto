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

__all__ = ("TelegramDatacenter", "TelegramTestDatacenter")


def _get_schema(resources_path: str) -> Schema:
    result = Schema()
    result.extend_from_raw_schema(open(os.path.join(resources_path, "auth.tl")).read())
    result.extend_from_raw_schema(open(os.path.join(resources_path, "application.tl")).read())
    result.extend_from_raw_schema(open(os.path.join(resources_path, "service.tl")).read())

    return result


def _get_public_rsa(public_rsa_file_path: str) -> PublicRSA:
    telegram_rsa = open(public_rsa_file_path).read()
    return PublicRSA(telegram_rsa)


_ll_mtproto_resources_path = os.path.join(os.path.dirname(__file__), "resources")
_telegram_public_rsa = _get_public_rsa(os.path.join(_ll_mtproto_resources_path, "telegram.rsa.pub"))
_telegram_test_public_rsa = _get_public_rsa(os.path.join(_ll_mtproto_resources_path, "telegram.test.rsa.pub"))
_telegram_api_schema = _get_schema(_ll_mtproto_resources_path)


class TelegramTestDatacenter:
    __slots__ = ()

    SCHEMA = _telegram_api_schema
    PUBLIC_RSA = _telegram_test_public_rsa

    PLUTO = DatacenterInfo("149.154.175.10", 443, _telegram_test_public_rsa, _telegram_api_schema, 1, False, True)
    VENUS = DatacenterInfo("149.154.167.40", 443, _telegram_test_public_rsa, _telegram_api_schema, 2, False, True)
    AURORA = DatacenterInfo("149.154.175.117", 443, _telegram_test_public_rsa, _telegram_api_schema, 3, False, True)

    ALL_MAIN_DATACENTERS: frozenset[DatacenterInfo] = frozenset((PLUTO, VENUS, AURORA))
    ALL_MEDIA_DATACENTERS: frozenset[DatacenterInfo] = frozenset()
    ALL_DATACENTERS: frozenset[DatacenterInfo] = ALL_MAIN_DATACENTERS


class TelegramDatacenter:
    __slots__ = ()

    SCHEMA = _telegram_api_schema
    PUBLIC_RSA = _telegram_public_rsa

    PLUTO = DatacenterInfo("149.154.175.50", 443, _telegram_public_rsa, _telegram_api_schema, 1, False, False)
    VENUS = DatacenterInfo("149.154.167.51", 443, _telegram_public_rsa, _telegram_api_schema, 2, False, False)
    AURORA = DatacenterInfo("149.154.175.100", 443, _telegram_public_rsa, _telegram_api_schema, 3, False, False)
    VESTA = DatacenterInfo("149.154.167.91", 443, _telegram_public_rsa, _telegram_api_schema, 4, False, False)
    FLORA = DatacenterInfo("149.154.171.5", 443, _telegram_public_rsa, _telegram_api_schema, 5, False, False)

    VENUS_MEDIA = DatacenterInfo("149.154.167.151", 443, _telegram_public_rsa, _telegram_api_schema, 2, True, False)
    VESTA_MEDIA = DatacenterInfo("149.154.164.250", 443, _telegram_public_rsa, _telegram_api_schema, 4, True, False)

    ALL_MAIN_DATACENTERS: frozenset[DatacenterInfo] = frozenset((PLUTO, VENUS, AURORA, VESTA, FLORA))
    ALL_MEDIA_DATACENTERS: frozenset[DatacenterInfo] = frozenset((VENUS_MEDIA, VESTA_MEDIA))
    ALL_DATACENTERS: frozenset[DatacenterInfo] = frozenset((*ALL_MAIN_DATACENTERS, *ALL_MEDIA_DATACENTERS))
