import os.path

from .crypto import PublicRSA
from .network import DatacenterInfo
from .tl.tl import Schema

__all__ = ("TelegramDatacenter",)


def _get_schema(resources_path: str) -> Schema:
    auth_schema = open(os.path.join(resources_path, "auth.tl")).read()
    application_schema = open(os.path.join(resources_path, "application.tl")).read()
    service_schema = open(os.path.join(resources_path, "service.tl")).read()

    merged_schema = "\n".join((auth_schema, application_schema, service_schema))

    return Schema(merged_schema, 151)


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
    ALL_MAIN_DATACENTERS = [PLUTO, VENUS, AURORA, VESTA, FLORA]

    VENUS_MEDIA = DatacenterInfo("149.154.167.151", 443, _telegram_public_rsa, _telegram_api_schema, 2, True)
    VESTA_MEDIA = DatacenterInfo("149.154.164.250", 443, _telegram_public_rsa, _telegram_api_schema, 4, True)
    ALL_MEDIA_DATACENTERS = [VENUS_MEDIA, VESTA_MEDIA]
