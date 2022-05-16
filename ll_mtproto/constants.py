import enum
import os.path as __ospath

from .tl.tl import Schema
from .network.encryption import PublicRSA


_path = __ospath.dirname(__file__)
_telegram_rsa = open(_path + "/resources/telegram.rsa.pub").read()

__all__ = ("TelegramSchema", "TelegramDatacenter", "DatacenterInfo")


_singleton_schema: Schema | None = None
_singleton_public_rsa: PublicRSA | None = None


def _get_public_rsa() -> PublicRSA:
    global _singleton_public_rsa

    if _singleton_public_rsa is None:
        _singleton_public_rsa = PublicRSA(_telegram_rsa)

    return _singleton_public_rsa


def _get_schema() -> Schema:
    global _singleton_schema

    if _singleton_schema is None:
        _singleton_schema = Schema(TelegramSchema.MERGED_SCHEMA, TelegramSchema.SCHEMA_LAYER)

    return _singleton_schema


class TelegramSchema:
    __slots__ = ()

    AUTH_SCHEMA = open(_path + "/resources/auth.tl").read()
    APPLICATION_SCHEMA = open(_path + "/resources/application.tl").read()
    SERVICE_SCHEMA = open(_path + "/resources/service.tl").read()

    MERGED_SCHEMA = "\n".join((AUTH_SCHEMA, APPLICATION_SCHEMA, SERVICE_SCHEMA))

    SCHEMA_LAYER = 139


class DatacenterInfo:
    __slots__ = ("address", "port", "rsa", "schema")

    address: str
    port: int
    rsa: PublicRSA
    schema: Schema

    def __init__(self, address: str, port: int, rsa: PublicRSA, schema: Schema):
        self.address = address
        self.port = port
        self.rsa = rsa
        self.schema = schema

    def __str__(self):
        return f"{self.address}:{self.port}"


class TelegramDatacenter(enum.Enum):
    __slots__ = ()

    PLUTO = DatacenterInfo("149.154.175.53", 443, _get_public_rsa(), _get_schema())
    VENUS = DatacenterInfo("149.154.167.51", 443, _get_public_rsa(), _get_schema())
    AURORA = DatacenterInfo("149.154.175.100", 443, _get_public_rsa(), _get_schema())
    VESTA = DatacenterInfo("149.154.167.91", 443, _get_public_rsa(), _get_schema())
    FLORA = DatacenterInfo("91.108.56.130", 443, _get_public_rsa(), _get_schema())

    VENUS_MEDIA = DatacenterInfo("149.154.167.151", 443, _get_public_rsa(), _get_schema())
    VESTA_MEDIA = DatacenterInfo("149.154.164.250", 443, _get_public_rsa(), _get_schema())
