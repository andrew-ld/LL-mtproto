import multiprocessing
import os.path as __ospath
from concurrent.futures import ThreadPoolExecutor

from .network.datacenter_info import DatacenterInfo
from .network.encryption import PublicRSA
from .tl.tl import Schema

_path = __ospath.dirname(__file__)
_telegram_rsa = open(_path + "/resources/telegram.rsa.pub").read()

__all__ = ("TelegramSchema", "TelegramDatacenter")

_singleton_schema: Schema | None = None
_singleton_public_rsa: PublicRSA | None = None
_singleton_executor: ThreadPoolExecutor | None = None


def _get_executor() -> ThreadPoolExecutor:
    global _singleton_executor

    if _singleton_executor is None:
        _singleton_executor = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())

    return _singleton_executor


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

    SCHEMA_LAYER = 143


class TelegramDatacenter:
    __slots__ = ()

    PLUTO = DatacenterInfo("149.154.175.53", 443, _get_public_rsa(), _get_schema(), _get_executor())
    VENUS = DatacenterInfo("149.154.167.51", 443, _get_public_rsa(), _get_schema(), _get_executor())
    AURORA = DatacenterInfo("149.154.175.100", 443, _get_public_rsa(), _get_schema(), _get_executor())
    VESTA = DatacenterInfo("149.154.167.91", 443, _get_public_rsa(), _get_schema(), _get_executor())
    FLORA = DatacenterInfo("91.108.56.130", 443, _get_public_rsa(), _get_schema(), _get_executor())

    VENUS_MEDIA = DatacenterInfo("149.154.167.151", 443, _get_public_rsa(), _get_schema(), _get_executor())
    VESTA_MEDIA = DatacenterInfo("149.154.164.250", 443, _get_public_rsa(), _get_schema(), _get_executor())
