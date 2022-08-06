import multiprocessing
import os.path as __ospath
from concurrent.futures import ThreadPoolExecutor

from .crypto import PublicRSA
from .tl.tl import Schema
from .network import DatacenterInfo

_ll_mtproto_path = __ospath.dirname(__file__)

__all__ = ("TelegramDatacenter",)


def _get_schema() -> Schema:
    auth_schema = open(_ll_mtproto_path + "/resources/auth.tl").read()
    application_schema = open(_ll_mtproto_path + "/resources/application.tl").read()
    server_schema = open(_ll_mtproto_path + "/resources/service.tl").read()
    merged_schema = "\n".join((auth_schema, application_schema, server_schema))
    return Schema(merged_schema, 143)


def _get_public_rsa() -> PublicRSA:
    telegram_rsa = open(_ll_mtproto_path + "/resources/telegram.rsa.pub").read()
    return PublicRSA(telegram_rsa)


def _get_executor() -> ThreadPoolExecutor:
    executor = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())
    return executor


class TelegramDatacenter:
    __slots__ = ()

    def __init__(self):
        raise NotImplementedError()

    _public_rsa = _get_public_rsa()
    _schema = _get_schema()
    _executor = _get_executor()

    PLUTO = DatacenterInfo("149.154.175.53", 443, _public_rsa, _schema, _executor)
    VENUS = DatacenterInfo("149.154.167.51", 443, _public_rsa, _schema, _executor)
    AURORA = DatacenterInfo("149.154.175.100", 443, _public_rsa, _schema, _executor)
    VESTA = DatacenterInfo("149.154.167.91", 443, _public_rsa, _schema, _executor)
    FLORA = DatacenterInfo("91.108.56.130", 443, _public_rsa, _schema, _executor)

    VENUS_MEDIA = DatacenterInfo("149.154.167.151", 443, _public_rsa, _schema, _executor)
    VESTA_MEDIA = DatacenterInfo("149.154.164.250", 443, _public_rsa, _schema, _executor)
