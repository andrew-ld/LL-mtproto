import enum
import os.path as __ospath

_path = __ospath.dirname(__file__)
_telegram_rsa = open(_path + "/resources/telegram.rsa.pub").read()


__all__ = ("TelegramSchema", "TelegramDatacenter", "TelegramDatacenterInfo")


class TelegramSchema:
    __slots__ = ()

    AUTH_SCHEMA = _path + "/resources/auth.tl"
    APPLICATION_SCHEMA = _path + "/resources/application.tl"
    SERVICE_SCHEMA = _path + "/resources/service.tl"
    SCHEMA_LAYER = 136


class TelegramDatacenterInfo:
    __slots__ = ("address", "port", "rsa")

    address: str
    port: int
    rsa: str

    def __init__(self, address: str, port: int, rsa: str):
        self.address = address
        self.port = port
        self.rsa = rsa

    def __str__(self):
        return f"{self.address}:{self.port}"


class TelegramDatacenter(enum.Enum):
    __slots__ = ()

    PLUTO = TelegramDatacenterInfo("149.154.175.53", 443, _telegram_rsa)
    VENUS = TelegramDatacenterInfo("149.154.167.51", 443, _telegram_rsa)
    AURORA = TelegramDatacenterInfo("149.154.175.100", 443, _telegram_rsa)
    VESTA = TelegramDatacenterInfo("149.154.167.91", 443, _telegram_rsa)
    FLORA = TelegramDatacenterInfo("91.108.56.130", 443, _telegram_rsa)

    VENUS_MEDIA = TelegramDatacenterInfo("149.154.167.151", 443, _telegram_rsa)
    VESTA_MEDIA = TelegramDatacenterInfo("149.154.164.250", 443, _telegram_rsa)
