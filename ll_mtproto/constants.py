import enum
import os.path as __ospath

_path = __ospath.dirname(__file__)
_telegram_rsa = open(_path + "/resources/telegram.rsa.pub").read()


__all__ = ("TelegramSchema", "TelegramDatacenter", "DatacenterInfo")


class TelegramSchema:
    __slots__ = ()

    AUTH_SCHEMA = open(_path + "/resources/auth.tl").read()
    APPLICATION_SCHEMA = open(_path + "/resources/application.tl").read()
    SERVICE_SCHEMA = open(_path + "/resources/service.tl").read()

    MERGED_SCHEMA = "\n".join((AUTH_SCHEMA, APPLICATION_SCHEMA, SERVICE_SCHEMA))

    SCHEMA_LAYER = 139


class DatacenterInfo:
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

    PLUTO = DatacenterInfo("149.154.175.53", 443, _telegram_rsa)
    VENUS = DatacenterInfo("149.154.167.51", 443, _telegram_rsa)
    AURORA = DatacenterInfo("149.154.175.100", 443, _telegram_rsa)
    VESTA = DatacenterInfo("149.154.167.91", 443, _telegram_rsa)
    FLORA = DatacenterInfo("91.108.56.130", 443, _telegram_rsa)

    VENUS_MEDIA = DatacenterInfo("149.154.167.151", 443, _telegram_rsa)
    VESTA_MEDIA = DatacenterInfo("149.154.164.250", 443, _telegram_rsa)
