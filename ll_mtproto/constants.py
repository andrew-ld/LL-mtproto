import enum
import os.path as __ospath

_path = __ospath.dirname(__file__)
_telegram_rsa = open(_path + "/resources/telegram.rsa.pub").read()


class TelegramSchema:
    AUTH_SCHEME = _path + "/resources/auth.tl"
    APPLICATION_SCHEME = _path + "/resources/application.tl"
    SERVICE_SCHEME = _path + "/resources/service.tl"
    SCHEME_LAYER: int = 136


class _TelegramDatacenterInfo:
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
    PLUTO = _TelegramDatacenterInfo("149.154.175.53", 443, _telegram_rsa)
    VENUS = _TelegramDatacenterInfo("149.154.167.51", 443, _telegram_rsa)
    AURORA = _TelegramDatacenterInfo("149.154.175.100", 443, _telegram_rsa)
    VESTA = _TelegramDatacenterInfo("149.154.167.91", 443, _telegram_rsa)
    FLORA = _TelegramDatacenterInfo("91.108.56.130", 443, _telegram_rsa)

    VENUS_MEDIA = _TelegramDatacenterInfo("149.154.167.151", 443, _telegram_rsa)
    VESTA_MEDIA = _TelegramDatacenterInfo("149.154.164.250", 443, _telegram_rsa)
