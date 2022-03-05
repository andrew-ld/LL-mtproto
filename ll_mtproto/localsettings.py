import os.path as __ospath

__path = __ospath.dirname(__file__)

TELEGRAM_HOST: str = "149.154.167.91"
TELEGRAM_PORT: int = 443

TELEGRAM_RSA: str = open(__path + "/resources/telegram.rsa.pub").read()

AUTH_SCHEME: str = __path + "/resources/auth.tl"
APPLICATION_SCHEME: str = __path + "/resources/application.tl"
SERVICE_SCHEME: str = __path + "/resources/service.tl"
SCHEME_LAYER: int = 136
