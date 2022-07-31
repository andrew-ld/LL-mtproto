from ll_mtproto.typed import TlRequestBody

__all__ = ("ConnectionInfo",)


class ConnectionInfo:
    __slots__ = (
        "api_id",
        "device_model",
        "system_version",
        "app_version",
        "lang_code",
        "system_lang_code",
        "lang_pack",
        "params"
    )

    api_id: int
    device_model: str
    system_version: str
    app_version: str
    lang_code: str
    system_lang_code: str
    lang_pack: str
    params: dict | None

    def __init__(
            self,
            *,
            api_id: int,
            device_model: str,
            system_version: str,
            app_version: str,
            lang_code: str,
            system_lang_code: str,
            lang_pack: str,
            params: TlRequestBody | None = None
    ):
        self.api_id = api_id
        self.device_model = device_model
        self.system_version = system_version
        self.app_version = app_version
        self.lang_code = lang_code
        self.system_lang_code = system_lang_code
        self.lang_pack = lang_pack
        self.params = params

    def dict(self) -> dict:
        return {
            "api_id": self.api_id,
            "device_model": self.device_model,
            "system_version": self.system_version,
            "app_version": self.app_version,
            "lang_code": self.lang_code,
            "system_lang_code": self.system_lang_code,
            "lang_pack": self.lang_pack,
            "params": self.params if self.params is not None else None
        }
