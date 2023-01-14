import time

from ..crypto import PublicRSA
from ..tl.tl import Schema

__all__ = ("DatacenterInfo",)


class DatacenterInfo:
    __slots__ = ("default_direct_address", "default_direct_port", "public_rsa", "schema", "datacenter_id", "is_media", "_time_difference")

    default_direct_address: str
    default_direct_port: int
    public_rsa: PublicRSA
    schema: Schema
    datacenter_id: int
    is_media: bool

    _time_difference: int

    def __init__(self, address: str, port: int, public_rsa: PublicRSA, schema: Schema, datacenter_id: int, is_media: bool):
        self.default_direct_address = address
        self.default_direct_port = port
        self.public_rsa = public_rsa
        self.schema = schema
        self.datacenter_id = datacenter_id
        self.is_media = is_media
        self._time_difference = 0

    def set_synchronized_time(self, synchronized_now: int):
        self._time_difference = synchronized_now - int(time.time())

    def get_synchronized_time(self) -> int:
        return int(time.time()) + self._time_difference

    def __copy__(self):
        return DatacenterInfo(self.default_direct_address, self.default_direct_port, self.public_rsa, self.schema, self.datacenter_id, self.is_media)

    def __str__(self):
        return f"{self.default_direct_address}:{self.default_direct_port} (layer {self.schema.layer}, datacenter {'media' if self.is_media else 'main'} {self.datacenter_id})"
