import time

from ..crypto import PublicRSA
from ..tl.tl import Schema

__all__ = ("DatacenterInfo",)


class DatacenterInfo:
    __slots__ = ("address", "port", "public_rsa", "schema", "datacenter_id", "_time_difference")

    address: str
    port: int
    public_rsa: PublicRSA
    schema: Schema
    datacenter_id: int
    _time_difference: int

    def __init__(self, address: str, port: int, public_rsa: PublicRSA, schema: Schema, datacenter_id: int):
        self.address = address
        self.port = port
        self.public_rsa = public_rsa
        self.schema = schema
        self.datacenter_id = datacenter_id
        self._time_difference = 0

    def set_synchronized_time(self, synchronized_now: int):
        self._time_difference = synchronized_now - int(time.time())

    def get_synchronized_time(self) -> int:
        return int(time.time()) + self._time_difference

    def __copy__(self):
        return DatacenterInfo(self.address, self.port, self.public_rsa, self.schema, self.datacenter_id)

    def __str__(self):
        return f"{self.address}:{self.port} (layer: {self.schema.layer}, datacenter: {self.datacenter_id})"
