from ll_mtproto.network.encryption import PublicRSA
from ll_mtproto.tl.tl import Schema


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
