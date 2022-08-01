from concurrent.futures import Executor

from .transport import TransportCodecFactory
from ..crypto import PublicRSA
from ..tl.tl import Schema


class DatacenterInfo:
    __slots__ = ("address", "port", "rsa", "schema", "executor", "transport_codec")

    address: str
    port: int
    rsa: PublicRSA
    schema: Schema
    executor: Executor
    transport_codec: TransportCodecFactory

    def __init__(
            self,
            address: str,
            port: int,
            rsa: PublicRSA,
            schema: Schema,
            executor: Executor,
            transport_codec: TransportCodecFactory
    ):
        self.address = address
        self.port = port
        self.rsa = rsa
        self.schema = schema
        self.executor = executor
        self.transport_codec = transport_codec

    def __copy__(self):
        return DatacenterInfo(self.address, self.port, self.rsa, self.schema, self.executor, self.transport_codec)

    def __str__(self):
        return f"{self.address}:{self.port} (layer: {self.schema.layer})"
