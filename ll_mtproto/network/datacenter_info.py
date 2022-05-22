from concurrent.futures import Executor

from .encryption import PublicRSA
from ..tl.tl import Schema


class DatacenterInfo:
    __slots__ = ("address", "port", "rsa", "schema", "executor")

    address: str
    port: int
    rsa: PublicRSA
    schema: Schema
    executor: Executor

    def __init__(self, address: str, port: int, rsa: PublicRSA, schema: Schema, executor: Executor):
        self.address = address
        self.port = port
        self.rsa = rsa
        self.schema = schema
        self.executor = executor

    def __str__(self):
        return f"{self.address}:{self.port} (layer: {self.schema.layer})"
