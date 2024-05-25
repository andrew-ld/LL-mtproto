import pickle
import sys
import timeit
import typing

from ll_mtproto import TelegramDatacenter
from ll_mtproto.tl.structure import Structure
from ll_mtproto.tl.tl import NativeByteReader

tlobjpath = sys.argv[-1]


with open(tlobjpath, "rb") as cf:
    tlobj = typing.cast(Structure, Structure.from_obj(pickle.load(cf)))


tlobjdict = tlobj.get_dict()
tlobjcons = tlobj.constructor_name
tlschema = TelegramDatacenter.SCHEMA
serialized = tlschema.serialize(True, tlobjcons, tlobjdict).get_flat_bytes()


def test_read():
    tlschema.read_by_boxed_data(NativeByteReader(serialized))


def test_write():
    tlschema.serialize(True, tlobjcons, tlobjdict).get_flat_bytes()


print(timeit.timeit(test_read, number=100_000))
print(timeit.timeit(test_write, number=100_000))
