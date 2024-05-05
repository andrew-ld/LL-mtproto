import pickle
import sys
import timeit
import typing

from ll_mtproto import TelegramDatacenter
from ll_mtproto.tl.byteutils import to_reader, reader_discard
from ll_mtproto.tl.structure import Structure


tlobjpath = sys.argv[-1]


with open(tlobjpath, "rb") as cf:
    tlobj = typing.cast(Structure, Structure.from_obj(pickle.load(cf)))


tlobjdict = tlobj.get_dict()
tlobjcons = tlobj.constructor_name
tlschema = TelegramDatacenter.VESTA.schema
serialized = tlschema.serialize(True, tlobjcons, tlobjdict).get_flat_bytes()


def test_read():
    reader = to_reader(serialized)
    tlschema.read_by_boxed_data(reader)
    reader_discard(reader)


def test_write():
    tlschema.serialize(True, tlobjcons, tlobjdict).get_flat_bytes()


print(timeit.timeit(test_read, number=100_000))
print(timeit.timeit(test_write, number=100_000))
