import pickle
import sys
import timeit
import typing

from ll_mtproto import TelegramDatacenter
from ll_mtproto.tl.byteutils import to_reader
from ll_mtproto.tl.structure import Structure


tlobjpath = sys.argv[-1]


with open(tlobjpath, "rb") as cf:
    tlobj = typing.cast(Structure, Structure.from_obj(pickle.load(cf)))


tlobjdict = tlobj.get_dict()
tlobjcons = tlobj.constructor_name
tlschema = TelegramDatacenter.VESTA.schema
serialized = tlschema.serialize(True, tlobjcons, tlobjdict).get_flat_bytes()


def test():
    tlschema.read_by_boxed_data(to_reader(serialized))


print(timeit.timeit(test, number=100_000))
