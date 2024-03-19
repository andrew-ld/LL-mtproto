# LL-MTPROTO  
> LL-mtproto is an abstraction-free mtproto client.

# ABOUT
ll-mtproto was developed as an answer to the mtproto clients currently existing on the opensource market, they are too complicated due to excessive abstraction layers, unfortunately these abstractions are difficult to maintain and have a strong impact on performance.

# FAST DYNAMIC TL DESERIALIZER
ll-mtproto unlike many alternatives does not generate code to deserialize the received data, it parse at runtime the schema and use it to deserialize the data, deserializer has been heavily adapted to be able to be compiled to native machine code to achieve superior performance

To compile the deserializer simply run mypyc by giving as input the file tl.py

`python3 -m mypyc --strict ll_mtproto/tl/tl.py ll_mtproto/tl/byteutils.py`

# LICESING
it must be noted that ll-mtproto is a derivative work of mtproto2json developed by @nikat, the publication of ll-mtproto under agplv3 license is possible only thanks to the approval of nikat to change the license of mtproto2json with agplv3.