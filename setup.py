from mypyc.build import mypycify
from setuptools import setup, Extension

mypyc_extensions = mypycify([
    'll_mtproto/tl/tl.py',
])

cpp_extension = Extension(
    'll_mtproto.crypto.providers.crypto_provider_openssl._impl',
    sources=['ll_mtproto/crypto/providers/crypto_provider_openssl/_impl.cpp'],
    libraries=['crypto'],
    extra_compile_args=['-std=c++17', '-Wall', '-Wextra', '-Werror', '-fno-exceptions', '-Ofast', '-flto'],
    extra_link_args=['-flto'],
    language='c++',
)

setup(
    ext_modules=mypyc_extensions + [cpp_extension],
)
