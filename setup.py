import sysconfig

from mypyc.build import mypycify
from setuptools import setup, Extension

sysconfig_platform = sysconfig.get_platform()
is_x86_64 = sysconfig_platform.endswith('x86_64')

mypyc_extensions = mypycify([
    'll_mtproto/tl/tl.py',
])

openssl_crypto_provider = Extension(
    'll_mtproto.crypto.providers.crypto_provider_openssl._impl',
    sources=['ll_mtproto/crypto/providers/crypto_provider_openssl/_impl.cpp'],
    libraries=['crypto'],
    extra_compile_args=['-std=c++17', '-Wall', '-Wextra', '-Werror', '-fno-exceptions', '-O3', '-flto'],
    extra_link_args=['-flto'],
    language='c++',
)

if is_x86_64:
    openssl_crypto_provider.extra_compile_args.append("-march=haswell")

setup(
    ext_modules=mypyc_extensions + [openssl_crypto_provider],
)
