import sysconfig

from mypyc.build import mypycify
from setuptools import setup, Extension
from setuptools.command.build_py import build_py as _build_py

from ll_mtproto.tl.types_generator import generate_schema_types


class build_py(_build_py):
    def run(self):
        generate_schema_types(
            schema_file="ll_mtproto/resources/tl/application.tl",
            output_file="ll_mtproto/tl/tls_application.py"
        )

        _build_py.run(self)


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
    cmdclass={
        "build_py": build_py
    }
)
