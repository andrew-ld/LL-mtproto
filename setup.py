# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2025 (andrew) https://github.com/andrew-ld/LL-mtproto
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import sysconfig

from mypyc.build import mypycify
from setuptools import setup, Extension
from setuptools.command.build_py import build_py as _build_py


class build_py(_build_py):
    def run(self):
        sys.path.append(os.getcwd())

        from ll_mtproto.tl.types_generator import generate_schema_types

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
    openssl_crypto_provider.extra_compile_args.append("-march=x86-64-v3")

setup(
    ext_modules=mypyc_extensions + [openssl_crypto_provider],
    cmdclass={
        "build_py": build_py
    }
)
