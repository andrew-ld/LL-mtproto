import pathlib
from setuptools import setup
from mypyc.build import mypycify

here = pathlib.Path(__file__).parent
init = here / "ll_mtproto" / "__init__.py"
readme_path = here / "README.md"

with open("requirements.txt", encoding="utf-8") as r:
    requires = [i.strip() for i in r]

with readme_path.open() as f:
    README = f.read()

setup(
    name='ll_mtproto',
    description='abstraction-free mtproto client',
    long_description=README,
    long_description_content_type='text/markdown',
    url='https://github.com/andrew-ld/LL-mtproto',
    packages=["ll_mtproto", ],
    ext_modules=mypycify([]),
    python_requires='>=3.12.0',
    install_requires=requires
)
