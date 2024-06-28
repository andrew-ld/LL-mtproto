from setuptools import setup

from mypyc.build import mypycify

setup(
    ext_modules=mypycify([
        '--strict',
        '--pretty',
        '--enable-incomplete-feature=NewGenericSyntax',
        'll_mtproto/tl/tl.py'
    ]),
)
