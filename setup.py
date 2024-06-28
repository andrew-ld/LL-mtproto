from setuptools import setup
from mypyc.build import mypycify

setup(ext_modules=mypycify([]))
