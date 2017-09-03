from distutils.core import setup
from setuptools import find_packages

setup(name='btcpy',
      version='1.0',
      packages=find_packages(),
      install_requires=['ecdsa', 'base58', 'python-bitcoinlib==0.7.0'])
