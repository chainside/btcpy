# Copyright (C) 2017 chainside srl
#
# This file is part of the btcpy package.
#
# It is subject to the license terms in the LICENSE.md file found in the top-level
# directory of this distribution.
#
# No part of btcpy, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE.md file.


from distutils.core import setup
from setuptools import find_packages

setup(name='btcpy',
      version='1.0',
      packages=find_packages(),
      install_requires=['ecdsa', 'base58', 'python-bitcoinlib==0.7.0'])
