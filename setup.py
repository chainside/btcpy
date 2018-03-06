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

setup(name='chainside-btcpy',
      version='0.3.3',
      packages=find_packages(),
      install_requires=['ecdsa==0.13'],
      extras_require={'develop': ['python-bitcoinlib==0.7.0']},
      description='A Python3 SegWit-compliant library which provides tools to handle Bitcoin data structures in a simple fashion.',
      author='chainside srl',
      author_email='simone.bronzini@chainside.net',
      url='https://github.com/chainside/btcpy',
      download_url='https://github.com/chainside/btcpy/archive/0.3.3.tar.gz',
      python_requires='>=3',
      keywords=['bitcoin', 'blockchain', 'bitcoind', 'chainside'])
