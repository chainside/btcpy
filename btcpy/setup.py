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
from .constants import Constants, BitcoinConstants

MAINNET = None
NETNAME = None
NETWORKS = {'mainnet': None,
            'testnet': None,
            'regtest': None}


def setup(network: str='mainnet', network_params: Constants=None,
          force: bool=False) -> None:
    '''Set network type and parameters to be used by the library.'''

    global MAINNET, NETNAME, NETWORKS

    if not network_params:  # by default load bitcoin-core params
        params = BitcoinConstants()

    if network_params:  # verify it's instance of Constants class to ensure compatibility.
        assert isinstance(network_params, Constants)

    if MAINNET is not None and NETNAME != network and not force:
        raise ValueError('Trying to change network type at runtime')

    if network not in NETWORKS:
        raise ValueError('Unknown network type: {}'.format(network))

    NETWORKS = {'mainnet': params,
                'testnet': params,
                'regtest': params}

    MAINNET = (network == 'mainnet')
    NETNAME = network


def is_mainnet():
    global MAINNET
    if MAINNET is None:
        raise ValueError('Network type not set')
    return MAINNET


def net_name():
    global NETNAME
    if NETNAME is None:
        raise ValueError('Network type not set')
    if NETNAME == 'regtest':
        return 'testnet'
    return NETNAME
