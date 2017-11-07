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

networks = {'mainnet', 'testnet', 'regtest'}

MAINNET = None
NETNAME = None


def setup(network='mainnet', force=False):
    global MAINNET, NETNAME
    if MAINNET is not None and NETNAME != network and not force:
        raise ValueError('Trying to change network type at runtime')
    if network not in networks:
        raise ValueError('Unknown network type: {}'.format(network))
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
    return NETNAME
