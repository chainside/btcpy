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

from functools import wraps

networks = {'mainnet', 'testnet', 'regtest'}

MAINNET = None
NETNAME = None
STRICT = None


def strictness(func):
    @wraps(func)
    def wrapper(*args, strict=None, **kwargs):
        if strict is None:
            strict = is_strict()
        return func(*args, strict=strict, **kwargs)
    return wrapper


def setup(network='mainnet', strict=True, force=False):
    global MAINNET, NETNAME, STRICT

    prev_state = get_state()

    if (MAINNET is not None and NETNAME != network) or (STRICT is not None and strict != is_strict()):
        if not force:
            raise ValueError('Trying to change network type at runtime')

    if network not in networks:
        raise ValueError('Unknown network type: {}'.format(network))

    MAINNET = (network == 'mainnet')
    NETNAME = network
    STRICT = strict

    return prev_state


def get_state():
    global MAINNET, NETNAME, STRICT
    return {'netname': NETNAME,
            'mainnet': MAINNET,
            'strict': STRICT}


def is_strict():
    global STRICT
    if STRICT is None:
        ValueError('Strictness not set')
    return STRICT


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
