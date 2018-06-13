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

from btcpy.constants import BitcoinMainnet, BitcoinTestnet

NETWORKS = (BitcoinMainnet, BitcoinTestnet)
NETWORK = None
STRICT = None


def strictness(func):
    @wraps(func)
    def wrapper(*args, strict=None, **kwargs):
        if strict is None:
            strict = is_strict()
        return func(*args, strict=strict, **kwargs)
    return wrapper


def setup(network=BitcoinMainnet, strict=True, force=False):
    global NETWORK, STRICT

    prev_state = get_state()

    if (NETWORK is not None and NETWORK != network) or (STRICT is not None and strict != is_strict()):
        if not force:
            raise ValueError('Trying to change network type at runtime')

    if network not in NETWORKS:
        raise ValueError('Unknown network type: {}'.format(network))

    NETWORK = network
    STRICT = strict

    return prev_state


def get_state():
    global NETWORK, STRICT
    return {'network': NETWORK,
            'strict': STRICT}


def is_strict():
    global STRICT
    if STRICT is None:
        ValueError('Strictness not set')
    return STRICT
