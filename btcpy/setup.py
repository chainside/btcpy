networks = {'mainnet', 'testnet', 'regtest'}

MAINNET = None
NETNAME = None


def setup(network='mainnet'):
    global MAINNET, NETNAME
    if MAINNET is not None:
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
