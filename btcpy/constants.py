class Constants(object):

    _lookup = {'base58.prefixes': {'1': ('p2pkh', 'mainnet'),
                                   'm': ('p2pkh', 'testnet'),
                                   'n': ('p2pkh', 'testnet'),
                                   '3': ('p2sh', 'mainnet'),
                                   '2': ('p2sh', 'testnet')},
               'base58.raw_prefixes': {('mainnet', 'p2pkh'): bytearray(b'\x00'),
                                       ('testnet', 'p2pkh'): bytearray(b'\x6f'),
                                       ('mainnet', 'p2sh'): bytearray(b'\x05'),
                                       ('testnet', 'p2sh'): bytearray(b'\xc4')},
               'bech32.net_to_hrp': {'mainnet': 'bc',
                                     'testnet': 'tb'},
               'bech32.hrp_to_net': {'bc': 'mainnet',
                                     'tb': 'testnet'},
               'xkeys.prefixes': {'mainnet': 'x', 'testnet': 't'},
               'xpub.version': {'mainnet': b'\x04\x88\xb2\x1e', 'testnet': b'\x04\x35\x87\xcf'},
               'xprv.version': {'mainnet': b'\x04\x88\xad\xe4', 'testnet': b'\x04\x35\x83\x94'},
               'wif.prefixes': {'mainnet': 0x80, 'testnet': 0xef}}

    @staticmethod
    def get(key):
        try:
            return Constants._lookup[key]
        except KeyError:
            raise ValueError('Unknown constant: {}'.format(key))
