from decimal import Decimal


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
               'xkeys.prefixes': {
                   b'\x04\x88\xb2\x1e': {'network': 'mainnet', 'prefix': 'x', 'type': 'pub'},
                   b'\x04\x88\xad\xe4': {'network': 'mainnet', 'prefix': 'x', 'type': 'prv'},

                   b'\x04\x35\x87\xcf': {'network': 'testnet', 'prefix': 't', 'type': 'pub'},
                   b'\x04\x35\x83\x94': {'network': 'testnet', 'prefix': 't', 'type': 'prv'},

                   b'\x04\x9d\x7c\xb2': {'network': 'mainnet', 'prefix': 'y', 'type': 'pub'},
                   b'\x04\x9d\x78\x78': {'network': 'mainnet', 'prefix': 'y', 'type': 'prv'},

                   b'\x04\x4a\x52\x62': {'network': 'testnet', 'prefix': 'u', 'type': 'pub'},
                   b'\x04\x4a\x4e\x28': {'network': 'testnet', 'prefix': 'u', 'type': 'prv'},

                   b'\x04\xb2\x47\x46': {'network': 'mainnet', 'prefix': 'z', 'type': 'pub'},
                   b'\x04\xb2\x43\x0c': {'network': 'mainnet', 'prefix': 'z', 'type': 'prv'},

                   b'\x04\x5f\x1c\xf6': {'network': 'testnet', 'prefix': 'v', 'type': 'pub'},
                   b'\x04\x5f\x18\xbc': {'network': 'testnet', 'prefix': 'v', 'type': 'prv'}
               },
               'xkeys.versions': {
                   'xpub': b'\x04\x88\xb2\x1e',
                   'xprv': b'\x04\x88\xad\xe4',
                   'ypub': b'\x04\x9d\x7c\xb2',
                   'yprv': b'\x04\x9d\x78\x78',
                   'zpub': b'\x04\xb2\x47\x46',
                   'zprv': b'\x04\xb2\x43\x0c',

                   'tpub': b'\x04\x35\x87\xcf',
                   'tprv': b'\x04\x35\x83\x94',
                   'upub': b'\x04\x4a\x52\x62',
                   'uprv': b'\x04\x4a\x4e\x28',
                   'vpub': b'\x04\x5f\x1c\xf6',
                   'vprv': b'\x04\x5f\x18\xbc',

               },
               'wif.prefixes': {'mainnet': 0x80, 'testnet': 0xef},
               'from_unit': Decimal('1e-8'),
               'to_unit': Decimal('1e8')
               }

    @staticmethod
    def get(key):
        try:
            return Constants._lookup[key]
        except KeyError:
            raise ValueError('Unknown constant: {}'.format(key))
