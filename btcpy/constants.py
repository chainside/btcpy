from .setup import net_name

wif_prefixes = {
    'mainnet': 0x80,
    'testnet': 0xEF,
    'litecoin': 0xB0,
    'dashcoin': 0xCC
}

raw_prefixes_c = {('mainnet', 'p2pkh'): bytearray(b'\x00'),
                  ('testnet', 'p2pkh'): bytearray(b'\x6f'),
                  ('mainnet', 'p2sh'): bytearray(b'\x05'),
                  ('testnet', 'p2sh'): bytearray(b'\xc4'),
                  ('litecoin', 'p2pkh'): bytearray(b'\x30'),
                  ('litecoin', 'p2sh'): bytearray(b'\x32'),
                  ('dashcoin', 'p2pkh'): bytearray(b'\x4c'),
                  ('dashcoin', 'p2sh'): bytearray(b'\x13')
                  }

prefixes_c = {'1': ('p2pkh', 'mainnet'),
              'm': ('p2pkh', 'testnet'),
              'n': ('p2pkh', 'testnet'),
              '3': ('p2sh', 'mainnet'),
              '2': ('p2sh', 'testnet'),
              'L': ('p2pkh', 'litecoin'),
              'M': ('p2sh', 'litecoin'),
              'X': ('p2pkh', 'dashcoin')
              }

raw_prefixes_to_init = {
    'litecoin':
        {
            'L': ('p2pkh', 'litecoin'),
            'M': ('p2sh', 'litecoin')
        },
    'dashcoin':
        {
            'X': ('p2pkh', 'dashcoin'),
            '8': ('p2sh', 'dashcoin'),
            '9': ('p2sh', 'dashcoin')
        },
    'mainnet':
        {
            '1': ('p2pkh', 'mainnet'),
            '3': ('p2sh', 'mainnet')
        },
    'testnet':
        {
            'm': ('p2pkh', 'testnet'),
            'n': ('p2pkh', 'testnet'),
            '2': ('p2sh', 'testnet')
        }
}


def prefixes_c():
    return raw_prefixes_to_init[net_name()]
