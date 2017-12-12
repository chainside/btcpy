from btcpy.lib.codecs import Base58Codec, Bech32Codec
from btcpy.structs.crypto import PrivateKey
from btcpy.structs.hd import ExtendedKey, ExtendedPrivateKey, ExtendedPublicKey


class Constants:
    wif_prefixes = None
    raw_prefixes = None
    prefixes = None
    net_to_hrp = None
    hrp_to_net = None
    key_prefixes = None
    public_key_version_strings = None
    private_key_version_strings = None

    @classmethod
    def init_constants(cls):
        Base58Codec.prefixes = cls.prefixes
        Base58Codec.raw_prefixes = cls.raw_prefixes
        PrivateKey.wif_prefixes = cls.wif_prefixes
        Bech32Codec.hrp_to_net = cls.hrp_to_net
        Bech32Codec.net_to_hrp = cls.net_to_hrp
        ExtendedKey.key_prefixes = cls.key_prefixes
        ExtendedPrivateKey.version_strings = cls.private_key_version_strings
        ExtendedPublicKey.version_strings = cls.public_key_version_strings


class BitcoinConstants(Constants):

    wif_prefixes = {'mainnet': 0x80, 'testnet': 0xef}

    raw_prefixes = {('mainnet', 'p2pkh'): bytearray(b'\x00'),
                    ('testnet', 'p2pkh'): bytearray(b'\x6f'),
                    ('mainnet', 'p2sh'): bytearray(b'\x05'),
                    ('testnet', 'p2sh'): bytearray(b'\xc4')}

    prefixes = {'1': ('p2pkh', 'mainnet'),
                'm': ('p2pkh', 'testnet'),
                'n': ('p2pkh', 'testnet'),
                '3': ('p2sh', 'mainnet'),
                '2': ('p2sh', 'testnet')}

    net_to_hrp = {'mainnet': 'bc',
                  'testnet': 'tb'}

    hrp_to_net = {'bc': 'mainnet',
                  'tb': 'testnet'}

    key_prefixes = {'x': 'mainnet', 't': 'testnet'}

    public_key_version_strings = {'mainnet': b'\x04\x88\xb2\x1e', 'testnet': b'\x04\x35\x87\xcf'}

    private_key_version_strings = {'mainnet': b'\x04\x88\xad\xe4', 'testnet': b'\x04\x35\x83\x94'}


NETWORKS = {'mainnet': BitcoinConstants(),
            'testnet': BitcoinConstants(),
            'regtest': BitcoinConstants()}
