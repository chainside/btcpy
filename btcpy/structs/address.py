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

from abc import ABCMeta

from ..lib.codecs import Bech32Codec, Base58Codec, CouldNotDecode
from ..setup import is_mainnet, net_name


class AddressBuilder(object):

    # TODO: manage actual SegWit encoding

    types = {'p2wpkh', 'p2wsh', 'p2pkh', 'p2sh'}
    nets = {'mainnet', 'testnet'}

    codecs = {'p2wpkh': Bech32Codec,
              'p2wsh': Bech32Codec,
              'p2pkh': Base58Codec,
              'p2sh': Base58Codec}

    prefixes = {('mainnet', 'p2wpkh'): {'bc1'},
                ('testnet', 'p2wpkh'): {'tb1'},
                ('mainnet', 'p2wsh'): {'bc1'},
                ('testnet', 'p2wsh'): {'tb1'},
                ('mainnet', 'p2pkh'): {'1'},
                ('testnet', 'p2pkh'): {'m', 'n'},
                ('mainnet', 'p2sh'): {'3'},
                ('testnet', 'p2sh'): {'2'}}

    raw_prefixes = {('mainnet', 'p2pkh'): bytearray(b'\x00'),
                    ('testnet', 'p2pkh'): bytearray(b'\x6f'),
                    ('mainnet', 'p2sh'): bytearray(b'\x05'),
                    ('testnet', 'p2sh'): bytearray(b'\xc4')}

    lengths = {'p2wpkh': 42,
               'p2wsh': 62}

    prefix_remove = {'p2pkh': lambda raw: raw[1:],
                     'p2sh': lambda raw: raw[1:]}

    hash_lens = {'p2pkh': 20,
                 'p2sh': 20,
                 'p2wpkh': 20,
                 'p2wsh': 32}

    @staticmethod
    def _has_prefix(network, addr_type, address):
        try:
            for prefix in AddressBuilder.prefixes[(network, addr_type)]:
                if address.startswith(prefix):
                    return True
        except KeyError:
            return True
        return False

    @staticmethod
    def _has_length(addr_type, address):
        try:
            if len(address) == AddressBuilder.lengths[addr_type]:
                return True
        except KeyError:
            return True
        return False

    @staticmethod
    def _address_data(address):
        for network in AddressBuilder.nets:
            for addr_type in AddressBuilder.types:
                addr_data = (network, addr_type)
                if AddressBuilder._has_prefix(*addr_data, address) and AddressBuilder._has_length(addr_type, address):
                    return addr_data
        raise ValueError('Unrecognised address: {}'.format(address))

    @staticmethod
    def _address_to_codec(address):
        network, addr_type = AddressBuilder._address_data(address)
        return AddressBuilder.codecs[addr_type]

    @staticmethod
    def addr_from_str(string, check_network=True):
        network, addr_type = AddressBuilder._address_data(string)
        codec = AddressBuilder.codecs[addr_type]

        try:
            address = codec.decode(string)
        except CouldNotDecode:
            raise ValueError('Codec {} could not decode string: {}'.format(codec.__name__, string))

        try:
            hashed_data = AddressBuilder.prefix_remove[addr_type](address)
        except KeyError:
            raise ValueError('No prefix for address type {}'.format(addr_type))

        try:
            if len(hashed_data) != AddressBuilder.hash_lens[addr_type]:
                raise ValueError('Wrong length for address: {}.'
                                 'Expected: {}'.format(len(hashed_data), AddressBuilder.hash_lens[addr_type]))
            if check_network and (network == 'mainnet') != is_mainnet():
                raise ValueError('Trying to parse {} address in {} environment'.format(network, net_name()))
            return Address(addr_type, hashed_data, network == 'mainnet')
        except KeyError:
            raise ValueError('No length found for address type: {}'.format(addr_type))

    @staticmethod
    def str_from_addr(address):
        raw_prefix = AddressBuilder.raw_prefixes[(address.network, address.type)]
        return AddressBuilder.codecs[address.type].encode(raw_prefix + address.hash).decode()


class Address(metaclass=ABCMeta):

    @staticmethod
    def from_string(string, check_mainnet=True):
        return AddressBuilder.addr_from_str(string, check_mainnet)

    def __init__(self, addr_type, hashed_data, mainnet=None):
        if mainnet is None:
            mainnet = is_mainnet()
        network = 'mainnet' if mainnet else 'testnet'
        if addr_type not in AddressBuilder.types:
            raise ValueError('Unknown address type: {}'.format(addr_type))
        self.network = network
        self.type = addr_type
        self.hash = hashed_data

    def __str__(self):
        return AddressBuilder.str_from_addr(self)
