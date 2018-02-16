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

from abc import ABCMeta, abstractmethod
from base58 import b58encode_check, b58decode_check

from .bech32 import decode, encode
from ..setup import net_name
from ..constants import NETWORKS
from ..structs.address import Address, SegWitAddress


class CouldNotDecode(ValueError):
    pass


class CouldNotEncode(ValueError):
    pass


class Codec(metaclass=ABCMeta):

    @staticmethod
    @abstractmethod
    def encode(address: Address) -> str:
        raise NotImplemented

    @staticmethod
    @abstractmethod
    def decode(string: str, check_network=True) -> Address:
        raise NotImplemented

    @classmethod
    def check_network(cls, network):
        if network != net_name():
            raise CouldNotDecode('Trying to parse {} address in {} environment'.format(network, net_name()))


class Base58Codec(Codec):

    hash_len = 20

    @staticmethod
    def encode(address):
        try:
            prefix = NETWORKS[net_name()].raw_prefixes[(address.network, address.type)]
        except KeyError:
            raise CouldNotEncode('Impossible to encode address type: {}, network: {}'.format(address.type,
                                                                                             address.network))
        return b58encode_check(bytes(prefix + address.hash))

    @staticmethod
    def decode(string, check_network=True):
        try:
            addr_type, network = NETWORKS[net_name()].prefixes[string[0]]
        except KeyError:
            raise CouldNotDecode('Impossible to decode address {}'.format(string))
        hashed_data = bytearray(b58decode_check(string))[1:]

        if len(hashed_data) != Base58Codec.hash_len:
            raise CouldNotDecode('Data of the wrong length: {}, expected {}'.format(len(hashed_data),
                                                                                    Base58Codec.hash_len))
        if check_network:
            Base58Codec.check_network(network)

        return Address(addr_type, hashed_data, network)


class Bech32Codec(Codec):

    lengths = {42: 'p2wpkh',
               62: 'p2wsh'}

    @staticmethod
    def encode(address):
        prefix = NETWORKS[net_name()].net_to_hrp[address.network]
        return encode(prefix, address.version, address.hash)

    @staticmethod
    def decode(string, check_network=True):
        if not string:
            raise CouldNotDecode('Impossible to decode empty string')

        lower = string[0].islower()
        for char in string:
            if not char.isdigit() and char.islower() != lower:
                raise CouldNotDecode('String {} mixes upper- and lower-case characters'.format(string))

        string = string.lower()
        try:
            network = NETWORKS[net_name()].hrp_to_net[string[:2]]
            addr_type = Bech32Codec.lengths[len(string)]
        except KeyError:
            raise CouldNotDecode('Impossible to decode address {}'.format(string))
        version, hashed_data = decode(string[:2], string)

        if not hashed_data:
            raise CouldNotDecode('Empty hash')

        if check_network:
            Bech32Codec.check_network(network)

        return SegWitAddress(addr_type, bytearray(hashed_data), version, network == 'mainnet')
