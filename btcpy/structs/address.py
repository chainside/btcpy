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

from ..setup import is_mainnet


class BaseAddress(metaclass=ABCMeta):

    @staticmethod
    def is_valid(string, check_network=True):
        from ..lib.codecs import CouldNotDecode
        try:
            Address.from_string(string, check_network=check_network)
            return True
        except CouldNotDecode:
            try:
                SegWitAddress.from_string(string, check_network=check_network)
                return True
            except CouldNotDecode:
                return False

    @staticmethod
    @abstractmethod
    def get_codec():
        raise NotImplemented

    @classmethod
    def from_string(cls, string, check_network=True):
        return cls.get_codec().decode(string, check_network)

    def __str__(self):
        return self.__class__.get_codec().encode(self)


class Address(BaseAddress):

    @staticmethod
    def get_codec():
        from ..lib.codecs import Base58Codec
        return Base58Codec

    def __init__(self, addr_type, hashed_data, mainnet=None):
        if mainnet is None:
            mainnet = is_mainnet()
        network = 'mainnet' if mainnet else 'testnet'
        self.network = network
        self.type = addr_type
        self.hash = hashed_data

    def __eq__(self, other):
        return (self.type, self.network, self.hash) == (other.type, other.network, other.hash)


class SegWitAddress(Address):

    @staticmethod
    def get_codec():
        from ..lib.codecs import Bech32Codec
        return Bech32Codec

    def __init__(self, addr_type, hashed_data, version, mainnet=None):
        super().__init__(addr_type, hashed_data, mainnet)
        self.version = version

    def to_address(self):
        if self.type == 'p2wpkh':
            addr_type = 'p2pkh'
        elif self.type == 'p2wsh':
            addr_type = 'p2sh'
        else:
            raise ValueError('SegWitAddress type does not match p2wpkh nor p2wsh, {} instead'.format(self.type))
        return Address(addr_type, self.hash, self.network == 'mainnet')

    def __eq__(self, other):
        return super().__eq__(other) and self.version == other.version
