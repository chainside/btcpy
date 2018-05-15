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

from ..setup import is_mainnet, strictness


class WrongScriptType(Exception):
    pass


class BaseAddress(metaclass=ABCMeta):

    @staticmethod
    @strictness
    def is_valid(string, strict=None):
        from ..lib.codecs import CouldNotDecode

        try:
            Address.from_string(string, strict=strict)
            return True
        except CouldNotDecode:
            try:
                SegWitAddress.from_string(string, strict=strict)
                return True
            except CouldNotDecode:
                return False

    @staticmethod
    @abstractmethod
    def get_codec():
        raise NotImplemented

    @classmethod
    @abstractmethod
    def from_script(cls, script, mainnet=None):
        raise NotImplemented

    @classmethod
    @abstractmethod
    def get_type(cls):
        raise NotImplemented

    @classmethod
    @strictness
    def from_string(cls, string, strict=None):
        return cls.get_codec().decode(string, strict=strict)

    @classmethod
    def hash_length(cls):
        raise NotImplemented

    def __init__(self, hashed_data):
        if len(hashed_data) != self.__class__.hash_length():
            raise ValueError('Hashed data must be {}-bytes long, length: {}'.format(self.__class__.hash_length(),
                                                                                    len(hashed_data)))

    def __str__(self):
        return self.__class__.get_codec().encode(self)


class Address(BaseAddress, metaclass=ABCMeta):

    @staticmethod
    def get_codec():
        from ..lib.codecs import Base58Codec
        return Base58Codec

    def __init__(self, hashed_data, mainnet=None):

        super().__init__(hashed_data)

        if mainnet is None:
            mainnet = is_mainnet()
        self.network = 'mainnet' if mainnet else 'testnet'
        self.hash = hashed_data

    def __eq__(self, other):
        return (self.network, self.hash) == (other.network, other.hash)


class SegWitAddress(BaseAddress, metaclass=ABCMeta):

    @staticmethod
    def get_codec():
        from ..lib.codecs import Bech32Codec
        return Bech32Codec

    def __init__(self, hashed_data, version, mainnet=None):

        super().__init__(hashed_data)

        if mainnet is None:
            mainnet = is_mainnet()
        self.network = 'mainnet' if mainnet else 'testnet'
        self.hash = hashed_data
        self.version = version

    def __eq__(self, other):
        return (self.network, self.hash, self.version) == (other.network, other.hash, other.version)


class P2pkhAddress(Address):

    @classmethod
    def get_type(cls):
        return 'p2pkh'

    @classmethod
    def from_script(cls, script, mainnet=None):
        from .script import P2pkhScript
        # can't use isinstance here: P2wpkhScript is child of P2pkhScript
        if script.__class__ is not P2pkhScript:
            raise WrongScriptType('Trying to produce P2pkhAddress from {} script'.format(script.__class__.__name__))

        return cls(script.pubkeyhash, mainnet)

    @classmethod
    def hash_length(cls):
        return 20


class P2shAddress(Address):

    @classmethod
    def get_type(cls):
        return 'p2sh'

    @classmethod
    def from_script(cls, script, mainnet=None):
        from .script import P2shScript
        # can't use isinstance here: P2wshScript is child of P2shScript
        if script.__class__ is P2shScript:
            return cls(script.scripthash, mainnet)
        return cls(script.p2sh_hash(), mainnet)

    @classmethod
    def hash_length(cls):
        return 20


class P2wpkhAddress(SegWitAddress):

    @classmethod
    def get_type(cls):
        return 'p2wpkh'

    @classmethod
    def from_script(cls, script, mainnet=None):
        from .script import P2wpkhScript
        if not isinstance(script, P2wpkhScript):
            raise WrongScriptType('Trying to produce P2pkhAddress from {} script'.format(script.__class__.__name__))

        return cls(script.pubkeyhash, script.__class__.get_version(), mainnet)

    @classmethod
    def hash_length(cls):
        return 20


class P2wshAddress(SegWitAddress):

    @classmethod
    def get_type(cls):
        return 'p2wsh'

    @classmethod
    def from_script(cls, script, mainnet=None):
        from .script import P2wshScript
        version = script.__class__.get_version()
        if isinstance(script, P2wshScript):
            hashed_data = script.scripthash
        else:
            hashed_data = script.p2wsh_hash()
        return cls(hashed_data, version, mainnet)

    @classmethod
    def hash_length(cls):
        return 32
