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


class InvalidAddress(Exception):
    pass


class Address(metaclass=ABCMeta):

    @classmethod
    @strictness
    def is_valid(cls, string, strict=None):
        try:
            cls.from_string(string, strict=strict)
        except InvalidAddress:
            return False
        return True

    @classmethod
    def get_codec(cls):
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
    def hash_length(cls):
        raise NotImplemented

    def __str__(self):
        return self.__class__.get_codec().encode(self)

    @staticmethod
    @strictness
    def from_string(string, strict=None):
        from ..lib.codecs import CouldNotDecode

        try:
            return ClassicAddress.decode(string, strict=strict)
        except CouldNotDecode:
            try:
                return SegWitAddress.decode(string, strict=strict)
            except CouldNotDecode:
                raise InvalidAddress

    @classmethod
    @strictness
    def decode(cls, string, strict=None):
        return cls.get_codec().decode(string, strict=strict)

    def __init__(self, hashed_data, mainnet=None):
        if len(hashed_data) != self.__class__.hash_length():
            raise ValueError('Hashed data must be {}-bytes long, length: {}'.format(self.__class__.hash_length(),
                                                                                    len(hashed_data)))

        if mainnet is None:
            mainnet = is_mainnet()
        self.network = 'mainnet' if mainnet else 'testnet'
        self.hash = hashed_data

    def __eq__(self, other):
        return (self.network, self.hash) == (other.network, other.hash)

    def get_script_type(self):
        raise NotImplemented

    def to_script(self):
        return self.get_script_type()(self.hash)


class ClassicAddress(Address, metaclass=ABCMeta):

    @classmethod
    def get_codec(cls):
        from ..lib.codecs import Base58Codec
        return Base58Codec


class SegWitAddress(Address, metaclass=ABCMeta):

    @classmethod
    def get_codec(cls):
        from ..lib.codecs import Bech32Codec
        return Bech32Codec

    def __init__(self, hashed_data, version, mainnet=None):
        super().__init__(hashed_data, mainnet)
        self.version = version

    def __eq__(self, other):
        return self.version == other.version and super().__eq__(other)


class P2pkhAddress(ClassicAddress):

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

    def get_script_type(self):
        from .script import P2pkhScript
        return P2pkhScript


class P2shAddress(ClassicAddress):

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

    def get_script_type(self):
        from .script import P2shScript
        return P2shScript


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

    def get_script_type(self):
        from .script import P2wpkhScript
        return P2wpkhScript.get(self.version)


class P2wshAddress(SegWitAddress):

    @classmethod
    def get_type(cls):
        return 'p2wsh'

    @classmethod
    def from_script(cls, script, mainnet=None, version=0):
        from .script import P2wshScript, P2shScript, P2wpkhScript

        if script.__class__ is P2shScript or isinstance(script, P2wpkhScript):
            raise ValueError("Can't embed {} in P2WSH".format(script.__class__.__name__))

        if isinstance(script, P2wshScript):
            script_version = script.__class__.get_version()
            if script_version != version:
                raise ValueError('Script version is {}, requested version is {}'.format(script_version, version))
            hashed_data = script.scripthash
        else:
            hashed_data = script.p2wsh_hash()

        return cls(hashed_data, version, mainnet)

    @classmethod
    def hash_length(cls):
        return 32

    def get_script_type(self):
        from .script import P2wshScript
        return P2wshScript.get(self.version)
