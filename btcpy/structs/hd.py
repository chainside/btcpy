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

import hmac
from hashlib import sha512
from base58 import b58decode_check, b58encode_check
from ecdsa import VerifyingKey
from ecdsa.ellipticcurve import INFINITY
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import generator_secp256k1
from abc import ABCMeta, abstractmethod

from ..lib.types import HexSerializable
from ..lib.parsing import Stream, Parser
from ..constants import NETWORKS
from ..setup import net_name
from .crypto import PrivateKey, PublicKey


class ExtendedKey(HexSerializable, metaclass=ABCMeta):
    
    master_parent_fingerprint = bytearray([0]*4)
    first_hardened_index = 1 << 31
    curve_order = SECP256k1.order
    
    @classmethod
    def master(cls, key, chaincode):
        return cls(key, chaincode, 0, cls.master_parent_fingerprint, 0, hardened=True)
    
    @classmethod
    def decode(cls, string, check_network=True):
        if string[0] not in NETWORKS[net_name()].key_prefixes:
            raise ValueError('Encoded key not recognised: {}'.format(string))
        network = NETWORKS[net_name()].key_prefixes[string[0]]
        
        if check_network and network != net_name():
            raise ValueError('Trying to decode {} key in {} environment'.format(network, net_name()))
        
        decoded = b58decode_check(string)
        parser = Parser(bytearray(decoded))
        parser >> 4
        depth = int.from_bytes(parser >> 1, 'big')
        fingerprint = parser >> 4
        index = int.from_bytes(parser >> 4, 'big')
        
        if index >= cls.first_hardened_index:
            index -= cls.first_hardened_index
            hardened = True
        else:
            hardened = False
            
        chaincode = parser >> 32
        keydata = parser >> 33
        
        if string[1:4] == 'prv':
            subclass = ExtendedPrivateKey
        elif string[1:4] == 'pub':
            subclass = ExtendedPublicKey
        else:
            raise ValueError('Encoded key not recognised: {}'.format(string))
        
        key = subclass.decode_key(keydata)
        
        return subclass(key, chaincode, depth, fingerprint, index, hardened)
    
    @staticmethod
    @abstractmethod
    def decode_key(keydata):
        raise NotImplemented
    
    @staticmethod
    @abstractmethod
    def get_version(mainnet=None):
        raise NotImplemented
    
    def __init__(self, key, chaincode, depth, pfing, index, hardened=False):
        if not 0 <= depth <= 255:
            raise ValueError('Depth must be between 0 and 255')
        self.key = key
        self.chaincode = chaincode
        self.depth = depth
        self.parent_fingerprint = pfing
        self.index = index
        self.hardened = hardened
    
    def derive(self, path):
        """
        :param path: a path like "m/44'/0'/1'/0/10" if deriving from a master key,
                     or a relative path like "./0/10"
        :return: the derived ExtendedPublicKey if deriving from an ExtendedPublicKey,
                 the derived ExtendedPrivateKey if deriving from an ExtendedPrivateKey
        """
        steps = path.split('/')
        
        if steps[0] not in {'m', '.'}:
            raise ValueError('Invalid derivation path: {}'.format(path))
        
        if steps[0] == 'm' and not self.is_master():
            raise ValueError('Trying to derive absolute path from non-master key')
        
        current = self
        for step in steps[1:]:
            hardened = False
            if step[-1] == "'":
                hardened = True
                step = step[:-1]
            index = int(step)
            current = current.get_child(index, hardened)
            # print(current)
            
        return current

    @abstractmethod
    def get_child(self, index, hardened=False):
        raise NotImplemented
    
    @abstractmethod
    def _serialized_public(self):
        raise NotImplemented

    @abstractmethod
    def _serialize_key(self):
        raise NotImplemented
    
    def get_hash(self, index, hardened=False):
        cls = self.__class__
        if hardened:
            data = self._serialize_key() + (index + cls.first_hardened_index).to_bytes(4, 'big')
        else:
            data = self._serialized_public() + index.to_bytes(4, 'big')
        h = bytearray(hmac.new(self.chaincode, data, sha512).digest())
        left, right = int.from_bytes(h[:32], 'big'), h[32:]
        if left > cls.curve_order:
            raise ValueError('Left side of hmac generated number bigger than SECP256k1 curve order')
        return left, right
        
    def is_master(self):
        return all([self.depth == 0,
                    self.parent_fingerprint == ExtendedKey.master_parent_fingerprint,
                    self.index == 0])
    
    def encode(self, mainnet=None):
        return b58encode_check(bytes(self.serialize(mainnet)))
    
    def serialize(self, mainnet=None):
        cls = self.__class__
        result = Stream()
        result << cls.get_version(mainnet)
        result << self.depth.to_bytes(1, 'big')
        result << self.parent_fingerprint
        if self.hardened:
            result << (self.index + cls.first_hardened_index).to_bytes(4, 'big')
        else:
            result << self.index.to_bytes(4, 'big')
        result << self.chaincode
        result << self._serialize_key()
        return result.serialize()
    
    def __str__(self):
        return 'version: {}\ndepth: {}\nparent fp: {}\n' \
               'index: {}\nchaincode: {}\nkey: {}\nhardened: {}'.format(self.__class__.get_version(),
                                                                        self.depth,
                                                                        self.parent_fingerprint,
                                                                        self.index,
                                                                        self.chaincode,
                                                                        self.key,
                                                                        self.hardened)
    
    def __eq__(self, other):
        return all([self.key == other.key,
                    self.chaincode == other.chaincode,
                    self.depth == other.depth,
                    self.parent_fingerprint == other.parent_fingerprint,
                    self.index == other.index,
                    self.hardened == other.hardened])
        
        
class ExtendedPrivateKey(ExtendedKey):
    version_strings = None

    @staticmethod
    def get_version(mainnet=None):
        network = mainnet
        if mainnet is True:
            network = 'mainnet'
        if mainnet is False:
            network = 'testnet'
        if mainnet is None:
            network = net_name()
        return bytearray(NETWORKS[net_name()].private_key_version_strings[network])
    
    @staticmethod
    def decode_key(keydata):
        return PrivateKey(keydata[1:])
    
    def __init__(self, key, chaincode, depth, pfing, index, hardened=False):
        if not isinstance(key, PrivateKey):
            raise TypeError('ExtendedPrivateKey expects a PrivateKey')
        super().__init__(key, chaincode, depth, pfing, index, hardened)

    def __int__(self):
        return int.from_bytes(self.key.key, 'big')
    
    def get_child(self, index, hardened=False):
        left, right = self.get_hash(index, hardened)
        k = (int(self) + left) % self.__class__.curve_order
        if k == 0:
            raise ValueError('Got 0 as k')
        return ExtendedPrivateKey(PrivateKey(k.to_bytes(32, 'big')),
                                  right,
                                  self.depth + 1,
                                  self.get_fingerprint(),
                                  index,
                                  hardened)
        
    def get_fingerprint(self):
        return self.pub().get_fingerprint()
    
    def _serialize_key(self):
        return bytearray([0]) + self.key.serialize()
    
    def _serialized_public(self):
        return self.pub()._serialize_key()
    
    def pub(self):
        return ExtendedPublicKey(self.key.pub(),
                                 self.chaincode,
                                 self.depth,
                                 self.parent_fingerprint,
                                 self.index,
                                 self.hardened)
        

class ExtendedPublicKey(ExtendedKey):
    version_strings = None

    @staticmethod
    def get_version(mainnet=None):
        network = mainnet
        if mainnet is True:
            network = 'mainnet'
        if mainnet is False:
            network = 'testnet'
        if mainnet is None:
            network = net_name()
        return bytearray(NETWORKS[net_name()].public_key_version_strings[network])
    
    @staticmethod
    def decode_key(keydata):
        return PublicKey(keydata)
    
    def __init__(self, key, chaincode, depth, pfing, index, hardened=False):
        if not isinstance(key, PublicKey):
            raise TypeError('ExtendedPublicKey expects a PublicKey')
        super().__init__(key.compress(), chaincode, depth, pfing, index, hardened)

    def __int__(self):
        return int.from_bytes(self.key.key, 'big')
        
    def get_fingerprint(self):
        return self.key.hash()[:4]

    def get_child(self, index, hardened=False):
        left, right = self.get_hash(index, hardened)
        point = ((left * generator_secp256k1)
                 + VerifyingKey.from_string(self.key.uncompressed[1:], curve=SECP256k1).pubkey.point)
        if point == INFINITY:
            raise ValueError('Computed point equals INFINITY')
        return ExtendedPublicKey(PublicKey.from_point(point), right, self.depth+1, self.get_fingerprint(), index, False)
    
    def get_hash(self, index, hardened=False):
        if hardened:
            raise ValueError('Trying to generate hardened child from public key')
        return super().get_hash(index, hardened)
    
    def _serialized_public(self):
        return self._serialize_key()
    
    def _serialize_key(self):
        return self.key.compressed
    
    def __lt__(self, other):
        return self.key < other.key
