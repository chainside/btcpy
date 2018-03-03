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


from binascii import unhexlify, hexlify

from ..lib.parsing import BlockParser, BlockHeaderParser, Parser
from ..lib.types import Immutable, Jsonizable, HexSerializable, cached


# from .transaction import Transaction
# noinspection PyUnresolvedReferences
class Block(Immutable, Jsonizable, HexSerializable):

    max_difficulty = 0xffff0000000000000000000000000000000000000000000000000000

    def __init__(self, header, txns):
        object.__setattr__(self, 'header', header)
        object.__setattr__(self, 'txns', txns)

    @staticmethod
    def unhexlify(string):
        return Block.deserialize(bytearray(unhexlify(string)))

    @staticmethod
    def deserialize(string):
        parser = BlockParser(string)
        header = parser.get_block_header()
        txns = parser.get_txns()
        return Block(header, txns)

    @cached
    def serialize(self):
        txns_arr = bytearray()
        for tx in self.txns:
            txns_arr += tx.serialize()
        return self.header.serialize() + Parser.to_varint(len(self.txns)) + txns_arr

    @cached
    def hash(self):
        from hashlib import sha256
        return hexlify(sha256(sha256(self.header.serialize()).digest()).digest()[::-1]).decode()

    @classmethod
    def from_json(cls, string):
        pass

    def to_json(self):
        return {
            'header': self.header.to_json(),
            'difficulty': self.bits_to_diff(),
            'hash': self.hash(),
            'txn_count': len(self.txns),
            'txns': {tx.txid for tx in self.txns}}

    def bits_to_diff(self):
        bits = self.header.bits
        n_size = int(bits, 16) >> 24
        current_target = int(bits, 16) & 0x007fffff
        if n_size <= 3:
            current_target >>= (8 * (3 - n_size))

        else:
            current_target <<= (8 * (n_size - 3))

        return Block.max_difficulty / current_target

    def __eq__(self, other):
        return self.hash() == other.hash()


# noinspection PyUnresolvedReferences
class BlockHeader(Immutable, Jsonizable, HexSerializable):

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce):
        object.__setattr__(self, 'version', version)
        object.__setattr__(self, 'prev_block', prev_block)
        object.__setattr__(self, 'merkle_root', merkle_root)
        object.__setattr__(self, 'timestamp', timestamp)
        object.__setattr__(self, 'bits', bits)
        object.__setattr__(self, 'nonce', nonce)

    @staticmethod
    def unhexlify(string):
        return BlockHeader.deserialize(bytearray(unhexlify(string)))

    @staticmethod
    def deserialize(string):
        parser = BlockHeaderParser(string)
        result = parser.get_block_header()
        return result

    @cached
    def serialize(self):
        version = bytearray(self.version.to_bytes(4, 'little'))
        prev_block = bytearray(unhexlify(self.prev_block)[::-1])
        merkle_root = bytearray(unhexlify(self.merkle_root)[::-1])
        timestamp = bytearray((self.timestamp.to_bytes(4, 'little')))
        bits = bytearray(unhexlify(self.bits)[::-1])
        nonce = bytearray(self.nonce.to_bytes(4, 'little'))
        return version + prev_block + merkle_root + timestamp + bits + nonce

    @classmethod
    def from_json(cls, string):
        pass

    def to_json(self):
        return {
            'version': self.version,
            'prev_block': self.prev_block,
            'merkle_root': self.merkle_root,
            'timestamp': self.timestamp,
            'bits': self.bits,
            'nonce': self.nonce}
