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

from binascii import hexlify, unhexlify
from hashlib import sha256
import hashlib

from .types import Serializable, HexSerializable
from .opcodes import OpCodeConverter


class IncompleteParsingException(ValueError):
    pass


class Parser(object):
    @staticmethod
    def to_varint(integer):
        if 0 <= integer < 0xfd:
            prefix, size = bytearray(), 1
        elif 0xfd <= integer <= 0xffff:
            prefix, size = bytearray([0xfd]), 2
        elif 0xffff <= integer <= 0xffffffff:
            prefix, size = bytearray([0xfe]), 4
        elif 0xffffffff <= integer <= 0xffffffffffffffff:
            prefix, size = bytearray([0xff]), 8
        else:
            raise ValueError('Wrong value for varint: {}'.format(integer))
        return prefix + bytearray(integer.to_bytes(size, 'little'))

    @staticmethod
    def from_hex(hexa):
        return Parser(unhexlify(hexa))

    def __init__(self, bytes_):
        self._string = bytes_
        self.pointer = 0

    def __rshift__(self, bytes_) -> bytearray:
        """
        Moves the parser forward of `bytes_` bytes. This consumes the first
        `bytes_` bytes of the string, and returns them
        :param bytes_: number of bytes to shift the pointer
        :return: part of the string consumed
        """
        if self.pointer == len(self._string):
            raise StopIteration('Trying to shift empty string')

        result = self._string[self.pointer:self.pointer + bytes_]
        if len(result) != bytes_:
            raise StopIteration('Not enough bytes available')

        self.pointer += bytes_

        return result

    def __lshift__(self, bytes_) -> bytearray:
        if len(self._string) == 0:
            raise StopIteration("Trying to shift the empty string")
        if self.pointer - bytes_ < 0:
            raise StopIteration("Trying to lshift before the beginning of the string")
        self.pointer -= bytes_

        result = self._string[self.pointer:self.pointer + bytes_]
        return result

    def __bool__(self):
        return self.pointer < len(self._string)

    def __next__(self):
        return (self >> 1)[0]

    def __iter__(self):
        return self

    def __len__(self):
        return len(self._string) - self.pointer

    def __getitem__(self, item):
        return self._string[item + self.pointer]

    def parse_varint(self):
        header = next(self)
        if header == 0xfd:
            result = self >> 2
        elif header == 0xfe:
            result = self >> 4
        elif header == 0xff:
            result = self >> 8
        else:
            return header
        return int.from_bytes(result, 'little')


class BlockHeaderParser(Parser):
    def __init__(self, bytes_):
        super().__init__(bytes_)

    def get_version(self):
        return int.from_bytes(self >> 4, 'little')

    def get_prev_block_hash(self):
        return hexlify((self >> 32)[::-1]).decode()

    def get_merkle_root(self):
        return hexlify((self >> 32)[::-1]).decode()

    def get_block_timestamp(self):
        return int.from_bytes(self >> 4, 'little')

    def get_bits(self):
        return hexlify((self >> 4)[::-1]).decode()

    def get_block_nonce(self):
        return int.from_bytes(self >> 4, 'little')

    def get_block_header(self):
        from ..structs.block import BlockHeader
        version = self.get_version()
        prev_block_hash = self.get_prev_block_hash()
        merkle_root = self.get_merkle_root()
        block_timestamp = self.get_block_timestamp()
        bits = self.get_bits()
        block_nonce = self.get_block_nonce()
        return BlockHeader(version, prev_block_hash, merkle_root, block_timestamp, bits, block_nonce)


class BlockParser(BlockHeaderParser):
    def get_txn_count(self):

        return self.parse_varint()

    def get_txns(self):

        txn_count = self.get_txn_count()
        counter = 0
        txns_parser = TransactionParser(self >> len(self))
        txns = []
        for i in range(txn_count):
            txns.append(txns_parser.get_next_tx())
            counter += 1
        if len(txns_parser) != 0:
            raise IncompleteParsingException("Incomplete Block parsing, leftover data...")
        return txns


class TransactionParser(Parser):
    def __init__(self, bytes_):
        super().__init__(bytes_)
        self.segwit = False
        self.txins = 0

    def _version(self):
        return int.from_bytes(self >> 4, 'little')

    def _txin_data(self):
        from ..structs.script import ScriptSig, CoinBaseScriptSig
        from ..structs.transaction import Sequence
        txout_hash = hexlify((self >> 32)[::-1]).decode()
        txout_index = int.from_bytes(self >> 4, 'little')

        if txout_hash == '0' * 64 and txout_index == 0xffffffff:
            script = CoinBaseScriptSig(self >> self.parse_varint())
        else:
            script = ScriptSig(self >> self.parse_varint())
        sequence = Sequence(int.from_bytes(self >> 4, 'little'))
        return txout_hash, txout_index, script, sequence

    def _txins_data(self):
        """
        :return: a couple (segwit, txins) where `segwit` is a boolean
        telling whether the transaction has a segwit format
        """
        ntxins = self.parse_varint()
        if ntxins == 0:
            self.segwit = True
            flag = next(self)
            if flag != 1:
                raise ValueError('Wrong flag in SegWit transaction: {}'.format(flag))
            ntxins = self.parse_varint()
        else:
            self.segwit = False
        self.txins = ntxins
        return self.segwit, [self._txin_data() for _ in range(ntxins)]

    def _txout(self, n):
        from ..structs.script import ScriptBuilder
        from ..structs.transaction import TxOut
        value = int.from_bytes(self >> 8, 'little')
        script = ScriptBuilder.identify(self >> self.parse_varint())
        return TxOut(value, n, script)

    def _txouts(self):
        return [self._txout(i) for i in range(self.parse_varint())]

    def _witness(self):
        from ..structs.script import StackData
        if self.segwit:
            witnesses = []
            for _ in range(self.txins):
                witnesses.append(
                    [StackData.from_bytes(self >> self.parse_varint()) for _ in range(self.parse_varint())])
            return witnesses
        raise ValueError('Trying to get witness on a non-segwit transaction')

    def _locktime(self):
        from ..structs.transaction import Locktime
        return Locktime(int.from_bytes(self >> 4, 'little'))

    def get_next_tx(self, mutable=False):
        from ..structs.script import CoinBaseScriptSig
        from ..structs.transaction import (CoinBaseTxIn, Witness, TxIn, SegWitTransaction, Transaction)

        version = self._version()
        # print('version: {}'.format(version))
        segwit, txins_data = self._txins_data()
        # print('txins_data: {}'.format(txins_data))
        txouts = self._txouts()
        # print('txouts: {}'.format(txouts))
        if segwit:
            witness = self._witness()
            # print('witness: {}'.format([item.hexlify() for w in witness for item in w]))
            txins = [CoinBaseTxIn(*txin_data[2:], witness=Witness(wit))
                     if isinstance(txin_data[2], CoinBaseScriptSig)
                     else TxIn(*txin_data, witness=Witness(wit))
                     for txin_data, wit in zip(txins_data, witness)]
        else:
            txins = [CoinBaseTxIn(*txin_data[2:])
                     if isinstance(txin_data[2], CoinBaseScriptSig)
                     else TxIn(*txin_data)
                     for txin_data in txins_data]

        locktime = self._locktime()
        # print('locktime: {}'.format(locktime))

        if len(txins) > 1 and isinstance(txins[0], CoinBaseTxIn):
            raise ValueError('Transaction looks like coinbase but has more than one txin')

        if segwit:
            result = SegWitTransaction(version, txins, txouts, locktime)
        else:
            result = Transaction(version, txins, txouts, locktime)
        return result.to_mutable() if mutable else result


class UnexpectedOperationFound(Exception):
    pass


class ScriptParser(Parser):
    def match(self, template, end=True):
        ops = iter(template.split(' '))
        pushes = []
        for op in ops:
            if OpCodeConverter.exists(op):
                self.require(op)
            elif '<' in op and '>' in op:  # push operation
                # print('Trying to match push template: {}'.format(op))
                if op[-1] == '*':
                    pushes += self.require_pushes(zero=True)
                elif op[-1] == '+':
                    # print('Non-zero push ops')
                    pushes += self.require_pushes(zero=False)
                elif op[-1] == '>':
                    pushes.append(self.require_push(op[1:-1]))
                else:
                    raise ValueError('Could not parse push requirement: {}'.format(op))
            else:
                ValueError('Could not understand template')
        if end:
            self.require_empty()
        return pushes

    def push_until(self, op, zero=False):
        pushes = self.require_pushes(zero)
        self.require(op)
        return pushes

    def require_pushes(self, zero=False):
        pushes = []
        next_op = None
        try:
            while True:
                next_op = next(self)
                # print('Parsing op: {}'.format(next_op))
                pushes.append(self.get_push(next_op))
        except UnexpectedOperationFound:
            # could not push, probably not a push operation, let's restore the buffer to the previous character
            self << 1
        except StopIteration:
            # we reached the end of the buffer
            pass
        finally:
            if not zero and len(pushes) == 0:
                raise UnexpectedOperationFound('Found zero pushes, though more than zero required')
            return pushes

    def require_push(self, constraint):
        try:
            push_data = self.get_push()
        except StopIteration:
            raise UnexpectedOperationFound('Empty push where push was required')
        validator = PushValidator(constraint)
        if not validator.check(push_data):
            raise UnexpectedOperationFound('Push operation did not pass validation constraints: {} '
                                           'with data: {}'.format(constraint, push_data.hexlify()))
        return push_data

    def require(self, op):
        from ..structs.script import Script
        try:
            next_op = next(self)
        except StopIteration:
            raise UnexpectedOperationFound('No further operation: parser reached end of script')
        if next_op != OpCodeConverter.to_int(op):
            raise UnexpectedOperationFound('{} not found, found {} instead'.format(op, next_op))

    def require_empty(self):
        if self:
            raise UnexpectedOperationFound('Unexpected operations left after template match')

    def get_push(self, curr_op=None):
        from ..structs.script import StackData
        try:
            if curr_op is None:
                curr_op = next(self)
        except StopIteration:
            raise
        return StackData.from_push_op(self, curr_op)


class PushValidator(object):
    sep = '|'
    range_sep = '-'

    def check(self, pushdata):
        for const in self.constraints:
            if PushValidator.range_sep in const:
                minimum, maximum = const.split(PushValidator.range_sep)
                if len(pushdata) in range(int(minimum), int(maximum) + 1):
                    return True
            elif not const or len(pushdata) == int(const):
                return True
        return False

    def __init__(self, string):
        if PushValidator.sep in string:
            self.constraints = string.split(PushValidator.sep)
        else:
            self.constraints = [string]


class Stream(HexSerializable):
    @staticmethod
    def unhexlify(hex_string):
        return Stream(bytearray(unhexlify(hex_string)))

    def __init__(self, initial=None):
        if initial is None:
            initial = bytearray()
        self.body = bytearray()
        self << initial

    def __lshift__(self, other):
        if isinstance(other, Serializable):
            self.body += other.serialize()
        elif isinstance(other, (bytes, bytearray)):
            self.body += other
        elif isinstance(other, int):
            self.body.append(other)
        else:
            raise ValueError('Cannot insert {} in stream'.format(type(other)))
        return self

    def __add__(self, other):
        new = Stream(self.body)
        new << other
        return new

    def __bool__(self):
        return bool(self.body)

    def sha256(self):
        return bytearray(sha256(self.body).digest())

    def ripemd(self):
        ripe = hashlib.new('ripemd160')
        ripe.update(self.body)
        return bytearray(ripe.digest())

    def hash256(self):
        return bytearray(sha256(sha256(self.body).digest()).digest())

    def hash160(self):
        sha = sha256(self.body).digest()
        ripe = hashlib.new('ripemd160')
        ripe.update(sha)
        return bytearray(ripe.digest())

    def serialize(self):
        return self.body
