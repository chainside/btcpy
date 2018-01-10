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
from decimal import Decimal

from .sig import Sighash
from .script import (ScriptBuilder, P2wpkhV0Script, P2wshV0Script, P2shScript, NulldataScript, ScriptSig, ScriptPubKey)
from ..lib.types import Immutable, Mutable, Jsonizable, HexSerializable, cached
from ..lib.parsing import Parser, TransactionParser, Stream


# noinspection PyUnresolvedReferences
class Sequence(Immutable, HexSerializable):

    disable_flag_position = 31
    type_flag_position = 22
    MAX = 0xffffffff

    @staticmethod
    def max():
        return Sequence(Sequence.MAX)

    @staticmethod
    def create(seq, blocks=True, disable=False):
        if seq > 0xffff:
            raise ValueError('Sequence value too high: {}'.format(seq))
        flags = 0
        if not blocks:
            flags |= 1 << Sequence.type_flag_position
        if disable:
            flags |= 1 << Sequence.disable_flag_position
        return flags + seq

    def __init__(self, seq):
        object.__setattr__(self, 'seq', seq)

    @property
    def n(self):
        return self.seq & 0xffff

    def __str__(self):
        return str(self.seq)

    def __repr__(self):
        return 'Sequence({})'.format(self.seq)

    def is_active(self):
        return not (self.seq & (1 << Sequence.disable_flag_position))

    def is_time(self):
        return bool(self.seq & (1 << Sequence.type_flag_position))

    def is_blocks(self):
        return not self.is_time()

    def for_script(self):
        from .script import StackData
        return StackData.from_int(self.seq)

    @cached
    def serialize(self):
        return bytearray(self.seq.to_bytes(4, 'little'))


# noinspection PyUnresolvedReferences
class TxIn(Immutable, HexSerializable, Jsonizable):
    """
    :txid, the txid of the transaction being spent
    :txout, the output number of the output being spent
    :script_sig, a scriptSig
    :sequence, the sequence number of the TxIn
    """

    @classmethod
    def from_json(cls, dic):
        from .script import ScriptSig

        if 'coinbase' in dic:

            return CoinBaseTxIn(ScriptSig(bytearray(unhexlify(dic['coinbase']['hex']))), Sequence(int(dic['sequence'])))
        return cls(dic['txid'],
                   dic['vout'],
                   ScriptSig(bytearray(unhexlify(dic['scriptSig']['hex']))),
                   Sequence(int(dic['sequence'])))

    def __init__(self, txid: str, txout: int, script_sig: ScriptSig, sequence: Sequence, witness=None):
        object.__setattr__(self, 'txid', txid)
        object.__setattr__(self, 'txout', txout)
        object.__setattr__(self, 'script_sig', script_sig)
        object.__setattr__(self, 'sequence', sequence)
        object.__setattr__(self, 'witness', witness)

    def to_json(self):
        result = {'txid': self.txid,
                  'vout': self.txout,
                  'scriptSig': self.script_sig.to_json()}

        if self.witness is not None:
            result['txinwitness'] = self.witness.to_json()
        result['sequence'] = str(self.sequence)
        return result

    @cached
    def serialize(self):
        result = Stream()
        result << unhexlify(self.txid)[::-1]
        result << self.txout.to_bytes(4, 'little')
        result << Parser.to_varint(len(self.script_sig))
        result << self.script_sig
        result << self.sequence
        return result.serialize()

    def is_replaceable(self):
        return self.sequence.seq < (0xffffffff - 1)

    def is_standard(self, prev_script=None):

        if not self.script_sig.is_standard(isinstance(prev_script, P2shScript)):
            return False

        if prev_script is not None and not prev_script.is_standard():
            return False

        if isinstance(prev_script, P2shScript):
            sig_data = self.script_sig.get_data()
            if not sig_data:
                return False
            prev_script = ScriptBuilder.identify(sig_data[-1].data)

        if isinstance(prev_script, (P2wshV0Script, P2wpkhV0Script)):
            if self.witness is None:
                return False
            return self.witness.is_standard(p2wsh=isinstance(prev_script, P2wshV0Script))

        return True

    def __str__(self):
        return 'TxIn(txid={}, txout={}, script_sig={}, sequence={}, witness={})'.format(self.txid,
                                                                                        self.txout,
                                                                                        self.script_sig,
                                                                                        self.sequence,
                                                                                        self.witness)

    def to_mutable(self):
        return MutableTxIn(self.txid, self.txout, self.script_sig, self.sequence, self.witness)


# noinspection PyUnresolvedReferences
class MutableTxIn(Mutable, TxIn):

    def to_immutable(self):
        return TxIn(self.txid, self.txout, self.script_sig, self.sequence, self.witness)


# noinspection PyUnresolvedReferences
class CoinBaseTxIn(TxIn):

    sentinel_txid = '0' * 64
    sentinel_txout = 0xffffffff

    def __init__(self, script_sig, sequence, witness=None):
        super().__init__(CoinBaseTxIn.sentinel_txid, CoinBaseTxIn.sentinel_txout, script_sig, sequence, witness)

    def to_json(self):
        return {'coinbase': self.script_sig.to_json(),
                'sequence': str(self.sequence)}

    def is_standard(self, *args, **kwargs):
        return True


# noinspection PyUnresolvedReferences
class TxOut(Immutable, HexSerializable, Jsonizable):

    @classmethod
    def from_json(cls, dic):
        return cls(int(Decimal(dic['value']) * Decimal('1e8')),
                   dic['n'],
                   ScriptBuilder.identify(bytearray(unhexlify(dic['scriptPubKey']['hex']))))

    def __init__(self, value: int, n: int, script_pubkey: ScriptPubKey):
        object.__setattr__(self, 'value', value)
        object.__setattr__(self, 'n', n)
        object.__setattr__(self, 'script_pubkey', script_pubkey)

    @property
    def type(self):
        return self.script_pubkey.type

    @property
    def req_sigs(self):
        return self.script_pubkey.req_sigs

    def is_standard(self):
        return self.script_pubkey.is_standard()

    def get_sig(self):
        pass

    def to_json(self):
        return {'value': str(Decimal(self.value) * Decimal('1e-8')),
                'n': self.n,
                'scriptPubKey': self.script_pubkey.to_json()}

    @cached
    def serialize(self):
        result = Stream()
        result << self.value.to_bytes(8, 'little')
        result << Parser.to_varint(len(self.script_pubkey))
        result << self.script_pubkey
        return result.serialize()

    def is_dust(self, size_to_relay_fee):
        return self.value < self.get_dust_threshold(size_to_relay_fee)

    def get_dust_threshold(self, size_to_relay_fee):

        if isinstance(self.script_pubkey, NulldataScript):
            return 0

        size = len(self.serialize())

        if isinstance(self.script_pubkey, (P2wpkhV0Script, P2wshV0Script)):
            # sum the sizes of the parts of a transaction input
            # with 75 % segwit discount applied to the script size.
            size += (32 + 4 + 1 + (107 // Witness.scale_factor) + 4)
        else:
            size += (32 + 4 + 1 + 107 + 4)

        return 3 * size_to_relay_fee(size)

    def __str__(self):
        return "TxOut(value={}, n={}, scriptPubKey='{}')".format(self.value, self.n, self.script_pubkey)


# noinspection PyUnresolvedReferences
class Locktime(Immutable, HexSerializable):

    blocks_threshold = 500000000

    def __init__(self, n):
        object.__setattr__(self, 'n', n)

    def __str__(self):
        return 'Locktime({})'.format(self.n)

    def is_blocks(self):
        return 0 < self.n < Locktime.blocks_threshold

    def is_time(self):
        return self.n >= Locktime.blocks_threshold

    def is_active(self):
        return self.n > 0

    def to_json(self):
        pass

    def for_script(self):
        from .script import StackData
        return StackData.from_int(self.n)

    @cached
    def serialize(self):
        return bytearray(self.n.to_bytes(4, 'little'))


# noinspection PyUnresolvedReferences
class Witness(Immutable, HexSerializable, Jsonizable):

    scale_factor = 4
    max_redeem_script_size = 3600
    max_p2sh_push_ops = 100
    max_single_push_size = 80

    @classmethod
    def from_json(cls, string):
        pass

    def __init__(self, stack_items):
        object.__setattr__(self, 'items', stack_items)

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        yield from self.items

    def __add__(self, other):
        return Witness(self.items + other.items)

    def to_json(self):
        return [str(item) for item in self.items]

    @cached
    def serialize(self):
        result = Stream()
        result << Parser.to_varint(len(self.items))
        for item in self.items:
            result << item
        return result.serialize()

    def to_script_sig(self):
        from .script import ScriptSig
        return ScriptSig.from_stack_data(self.items)

    def is_standard(self, p2wsh=False):
        if p2wsh:
            if len(self.items[-1]) > Witness.max_redeem_script_size:
                return False
            if len(self.items) - 1 > Witness.max_p2sh_push_ops:
                return False
            for item in self.items[:-1]:
                if len(item) > Witness.max_single_push_size:
                    return False
        return True

    def __str__(self):
        return 'Witness([{}])'.format(', '.join('"{}"'.format(item) for item in self.items))


# noinspection PyUnresolvedReferences
class Transaction(Immutable, HexSerializable, Jsonizable):

    max_version = 2
    max_weight = 400000

    @classmethod
    def unhexlify(cls, string):
        return cls.deserialize(bytearray(unhexlify(string)))

    @classmethod
    def deserialize(cls, string):
        parser = TransactionParser(string)
        result = parser.get_next_tx(cls is MutableTransaction)
        if parser:
            raise ValueError('Leftover data after transaction')
        return result

    @classmethod
    def from_json(cls, tx_json):

        tx = cls(version=tx_json['version'],
                 locktime=Locktime(tx_json['locktime']),
                 txid=tx_json['txid'],
                 ins=[TxIn.from_json(txin_json) for txin_json in tx_json['vin']],
                 outs=[TxOut.from_json(txout_json) for txout_json in tx_json['vout']])

        return tx

    def __init__(self, version, ins, outs, locktime, txid=None):
        object.__setattr__(self, 'version', version)
        object.__setattr__(self, 'ins', tuple(ins))
        object.__setattr__(self, 'outs', tuple(outs))
        object.__setattr__(self, 'locktime', locktime)
        object.__setattr__(self, '_txid', txid)
        if txid != self.txid and txid is not None:
            raise ValueError('txid {} does not match transaction data {}'.format(txid, self.hexlify()))
        # if not self.ins or not self.outs:
        #     raise ValueError('Empty txin or txout array')
        # if len(self.serialize()) > Block.max_size:
        #     raise ValueError('Invalid transaction size: {}'.format(len(self.serialize())))

    def _base_size(self):
        return len(self.serialize())

    @cached
    def hash(self):
        stream = Stream()
        stream << self
        return hexlify(stream.hash256()[::-1]).decode()

    @property
    def txid(self):
        return self.hash()

    @property
    @cached
    def normalized_id(self):
        mutable = self.to_mutable()
        for txin in mutable.ins:
            txin.script_sig = ScriptSig.empty()
        return mutable.txid

    @property
    def size(self):
        return len(self.serialize())

    @property
    def weight(self):
        return self._base_size() * 3 + self.size

    @property
    def vsize(self):
        from math import ceil
        return ceil(self.weight / 4)

    def to_json(self):
        return {'hex': self.hexlify(),
                'txid': self.txid,
                'hash': self.hash(),
                'size': self.size,
                'vsize': self.vsize,
                'version': self.version,
                'locktime': self.locktime.n,
                'vin': [txin.to_json() for txin in self.ins],
                'vout': [txout.to_json() for txout in self.outs]}

    @cached
    def serialize(self):
        from itertools import chain
        result = Stream()
        result << self.version.to_bytes(4, 'little')
        result << Parser.to_varint(len(self.ins))
        # the most efficient way to flatten a list in python
        result << bytearray(chain.from_iterable(txin.serialize() for txin in self.ins))
        result << Parser.to_varint(len(self.outs))
        # the most efficient way to flatten a list in python
        result << bytearray(chain.from_iterable(txout.serialize() for txout in self.outs))
        result << self.locktime
        return result.serialize()

    def is_replaceable(self):
        return any(txin.is_replaceable() for txin in self.ins)

    def is_standard(self, size_to_relay_fee, prev_scripts=None):

        if len(prev_scripts) != len(self.ins):
            raise ValueError('Prev scripts provided are a different number than txins')

        if not 1 <= self.version <= Transaction.max_version:
            return False

        if self.weight > Transaction.max_weight:
            return False

        for prev, txin in zip(prev_scripts, self.ins):
            if not txin.is_standard(prev):
                return False

        nulldata = 0
        for out in self.outs:
            if not out.script_pubkey.is_standard():
                return False
            if isinstance(out.script_pubkey, NulldataScript):
                nulldata += 1
                if nulldata > 1:
                    return False
                if out.is_dust(size_to_relay_fee):
                    return False

        return True

    def is_coinbase(self):
        return len(self.ins) == 1 and isinstance(self.ins[0], CoinBaseTxIn)

    def to_mutable(self):
        return MutableTransaction(self.version, [txin.to_mutable() for txin in self.ins], self.outs, self.locktime)

    def get_digest_preimage(self, index, prev_script, sighash=Sighash('ALL')):

        # TODO: manage codeseparator

        # print([str(inp) for inp in self.ins])
        # print([str(out) for out in self.outs])
        # print('Computing digest for input {}...'.format(index))
        throwaway = self.to_mutable()
        for i in range(len(throwaway.ins)):
            # we are signing input i so we create
            # empty scriptsig for every txin unless i == j
            throwaway.ins[i].script_sig = ScriptSig.empty()
            if i == index:
                throwaway.ins[i].script_sig = prev_script

        if sighash in ('NONE', 'SINGLE'):

            if sighash == 'NONE':
                throwaway.outs = []

            elif sighash == 'SINGLE':
                if index >= len(throwaway.outs):
                    raise ValueError('TxIn index greater than number of outputs and SIGHASH_SINGLE was chosen!')
                matching_out = throwaway.outs[index]
                throwaway.outs = [TxOut(0xffffffffffffffff, i, ScriptPubKey.empty()) for i in range(index)]
                throwaway.outs.append(matching_out)

            # so that others can replace
            for i in range(len(throwaway.ins)):
                if i != index:
                    throwaway.ins[i].sequence = Sequence(0)

        if sighash.anyone:
            # remove all other inputs completely
            throwaway.ins = [throwaway.ins[index]]

        to_hash = Stream()
        to_hash << throwaway
        to_hash << sighash

        # print('SIGHASH: {}'.format(spend.sighash))
        # print(self)

        return to_hash

    def get_digest(self, txin, prev_script, sighash=Sighash('ALL')):
        return self.get_digest_preimage(txin, prev_script, sighash).hash256()

    def __str__(self):
        return ('Transaction(version={}, '
                'ins=[{}], '
                'outs=[{}], '
                'locktime={})'.format(self.version,
                                      ', '.join(str(txin) for txin in self.ins),
                                      ', '.join(str(out) for out in self.outs),
                                      self.locktime))


class MutableTransaction(Mutable, Transaction):

    def __init__(self, version, ins, outs, locktime):
        super().__init__(version, ins, outs, locktime)
        ins = []
        for txin in self.ins:
            if isinstance(txin, MutableTxIn):
                ins.append(txin)
            elif isinstance(txin, TxIn):
                ins.append(txin.to_mutable())
            else:
                raise ValueError('Expected objects of type `TxIn` or `MutableTxIn`, got {} instead'.format(type(txin)))
        self.ins = ins
        self.outs = list(self.outs)

    def to_immutable(self):
        return Transaction(self.version, [txin.to_immutable() for txin in self.ins], self.outs, self.locktime)

    def to_segwit(self):
        return MutableSegWitTransaction(self.version, self.ins, self.outs, self.locktime)

    def spend_single(self, index, txout, solver):

        sighashes = solver.get_sighashes()
        prev_script = solver.get_prev_script() if solver.has_prev_script() else txout.script_pubkey

        if len(sighashes) == 0:
            script_sig, witness = solver.solve()
        elif len(sighashes) == 1:
            script_sig, witness = solver.solve(self.get_digest(index, prev_script, sighashes[0]))
        else:
            digests = []
            for sighash in sighashes:
                digests.append(self.get_digest(index, prev_script, sighash))
            script_sig, witness = solver.solve(*digests)

        if witness:
            raise ValueError('Trying to spend segwit output with non-segwit transaction!')

        self.ins[index].script_sig = script_sig

    def spend(self, txouts, solvers):
        if any(solver.solves_segwit() for solver in solvers):
            return self.to_segwit().spend(txouts, solvers)
        if len(solvers) != len(self.ins) or len(txouts) != len(solvers):
            raise ValueError('{} solvers and {} txouts provided for {} inputs'.format(len(solvers),
                                                                                      len(txouts),
                                                                                      len(self.ins)))
        for i, (txout, solver) in enumerate(zip(txouts, solvers)):
            self.spend_single(i, txout, solver)

        return self.to_immutable()


class SegWitTransaction(Immutable, HexSerializable, Jsonizable):

    marker = 0x00
    flag = 0x01
    byte_marker = bytearray([marker])
    byte_flag = bytearray([flag])

    @staticmethod
    def unhexlify(string):
        tx = Transaction.unhexlify(string)
        return SegWitTransaction(tx.version, tx.ins, tx.outs, tx.locktime)

    @staticmethod
    def from_json(string):
        tx = Transaction.from_json(string)
        return SegWitTransaction(tx.version, tx.ins, tx.outs, tx.locktime)

    def __init__(self, version, ins, outs, locktime, txid=None):
        object.__setattr__(self, 'transaction', Transaction(version, ins, outs, locktime, txid))

    def __getattr__(self, item):
        return getattr(self.transaction, item)

    @cached
    def serialize(self):
        from itertools import chain
        classic = self.transaction.serialize()
        version, middle, locktime = classic[:4], classic[4:-4], classic[-4:]
        witness = bytearray(chain.from_iterable(txin.witness.serialize() for txin in self.ins))
        return version + self.__class__.byte_marker + self.__class__.byte_flag + middle + witness + locktime

    @property
    def normalized_id(self):
        return self.txid

    @cached
    def hash(self):
        stream = Stream()
        stream << self
        return hexlify(stream.hash256()[::-1]).decode()

    def hexlify(self):
        return super().hexlify()

    def to_mutable(self):
        return MutableSegWitTransaction(self.version,
                                        [txin.to_mutable() for txin in self.ins],
                                        self.outs,
                                        self.locktime)

    def get_digest(self, index, prev_script, sighash=Sighash('ALL')):
        return self.transaction.get_digest(index, prev_script, sighash)

    def get_segwit_digest(self, index, prev_script, prev_amount, sighash=Sighash('ALL')):
        return self._get_segwit_digest_preimage(index, prev_script, prev_amount, sighash).hash256()

    def _get_segwit_digest_preimage(self, index, prev_script, prev_amount, sighash=Sighash('ALL')):

        # TODO reinsert partial caching to avoid quadratic hashing

        hash_prevouts = bytearray([0] * 32)
        hash_sequence = bytearray([0] * 32)
        hash_outputs = bytearray([0] * 32)

        if not sighash.anyone:
            # if cache['hash_prevouts'] is None:
            # cache['hash_prevouts'] = self._hash_prevouts()
            # hash_prevouts = cache['hash_prevouts']
            hash_prevouts = self._hash_prevouts()

        if not sighash.anyone and (sighash not in ('SINGLE', 'NONE')):
            # if cache['hash_sequence'] is None:
            #     cache['hash_sequence'] = self._hash_sequence()
            # hash_sequence = cache['hash_sequence']
            hash_sequence = self._hash_sequence()

        if sighash not in ('SINGLE', 'NONE'):
            # if cache['hash_outputs'] is None:
            #     cache['hash_outputs'] = self._hash_outputs()
            # hash_outputs = cache['hash_outputs']
            hash_outputs = self._hash_outputs()
        elif sighash == 'SINGLE' and index < len(self.outs):
            hash_outputs = (Stream() << self.outs[index]).hash256()

        if isinstance(prev_script, P2wpkhV0Script):
            script_code = prev_script.get_scriptcode()
        else:
            script_code = prev_script.to_stack_data()

        curr_in = self.ins[index]

        result = Stream()

        result << self.version.to_bytes(4, 'little')
        result << hash_prevouts
        result << hash_sequence
        result << unhexlify(curr_in.txid)[::-1]
        result << curr_in.txout.to_bytes(4, 'little')
        result << script_code
        result << prev_amount.to_bytes(8, 'little')
        result << curr_in.sequence
        result << hash_outputs
        result << self.locktime
        result << sighash

        # print('Version: {}'.format(hexlify(self.version.to_bytes(4, 'little'))))
        # print('Hash prevouts: {}'.format(hexlify(hash_prevouts)))
        # print('Hash sequence: {}'.format(hexlify(hash_sequence)))
        # print('Outpoint txid: {}'.format(hexlify(unhexlify(curr_in.txid)[::-1])))
        # print('Outpoint vout: {}'.format(hexlify(curr_in.txout.to_bytes(4, 'little'))))
        # print('Script code: {}'.format(script_code.hexlify()))
        # print('Prev amount: {}'.format(hexlify(spend.prev_amount.to_bytes(8, 'little'))))
        # print('Sequence: {}'.format(curr_in.sequence.hexlify()))
        # print('Hash outputs: {}'.format(hexlify(hash_outputs)))
        # print('Locktime: {}'.format(self.locktime.hexlify()))
        # print('Sighash: {}'.format(spend.sighash.hexlify()))
        # print('Digest: {}'.format(hexlify(result.hash())))

        return result

    def _hash_prevouts(self):
        result = Stream()
        for txin in self.ins:
            result << unhexlify(txin.txid)[::-1]
            result << txin.txout.to_bytes(4, 'little')
        return result.hash256()

    def _hash_sequence(self):
        result = Stream()
        for txin in self.ins:
            result << txin.sequence
        return result.hash256()

    def _hash_outputs(self):
        result = Stream()
        for out in self.outs:
            result << out
        return result.hash256()

    # the following properties must be redefined,
    # it does not work if one calls them on the inner transaction
    # the only difference with what is defined in Transaction
    # is that here _base_size() extracts the inner transaction's base_size
    @property
    def size(self):
        return len(self.serialize())

    @property
    def weight(self):
        return self._base_size() * 3 + self.size

    @property
    def vsize(self):
        from math import ceil
        return ceil(self.weight / 4)

    def to_json(self):
        return {'hex': self.hexlify(),
                'txid': self.txid,
                'hash': self.hash(),
                'size': self.size,
                'vsize': self.vsize,
                'version': self.version,
                'locktime': self.locktime.n,
                'vin': [txin.to_json() for txin in self.ins],
                'vout': [txout.to_json() for txout in self.outs]}

    def __str__(self):
        return ('SegWitTransaction(version={}, '
                'ins=[{}], '
                'outs=[{}], '
                'locktime={})'.format(self.version,
                                      ', '.join(str(txin) for txin in self.ins),
                                      ', '.join(str(out) for out in self.outs),
                                      self.locktime))


class MutableSegWitTransaction(Mutable, SegWitTransaction):

    def __init__(self, version, ins, outs, locktime, txid=None):
        super().__init__(version, ins, outs, locktime, txid)
        ins = []
        for txin in self.ins:
            if isinstance(txin, MutableTxIn):
                ins.append(ins)
            elif isinstance(txin, TxIn):
                ins.append(txin.to_mutable())
            else:
                raise ValueError('Expected objects of type `TxIn` or `MutableTxIn`, got {} instead'.format(type(txin)))
        self.transaction = self.transaction.to_mutable()

    def to_immutable(self):
        return SegWitTransaction(self.version,
                                 [txin.to_immutable() for txin in self.ins],
                                 self.outs,
                                 self.locktime)

    def spend_single(self, index, txout, solver):

        sighashes = solver.get_sighashes()
        prev_script = solver.get_prev_script() if solver.has_prev_script() else txout.script_pubkey

        if len(sighashes) == 0:
            script_sig, witness = solver.solve()
        elif len(sighashes) == 1:
            if solver.solves_segwit():
                digest = self.get_segwit_digest(index, prev_script, txout.value, sighashes[0])
                script_sig, witness = solver.solve(digest)
            else:
                digest = self.get_digest(index, prev_script, sighashes[0])
                script_sig, witness = solver.solve(digest)

        else:
            digests = []
            if solver.solves_segwit():
                for sighash in sighashes:
                    digests.append(self.get_segwit_digest(index,
                                                          prev_script,
                                                          txout.value,
                                                          sighash))
            else:
                for sighash in sighashes:
                    digests.append(self.get_digest(index, prev_script, sighash))
            script_sig, witness = solver.solve(*digests)

        self.ins[index].script_sig = script_sig
        self.ins[index].witness = witness

    def spend(self, txouts, solvers):

        if len(solvers) != len(self.ins) or len(txouts) != len(solvers):
            raise ValueError('{} solvers, {} txouts provided for {} inputs'.format(len(solvers),
                                                                                   len(txouts),
                                                                                   len(self.ins)))

        for i, (txout, solver) in enumerate(zip(txouts, solvers)):
            self.spend_single(i, txout, solver)

        return self.to_immutable()

