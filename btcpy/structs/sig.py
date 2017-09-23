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

from enum import Enum
from abc import ABCMeta, abstractmethod

from ..lib.types import Immutable, HexSerializable
from .script import (Script, P2shScript, ScriptSig, P2pkhScript, P2wpkhV0Script, P2wshV0Script,
                     P2pkScript, MultisigScript, TimelockScript, RelativeTimelockScript,
                     IfElseScript, HashlockScript, StackData)
from ..lib.parsing import Stream


class Branch(Enum):
    ELSE = 0
    IF = 1


class Sighash(Immutable, HexSerializable):

    types = {'ALL': 0x01,
             'NONE': 0x02,
             'SINGLE': 0x03}

    def __init__(self, sighash, anyonecanpay=False):
        if sighash not in self.__class__.types:
            raise ValueError('Unknown sighash: {}'.format(sighash))
        object.__setattr__(self, 'sighash', sighash)
        object.__setattr__(self, 'anyone', anyonecanpay)

    def __eq__(self, string):
        return self.sighash == string

    def __int__(self):
        return self.__class__.types[self.sighash] | (0x80 if self.anyone else 0x00)

    def __str__(self):
        return '[{}{}]'.format(self.sighash, '|ANYONECANPAY' if self.anyone else '')

    def as_byte(self):
        return int(self).to_bytes(1, 'little')

    def serialize(self):
        return int(self).to_bytes(4, 'little')


class Solver(metaclass=ABCMeta):
    
    @abstractmethod
    def solve(self, digest):
        raise NotImplemented

    @abstractmethod
    def get_sighashes(self):
        raise NotImplemented
    
    @abstractmethod
    def solves_segwit(self):
        raise NotImplemented
    
    def has_prev_script(self):
        return False
    
    
class SingleSigSolver(Solver, metaclass=ABCMeta):

    def __init__(self, sighash=Sighash('ALL')):
        self.sighash = sighash
    
    def get_sighashes(self):
        return [self.sighash]

    def solves_segwit(self):
        return False
    

class SegWitSolver(Solver, metaclass=ABCMeta):
    
    def solves_segwit(self):
        return True
    

class P2pkhSolver(SingleSigSolver):
    
    def __init__(self, privk, sighash=Sighash('ALL')):
        super().__init__(sighash)
        self.privk = privk
        
    def solve(self, digest):
        from .transaction import Witness
        pubkey = self.privk.pub()
        sig = self.privk.sign(digest)
        return (ScriptSig.from_stack_data([StackData.from_bytes(sig + self.sighash.as_byte()),
                                           StackData.from_bytes(pubkey.compressed)]),
                Witness([]))
        
        
class P2wpkhV0Solver(SegWitSolver, P2pkhSolver):
    
    def solve(self, digest):
        script_sig, witness = super().solve(digest)
        return witness.to_script_sig(), script_sig.to_witness()


class P2pkSolver(SingleSigSolver):
    
    def __init__(self, privk, sighash=Sighash('ALL')):
        super().__init__(sighash)
        self.privk = privk
        
    def solve(self, digest):
        from .transaction import Witness
        sig = self.privk.sign(digest)
        return (ScriptSig.from_stack_data([StackData.from_bytes(sig + self.sighash.as_byte())]),
                Witness([]))


class P2shSolver(Solver):
    
    def __init__(self, redeem_script, redeem_script_solver):
        self.redeem_script = redeem_script
        self.redeem_script_solver = redeem_script_solver
    
    def solve(self, *digests):
        script_sig, witness = self.redeem_script_solver.solve(*digests)
        script_sig_data = script_sig.get_data()
        script_sig_data.append(self.redeem_script.to_stack_data())
        return ScriptSig.from_stack_data(script_sig_data), witness
    
    def get_sighashes(self):
        return self.redeem_script_solver.get_sighashes()

    def solves_segwit(self):
        return self.redeem_script_solver.solves_segwit()
    
    def get_prev_script(self):
        if self.redeem_script_solver.has_prev_script():
            return self.redeem_script_solver.get_prev_script()
        else:
            return self.redeem_script
    
    def has_prev_script(self):
        return True


class P2wshV0Solver(SegWitSolver):
    
    def __init__(self, witness_script, witness_script_solver):
        self.witness_script = witness_script
        self.witness_script_solver = witness_script_solver

    def solve(self, *digests):
        from .transaction import Witness
        script_sig, witness = self.witness_script_solver.solve(*digests)
        return (ScriptSig.empty(),
                (script_sig.to_witness()
                 + witness
                 + Witness([self.get_prev_script().to_stack_data()])))
    
    def get_sighashes(self):
        return self.witness_script_solver.get_sighashes()
    
    def get_prev_script(self):
        return self.witness_script
    
    def has_prev_script(self):
        return True


class MultisigSolver(Solver):
    
    def __init__(self, *privkeys, sighashes=None):
        if sighashes is None:
            sighashes = [Sighash('ALL') for _ in privkeys]
        if len(sighashes) != len(privkeys):
            raise ValueError('{} privkeys provided and {} sighashes'.format(len(privkeys), len(sighashes)))
        self.privkeys = privkeys
        self.sighashes = sighashes
        
    def solve(self, *digests):
        from .transaction import Witness
        if len(digests) != len(self.privkeys):
            raise ValueError('{} privkeys provided and {} digests'.format(len(self.privkeys), len(digests)))
        script_sig_data = [StackData.zero()]
        for priv, digest, sighash in zip(self.privkeys, digests, self.sighashes):
            sig = priv.sign(digest)
            script_sig_data.append(StackData.from_bytes(sig + sighash.as_byte()))
        return ScriptSig.from_stack_data(script_sig_data), Witness([])
    
    def get_sighashes(self):
        return self.sighashes

    def solves_segwit(self):
        return False
        

class IfElseSolver(Solver):
    
    def __init__(self, branch, inner_solver):
        self.branch = branch
        self.inner_solver = inner_solver
        
    def solve(self, *digests):
        script_sig, witness = self.inner_solver.solve(*digests)
        script_sig_data = script_sig.get_data()
        script_sig_data.append(StackData.from_int(self.branch.value))
        return ScriptSig.from_stack_data(script_sig_data), witness
    
    def get_sighashes(self):
        return self.inner_solver.get_sighashes()

    def solves_segwit(self):
        return self.inner_solver.solves_segwit()


class TimelockSolver(Solver):
    
    def __init__(self, inner_solver):
        self.inner_solver = inner_solver
        
    def solve(self, *digests):
        return self.inner_solver.solve(*digests)
    
    def get_sighashes(self):
        return self.inner_solver.get_sighashes()

    def solves_segwit(self):
        return self.inner_solver.solves_segwit()
    
    
class HashlockSolver(Solver):
    
    def __init__(self, preimage, inner_solver):
        self.preimage = preimage
        self.inner_solver = inner_solver
        
    def solve(self, *digests):
        script_sig, witness = self.inner_solver.solve(*digests)
        script_sig_data = script_sig.get_data()
        script_sig_data.append(StackData.from_bytes(self.preimage))
        return ScriptSig.from_stack_data(script_sig_data), witness
        
    def get_sighashes(self):
        return self.inner_solver.get_sighashes()

    def solves_segwit(self):
        return self.inner_solver.solves_segwit()
