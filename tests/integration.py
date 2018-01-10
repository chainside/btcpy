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


import sys
import copy
import unittest
from functools import partial
from argparse import ArgumentParser

from .regtest import Manager
from btcpy.structs.hd import ExtendedPrivateKey, ExtendedPublicKey
from btcpy.structs.transaction import Transaction, Sequence, TxOut, Locktime, TxIn, MutableTransaction, MutableTxIn
from btcpy.structs.sig import *
from btcpy.structs.script import *
from btcpy.setup import setup

setup('regtest')


keys = [('tpubDHVQPtNuLdRLj7FU348D5PcrkkPj5ibhN52cfjthEH9KTfwTaVmo'
         'dTn1Ekpge6PhUjW1noZ452xesirHgBKbzmY6hz4eoVXDwHcjczDT7zb',
         'tprv8koNFULfCFjfqeDg9QTcfyxkBisnvPQnnmRqPDrPp1LvdBggx6xD'
         'SyA94cjpAXS7ccGhsQ7w6q7Y9Ku31e1eTDztU49LVBz9B1sCDoeE6Jc'),
        ('tpubDEhdzhXujo86G6PXroPKQJSCJi8qbdQvrALhTNiExsGKfFHXtVbT'
         'E9tnLBCAP7nqQrqfUSVTCDuqv6RMHu8PDL5a8G43b5N2zKsF89nmLd6',
         'tprv8i1brHVfbRSRNdMjy9iiztn5jgcuSJE2GrjvArfwYbTvpm2mG6ms'
         '3fGvA5kdZ3qZ7KB26VehAudSCUURKT56Hej2pBgj26ZkNbdD1YMdTiD'),
        ('tpubDDqNYkcvEKbQJKtda5miuWCBWqX2Bd8qJWgSNbsiqfSHRzNpsjpX'
         'HAMiNYNHZw9FCnkuJpVAJjZkTeujhT4h293w6YMexGyAgNGRYWVtJ1D',
         'tprv8h9LQLag5wujQrrqgS78W6Y4wp162HwvjD5f65qRRPdtbW84FLzw'
         '6fjrCNeqEvsKqiDxLtzJ9oHUGVTL17KptjbDVqgJ2XvAs2LcvSWrTUh'),
        ('tpubDATAg7GX3FHknHSDzfVEgwo8U1aEWPNdkgRjs4dBF244x9xC6tRq'
         'UkM8ZMk8JNHnmQMqNG1evQBNKwt97G348FXaWjhT88UWbwqrBTpmwe3',
         'tprv8dm8XhEGtsc5tpQS71peHY91tz4JM4BjBNpxaYaspkFg7fhRUVcF'
         'JFjGPFHYGQLo21nmCrkjryoUFJKSKMUjKqpuRXAmMMhvMaP27UtqeLA'),
        ('tpubDHfgxSGzrfm7dWndtJ86CZPyoFNwkjB7dE2TNxp9BtwNcFq4oozW'
         '7bd5mCDzf1HBdXUofL1isdDA1LX7hAJmAx5Kp1grD85Q8UH5MCpuU51',
         'tprv8kyep2EkiJ5Sk3kqzeTVo9jsEDs1bPzD3vRg6Smqmd8ymmaJBRAu'
         'w71Db3Vuu8FThpRuLdoqhbvZZJ2zDNF7sNaJ6uB745RMESF5ezYNBAc'),
        ('tpubDExb5uGPg2pzURTo6aSQ1nf7eER9huQM96KmvbpY1AND3h12rfhV'
         'TEVeMQoT4Ljk22NQyTDt66eaJdjccT9JJZ8JGZQXq247b9SU7RjYCoP',
         'tprv8iGYwVE9Xf9KaxS1CvmocP115CuDYaDSZnize5nEatZpDCkGEGsu'
         'GjsnBGidvG6H3ZZGLqBvwjE2TF65vvMphKomStDGQWE5JBMsQA7UmZ7'),
        ('tpubDDLkGHUS4f3JrExQj1QN5LC4akrBW2VAhbLFMFC8mJgCpemZXifj'
         '4w2RQJHhZD4ET9VcxkcdZXxGfnUZv29EbsD7qD8rYJRrp9QXbenMXd7',
         'tprv8gei7sSBvHMdxmvcqMjmfvXx1jLFLhJG8HjU4j9qM2sozAWnuKr8'
         'tSQZEA57BdJkAqJKgFEb6S7StLBYpy4cxVDWZcVFSCcmfMXRdSUP5PR'),
        ('tpubDBD1DrcA8gpjpVdcbR5cFS9dHL9mUthxikEiVhmqXFqVHxr5tj6k'
         'Fa12HpJmfsiuMcWqRoq7FgHsKUSwwAKguWzUTwGak7SpR9suaUfuiD6',
         'tprv8eWy5SZuzK94w2bphmR1r2VWiJdqKZX49SdwDBjY6z36TUbKGLHA'
         '55PA7iUWTVKQjdQ95wz8Uy63pwuinehL72qsYyRFhM7i8huwRMxX9Jh'),
        ('tpubD9PSZUhp2M8CsZJMRXgg3MRp78bPM5L19fexkkiVxDaNcBUgUiPH'
         'TEFPg3rgbvaSxRjZGm793doYgRhV6kPpQNm7dinSniz8CrUaFc3JfwR',
         'tprv8chQR4fZsySXz6GZXt25dwmhY75TBk96aN4BUEgCXwmymhDurKZh'
         'GjdXVudZa6LhSSqo8vkPADFzssBtUXQKoRyK71yFaLEYG5fa1RGWKqY'),
        ('tpubD6NzVbkrYhZ4XjPybvVw1yfCMNhtBfcwfJaFycMouiGGhdrT5jyW'
         'b4NeivCte87ytt7f4qBaAQcWgTb3xS5oRrgnxByiQE7WjrkP1eZumon',
         'tprv8ZgxMBicQKsPeGNBiGqLca15nMBx2LS35zyUh6KWVSTss9bgTM9v'
         'QZknYnX2CdoDzkKmpRo8QZBvJceVBAAq7dSGK85j7MhCf2ZVToT36UX'),
        ('tpubDHFe2fdwqMEkzbTpx3GZjMSc1cfywRETR6dMx1Z7qoDHJgduZCr3'
         'Q6CkaJK4uDY9SpwonuDBTe8fjK9NCYmyzE5FQLvHCZEo5xhPYvwHgg8',
         'tprv8kZbtFbhgyZ678S34PbyKwnVSbA3n63Yqo2afVWpRXQtUCP8vp2T'
         'DbatQA23vW52PiDV52s8bnBMgBqQFJpGVdRi7RJkdxG9Yx32BPw6uKb'),
        ('tpubDEp72oRxJByNPNbhJp939pcwL67igJxHSzt6XQM7r5nF2uu3ZxPg'
         'S2hz3BsSVtvYAeweaJwTAJFgBzcRGvCgaTyVn31ut7CsvEnaaxp3Cwe',
         'tprv8i84tPPi9pHhVuZuRAUSkQxpm4bnWymNshHKEtJpRoyrCReGwZa6'
         'FY67s4cgwqxtbGNCWWWhcwcFWzdFDtpqeMpw96b56RtMfZXAFd9kKuh'),
        ('tpubDCZivWe1G5AxsNbupJnBPYUfBAy4eWbZs9BBCXV2rkbZ3N1Fi3e1'
         '9B1GcYeoT2UsngmqM2z1oPRwUUeEMuk1Y8Ku1bgrhNvcLiyg8ERkNoL',
         'tprv8fsgn6bm7hVHyua7vf7az8pYc9T8VBQfHqaPv1SjSUoACskV5epQ'
         'xgPQSQ1BjqXh4sjaZNZsxDvvjuwePEGHFBo1qbcZAvHixSZUfM4QQtr'),
        ('tpubDAtbo5g1qbYsLTD76KiRG4sNB48oD5eUTjgmPsnRMwuQSy4k5sag'
         'vJBH1LP5yGwDJHWhPQR61jqburWoee9kYuwkFJuTozddAVCFxQVB7wR',
         'tprv8eCZefdmhDsCSzBKCg3prfDFc2cs3kTZtS5z7Mk7wg71cUoyTUm6'
         'joZQqEHb87njVJxS8J1uNDXAB99mPPRixy4WpyZUbbYSij6mpbDpzKw'),
        ('tpubD8rXJ4n6Xbd5bP1zSJ1MKtkVEJapMQjiqJqdp3Tk8rAMsiWqt4i9'
         'HNt5omstF2pM6WL2Mu9R3VSxzFVGN5CMUG5PrkbGw9ukVjDyYXv4wTD',
         'tprv8cAV9ejrPDwQhuzCYeLkvV6NfH4tC5YpG1ErXXRSiaMy3EG5FftZ'
         '6tGDdbXmZ37Tw9MkZkMdMaHxL9LQGoPbyEWnGsEzesHegCfwZyQxQWH'),
        ('tpubD6NzVbkrYhZ4WM9KGkvWDfaQ8TbaigvHZnAcdyUH9BDihGTD3FkS'
         'Ed21ATMkqs4vTFY3LCgfeamCvRSnoQpsiaz8zmH5bYYiGMUUGKmnzyY',
         'tprv8ZgxMBicQKsPct7XP7FupFvHZS5eZMjNzUZqMTRyiuRKrnCSQrvr'
         '48Q8zLtc4w3vMCiZnmXXXVxxjRQFLZjgj7JHZ5n4WM2CULDEaqpCsVo')]

regtest = Manager()
regtest.generate_nodes(1)
regtest.start_nodes()
regtest.send_rpc_cmd(['generate', '500'], 0)

parser = ArgumentParser()
parser.add_argument('--dump', dest='dumpfile')
parser.add_argument('unittest_args', nargs='*')
cmdline_args = parser.parse_args()


def min_locktime(locktimes):
    m = 0
    res = Locktime(0)
    for lock in locktimes:
        if m is 0 or lock.n < m:
            m = lock.n
            res = lock
    return res


class Embedder(metaclass=ABCMeta):

    @staticmethod
    @abstractmethod
    def get_script_cls():
        raise NotImplemented

    @staticmethod
    @abstractmethod
    def get_name():
        raise NotImplemented

    @staticmethod
    def get_args():
        return []

    def __init__(self, *args, scripts):
        self.instance = self.get_script_cls()(*self.get_args(), *args, *scripts)

    def post(self):
        pass


class P2shEmbedder(Embedder):
    @staticmethod
    def get_name():
        return 'p2sh'

    @staticmethod
    def get_script_cls():
        return P2shScript


class P2wshEmbedder(Embedder):
    @staticmethod
    def get_name():
        return 'p2wsh'

    @staticmethod
    def get_script_cls():
        return P2wshV0Script


class IfElseEmbedder(Embedder):
    @staticmethod
    def get_name():
        return 'ifelse'

    @staticmethod
    def get_script_cls():
        return IfElseScript


class TimelockEmbedder(Embedder):
    @staticmethod
    def get_name():
        return 'absolutetime'

    @staticmethod
    def get_script_cls():
        return TimelockScript

    @staticmethod
    def get_args():
        return Locktime(100),


class Relativetimelockembedder(Embedder):
    @staticmethod
    def get_name():
        return 'relativetime'

    @staticmethod
    def get_script_cls():
        return RelativeTimelockScript

    @staticmethod
    def get_args():
        return Sequence(3),

    def post(self):
        regtest.send_rpc_cmd(['generate', '3'])


class Hashlock160Embedder(Embedder):
    @staticmethod
    def get_name():
        return 'hash160'

    @staticmethod
    def get_script_cls():
        return Hashlock160Script


class Hashlock256Embedder(Embedder):
    @staticmethod
    def get_name():
        return 'hash256'

    @staticmethod
    def get_script_cls():
        return Hashlock256Script


class TestSpends(unittest.TestCase):

    @staticmethod
    def rand_bytes(n=500):
        import os
        return bytearray(os.urandom(n))

    @staticmethod
    def pairwise(iterable):
        from itertools import tee
        a, b = tee(iterable)
        next(b, None)
        return list(zip(a, b))

    def __init__(self, *args, **kwargs):
        global keys

        super().__init__(*args, **kwargs)

        pubs = [ExtendedPublicKey.decode(pair[0]).key for pair in keys]
        privs = [ExtendedPrivateKey.decode(pair[1]).key for pair in keys]
        all_embedders = {'p2sh', 'p2wsh', 'ifelse', 'absolutetime', 'relativetime', 'hash160', 'hash256'}

        self.scripts = [{'name': 'p2pkh',
                         'script': P2pkhScript(pubs[0]),
                         'solver': partial(P2pkhSolver, privs[0]),
                         'embeddable_by': all_embedders},
                        {'name': 'p2wpkh',
                         'script': P2wpkhV0Script(pubs[1]),
                         'solver': partial(P2wpkhV0Solver, privs[1]),
                         'embeddable_by': {'p2sh'}},
                        {'name': 'p2pk',
                         'script': P2pkScript(pubs[2]),
                         'solver': partial(P2pkSolver, privs[2]),
                         'embeddable_by': all_embedders},
                        {'name': 'multisig',
                         'script': MultisigScript(2, pubs[3], pubs[4], pubs[5], 3),
                         'solver': partial(MultisigSolver, privs[3], privs[4]),
                         'embeddable_by': all_embedders}, ]

        self.sighashed_scripts = []

        for script in self.scripts:
            for args in (('ALL', False), ('ALL', True), ('NONE', False), ('NONE', True), ('SINGLE', False),
                         ('SINGLE', True)):
                scriptcpy = copy.deepcopy(script)
                scriptcpy['sighash'] = Sighash(*args)
                try:
                    scriptcpy['solver'] = scriptcpy['solver'](sighash=Sighash(*args))
                except TypeError:
                    scriptcpy['solver'] = scriptcpy['solver'](sighashes=[Sighash(*args), Sighash(*args)])
                self.sighashed_scripts.append(scriptcpy)

        self.scripts = self.sighashed_scripts

        self.scripts = self.sighashed_scripts

        self.final = {'name': 'nulldata',
                      'script': NulldataScript(StackData.unhexlify('deadbeef')),
                      'solver': None,
                      'embeddable_by': {}}
        self.preimage_streams = [Stream(TestSpends.rand_bytes())]
        self.preimages = [pre.serialize() for pre in self.preimage_streams]
        self.hashes160 = [preimage.hash160() for preimage in self.preimage_streams]
        self.hashes256 = [preimage.hash256() for preimage in self.preimage_streams]

        self.all = [(s['script'],
                     (s['solver'], s['script']),
                     s['name']) for s in self.scripts]

        self.embedders = [TimelockEmbedder, Relativetimelockembedder,
                          Hashlock160Embedder, Hashlock256Embedder]

        self.double_embedders = [IfElseEmbedder]

        embedded = []

        for embedder in self.embedders:
            if embedder.get_name() != 'ifelse':
                for script in self.scripts:
                    if embedder.get_name() in script['embeddable_by']:
                        if embedder.get_name() == 'hash160':
                            for preimage, phash in zip(self.preimages, self.hashes160):
                                emb = embedder(phash, scripts=[script['script']])
                                embedded.append((emb.instance,
                                                 (HashlockSolver(preimage, script['solver']),
                                                  emb.instance),
                                                 '{}({})'.format(embedder.get_name(), script['name'])))
                        elif embedder.get_name() == 'hash256':
                            for preimage, phash in zip(self.preimages, self.hashes256):
                                emb = embedder(phash, scripts=[script['script']])
                                embedded.append((emb.instance,
                                                 (HashlockSolver(preimage, script['solver']),
                                                  emb.instance),
                                                 '{}({})'.format(embedder.get_name(), script['name'])))
                        else:
                            emb = embedder(scripts=[script['script']])
                            embedded.append((emb.instance,
                                             (TimelockSolver(script['solver']), emb.instance),
                                             '{}({})'.format(embedder.get_name(), script['name'])))

        self.all += [s for s in embedded]

        for embedder in self.double_embedders:
            included = [(x, y, t) for (x, y, t) in self.all if t != 'p2wpkh']
            for ((if_script, (if_solver, _), if_type), (else_script, (else_solver, _), else_type)) in TestSpends.pairwise(included):
                for branch in [Branch.IF, Branch.ELSE]:
                    inst = embedder(scripts=[if_script, else_script]).instance
                    # print(type(if_script), type(if_keys), type(if_spend), type(if_type))
                    # if 'hash' in else_type:
                    #     print(else_spend)
                    self.all.append((inst,
                                     (IfElseSolver(branch, if_solver if branch == Branch.IF else else_solver), inst),
                                     'ifelse({}, {})'.format(if_type, else_type)))

        for script, (solver, _), stype in [s for s in self.all]:
            if 'p2wpkh' not in stype:
                inst = P2wshEmbedder(scripts=[script]).instance
                self.all.append((inst,
                                 (P2wshV0Solver(script, solver), script),
                                 'p2wsh({})'.format(stype)))

        for script, (solver, prev), stype in [s for s in self.all]:
            inst = P2shEmbedder(scripts=[script]).instance
            self.all.append((inst,
                             (P2shSolver(script, solver), prev),
                             'p2sh({})'.format(stype)))

    def get_spending_data(self, solver, state=None):
        if state is None:
            state = {}
        # base case
        if isinstance(solver, (P2pkhSolver, P2wpkhV0Solver, P2pkSolver, MultisigSolver)):
            state['sig_hashes'] = [hexlify(sighash.as_byte()).decode() for sighash in solver.get_sighashes()]
            if isinstance(solver, P2pkSolver):
                state['priv_keys'] = [solver.privk.hexlify()]
            elif isinstance(solver, P2pkhSolver):
                state['priv_keys'] = [solver.privk.hexlify()]
            elif isinstance(solver, P2wpkhV0Solver):
                state['priv_keys'] = [solver.privk.hexlify()]
            else:
                assert isinstance(solver, MultisigSolver)
                state['priv_keys'] = [privk.hexlify() for privk in solver.privkeys]
            return state
        else:
            if isinstance(solver, HashlockSolver):
                return self.get_spending_data(solver.inner_solver, state)
            elif isinstance(solver, TimelockSolver):
                return self.get_spending_data(solver.inner_solver, state)
            elif isinstance(solver, IfElseSolver):
                try:
                    state['branches'].append(solver.branch.value)
                except KeyError:
                    state['branches'] = [solver.branch.value]
                return self.get_spending_data(solver.inner_solver, state)
            elif isinstance(solver, P2shSolver):
                return self.get_spending_data(solver.redeem_script_solver, state)
            elif isinstance(solver, P2wshV0Solver):
                return self.get_spending_data(solver.witness_script_solver, state)
            else:
                assert False

    def json_dump(self, unspent, spending, index, mutable_tx):
            dump = {'script_pubkey': {'hex': unspent['txout'].script_pubkey.hexlify(),
                                      'type': unspent['txout'].script_pubkey.type},
                    'spend_data': {'prev_amount': unspent['txout'].value}}
            prev_script = unspent['txout'].script_pubkey
            if isinstance(unspent['solver'], P2shSolver):
                dump['spend_data']['redeem_script'] = {'hex': unspent['solver'].redeem_script.hexlify(),
                                                       'type': unspent['solver'].redeem_script.type}
                prev_script = unspent['solver'].redeem_script
                if isinstance(unspent['solver'].redeem_script_solver, P2wshV0Solver):
                    dump['spend_data']['witness_script'] = {'hex': unspent['solver'].redeem_script_solver.witness_script.hexlify(),
                                                            'type': unspent['solver'].redeem_script_solver.witness_script.type}
                    prev_script = unspent['solver'].redeem_script_solver.witness_script
            elif isinstance(unspent['solver'], P2wshV0Solver):
                dump['spend_data']['witness_script'] = {'hex': unspent['solver'].witness_script.hexlify(),
                                                        'type': unspent['solver'].witness_script.type}
                prev_script = unspent['solver'].witness_script
            dump['script_sig'] = spending.script_sig.hexlify()
            if spending.witness is not None:
                dump['witness'] = spending.witness.hexlify()

            spend_data = dict(dump['spend_data'], **self.get_spending_data(unspent['solver']))
            dump['spend_data'] = spend_data
            dump['digests'] = []
            for sighash in unspent['solver'].get_sighashes():
                if unspent['solver'].solves_segwit():
                    dump['digests'].append(hexlify(mutable_tx.get_segwit_digest(index,
                                                                                prev_script=prev_script,
                                                                                prev_amount=unspent['txout'].value,
                                                                                sighash=sighash)).decode())
                else:
                    dump['digests'].append(hexlify(mutable_tx.get_digest(index, prev_script, sighash=sighash)).decode())
            return dump

    def test_all(self):
        global keys
        priv = ExtendedPrivateKey.decode(keys[0][1]).key
        pk = priv.pub()
        addr_string = str(pk.to_address())
        utxo = []

        for i in range(3):
            # create 3 tx to add to UTXO
            txid = regtest.send_rpc_cmd(['sendtoaddress', addr_string, '100'], 0)
            to_spend = Transaction.unhexlify(regtest.send_rpc_cmd(['getrawtransaction', txid, '0'], 0))
            txout = None
            for out in to_spend.outs:
                if str(out.script_pubkey.address()) == addr_string:
                    txout = out
                    break
            assert txout is not None

            utxo.append({'txid': txid,
                         'txout': txout,
                         'solver': P2pkhSolver(priv),
                         'next_seq': Sequence.max(),
                         'next_locktime': Locktime(0)})

        regtest.send_rpc_cmd(['generate', '100'], 0)

        generate = False
        next_locktime = Locktime(0)
        next_sequence = Sequence.max()

        i = 0
        while i < len(self.all) - 2:
            print('{:04d}\r'.format(i), end='', flush=True)
            ins = [MutableTxIn(unspent['txid'], unspent['txout'].n, ScriptSig.empty(), unspent['next_seq']) for unspent in utxo]
            outs = []
            prev_types = []

            for j, (unspent, script) in enumerate(zip(utxo, self.all[i:i+3])):
                outs.append(TxOut(unspent['txout'].value - 1000000, j, script[0]))
                prev_types.append(script[2])

            tx = MutableTransaction(2, ins, outs, min_locktime(unspent['next_locktime'] for unspent in utxo))
            mutable = copy.deepcopy(tx)
            tx = tx.spend([unspent['txout'] for unspent in utxo], [unspent['solver'] for unspent in utxo])

            # print('====================')
            # print('txid: {}'.format(tx.txid))
            # print()
            # print(tx)
            # print()
            # print('raw: {}'.format(tx.hexlify()))
            # print('prev_scripts, amounts, solvers:')

            print('TX: {}'.format(i))
            regtest.send_rpc_cmd(['sendrawtransaction', tx.hexlify()], 0)
            print('Mempool size: {}'.format(len(regtest.send_rpc_cmd(['getrawmempool'], 0))))

            if cmdline_args.dumpfile is not None:
                with open(cmdline_args.dumpfile, 'a') as out:
                    for j, unspent in enumerate(utxo):
                        json.dump(self.json_dump(unspent, tx.ins[j], j, copy.deepcopy(mutable).to_segwit()), out)
                        out.write('\n')

            utxo = []

            for j, (output, prev_type) in enumerate(zip(tx.outs, prev_types)):

                if 'time' in prev_type:
                    if 'absolute' in prev_type:
                        next_locktime = Locktime(100)
                        next_sequence = Sequence(0xfffffffe)
                    if 'relative' in prev_type:
                        next_sequence = Sequence(3)
                        generate = True
                else:
                    next_locktime = Locktime(0)
                    next_sequence = Sequence.max()

                utxo.append({'txid': tx.txid,
                             'txout': output,
                             'solver': self.all[i+j][1][0],  # solver
                             'next_seq': next_sequence,
                             'next_locktime': next_locktime})
            if generate:
                regtest.send_rpc_cmd(['generate', '4'], 0)
                generate = False

            if not i % 10:
                print('generating 2')
                regtest.send_rpc_cmd(['generate', '2'], 0)

            i += 1

        ins = [MutableTxIn(unspent['txid'],
                           unspent['txout'].n,
                           ScriptSig.empty(),
                           unspent['next_seq']) for unspent in utxo]

        tx = MutableTransaction(2,
                                ins,
                                [TxOut(sum(unspent['txout'].value for unspent in utxo) - 1000000, 0, self.final['script'])],
                                min_locktime(unspent['next_locktime'] for unspent in utxo))
        tx = tx.spend([unspent['txout'] for unspent in utxo], [unspent['solver'] for unspent in utxo])

        # print('====================')
        # print('txid: {}'.format(tx.txid))
        # print()
        # print(tx)
        # print()
        # print('raw: {}'.format(tx.hexlify()))
        # print('prev_scripts, amounts, solvers:')
        # for unspent in utxo:
        #     print(unspent['txout'].script_pubkey, unspent['txout'].value, unspent['solver'].__class__.__name__)
        regtest.send_rpc_cmd(['sendrawtransaction', tx.hexlify()], 0)

        regtest.teardown()


if __name__ == '__main__':
    sys.argv[1:] = cmdline_args.unittest_args
    unittest.main()
