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


import unittest
from unittest.mock import patch

from btcpy.structs.transaction import *
from btcpy.structs.script import *
from btcpy.structs.block import *
from btcpy.structs.crypto import PublicKey, PrivateKey
from btcpy.structs.address import Address
from btcpy.lib.codecs import CouldNotDecode
from btcpy.setup import setup
from btcpy.structs.hd import *
from btcpy.lib.parsing import IncompleteParsingException

setup('regtest')


def get_data(filename):
    import os
    import json
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open('{}/data/{}.json'.format(dir_path, filename)) as infile:
        return json.load(infile)


transactions = get_data('rawtxs')
scripts = get_data('scripts')
keys = get_data('xkeys')
segwit_valid_addresses = get_data('segwit_addr_valid')
segwit_invalid_addresses = get_data('segwit_addr_invalid')
valid_blocks = get_data('valid_blocks')
invalid_blocks = get_data('invalid_blocks')
short_blocks = get_data('short_blocks')
hd_keys = get_data('hd')
addresses = get_data('addr')
malleated_txs = get_data('malleated')
privk = get_data('priv_addr_path')
segsig = get_data('segwitsig')
p2sh = get_data('p2sh')
priv_pub_hash_addr_p2pkh_segwit = get_data('priv_pub_hash_addr_p2pkh_segwit')


class TestPrivPubHashAddrP2pkhSegwit(unittest.TestCase):

    def test(self):
        for data in priv_pub_hash_addr_p2pkh_segwit:
            priv = PrivateKey.from_wif(data['privkey'])
            pub = PublicKey.unhexlify(data['pubkey'])
            pubhash = bytearray(unhexlify(data['pubkeyhash']))
            address = Address.from_string(data['address'], check_network=False)
            p2pkhhex = data['scriptpubkey']
            segwit_addr = data['segwit']

            self.assertEqual(priv.pub(), pub)
            self.assertEqual(pub.hash(), pubhash)
            self.assertEqual(address.hash, pubhash)
            self.assertEqual(P2pkhScript(pub).hexlify(), p2pkhhex)
            self.assertEqual(P2pkhScript(address).hexlify(), p2pkhhex)
            self.assertEqual(P2pkhScript(pubhash).hexlify(), p2pkhhex)
            self.assertEqual(str(P2shScript(P2wpkhV0Script(pub)).address()), segwit_addr)
            self.assertEqual(str(P2shScript(P2wpkhV0Script(pubhash)).address()), segwit_addr)
            self.assertEqual(P2shScript(P2wpkhV0Script(pub)).scripthash, Address.from_string(segwit_addr).hash)
            self.assertEqual(P2shScript(P2wpkhV0Script(pubhash)).scripthash, Address.from_string(segwit_addr).hash)


class TestNormalizedId(unittest.TestCase):

    def test(self):
        for tx1, tx2 in malleated_txs:
            tx1 = Transaction.unhexlify(tx1)
            tx2 = Transaction.unhexlify(tx2)
            self.assertNotEqual(tx1.txid, tx2.txid)
            self.assertEqual(tx1.normalized_id, tx2.normalized_id)


class TestHD(unittest.TestCase):

    def test_hd(self):
        masterpriv = None
        for data in hd_keys:
            priv = ExtendedKey.decode(data['prv'], check_network=False)
            pub = ExtendedKey.decode(data['pub'], check_network=False)
            if data['path'] == 'm':
                masterpriv = priv
            self.assertEqual(priv.pub().encode(mainnet=True), pub.encode(mainnet=True))
            self.assertEqual(priv.encode(mainnet=True), data['prv'])
            self.assertEqual(pub.encode(mainnet=True), data['pub'])
            derived = masterpriv.derive(data['path'])
            self.assertEqual(derived.encode(mainnet=True), data['prv'])
            self.assertEqual(derived.pub().encode(mainnet=True), data['pub'])

    def test_priv_pub(self):
        masterpub = ExtendedPublicKey.decode(hd_keys[0]['pub'], check_network=False)
        masterpriv = ExtendedPublicKey.decode(hd_keys[0]['prv'], check_network=False)
        pubs = [masterpub]
        privs = [masterpriv]
        paths = ['m/0/1/2147483646/2',
                 './2147483646/0',
                 './0/2147483647/1/2147483646/2',
                 './156131385/44645489/4865448/4896853']
        for path in paths:
            newpubs = []
            newprivs = []
            for pub, priv in zip(pubs, privs):
                newpubs.append(pub.derive(path))
                newprivs.append(priv.derive(path))
                self.assertEqual(newpubs[-1], newprivs[-1].pub())
            pubs += newpubs
            privs += newprivs


class TestBlock(unittest.TestCase):
    def test_block_deserialize_serialize(self):
        for i in range(len(valid_blocks)):
            unhex_block = Block.unhexlify(valid_blocks[i]['raw'])
            serial_block = unhex_block.serialize()
            self.assertEqual(valid_blocks[i]['raw'], hexlify(serial_block).decode())

    def test_block_hash(self):
        for i in range(len(valid_blocks)):
            unhex_block = Block.unhexlify(valid_blocks[i]['raw'])
            self.assertEqual(valid_blocks[i]['hash'], unhex_block.hash())

    def test_block_header(self):
        for i in range(len(valid_blocks)):
            unhex_block = Block.unhexlify(valid_blocks[i]['raw'])
            unhex_header = BlockHeader.unhexlify(valid_blocks[i]['raw'])
            self.assertEqual(hexlify(unhex_block.header.serialize()), hexlify(unhex_header.serialize()))

    def test_fail_block_deserialize_serialize(self):
        for i in range(len(valid_blocks)):
            unhex_block = Block.unhexlify(invalid_blocks[i]['raw'])
            serial_block = unhex_block.serialize()
            self.assertNotEqual(valid_blocks[i]['raw'], hexlify(serial_block).decode())

    def test_fail_block_hash(self):
        for i in range(len(valid_blocks)):
            unhex_block = Block.unhexlify(invalid_blocks[i]['raw'])
            self.assertNotEqual(valid_blocks[i]['hash'], unhex_block.hash())

    def test_fail_block_header(self):
        for i in range(len(valid_blocks)):
            unhex_block = Block.unhexlify(valid_blocks[i]['raw'])
            unhex_header = BlockHeader.unhexlify(invalid_blocks[i]['raw'])
            self.assertNotEqual(hexlify(unhex_block.header.serialize()), hexlify(unhex_header.serialize()))

    def test_stop_iteration(self):
        for i in range(len(short_blocks)):
            with self.assertRaises(StopIteration):
                Block.unhexlify(short_blocks[i]['raw'])
            with self.assertRaises(StopIteration):
                Block.unhexlify(short_blocks[i]['raw']).serialize()

    def test_empty_deserialized_string(self):
        for i in range(len(valid_blocks)):
            parser = BlockParser(bytearray(unhexlify(valid_blocks[i]['raw'])))
            parser.get_block_header()
            parser.get_txns()
            with self.assertRaises(StopIteration):
                parser >> 1

    def test_incomplete_parsing_exception(self):
        for i in range(len(valid_blocks)):
            aug_raw = valid_blocks[i]['raw'] + "ff"
            with self.assertRaises(IncompleteParsingException):
                Block.unhexlify(aug_raw)


class TestTransaction(unittest.TestCase):

    def test_serialization(self):
        for data in transactions:
            tx = Transaction.unhexlify(data['raw'])
            computed = tx.hexlify()
            original = data['raw']
            self.assertEqual(computed, original)

    def test_txid(self):
        for data in transactions:
            self.assertEqual(Transaction.unhexlify(data['raw']).txid, data['txid'])

    def test_script(self):
        for key, value in scripts.items():
            parsed_script = ScriptBuilder.identify(value['hex'])
            self.assertEqual(parsed_script.hexlify(), value['hex'])
            self.assertEqual(eval(value['code']).hexlify(), value['hex'])
            self.assertEqual(parsed_script.type, value['type'])


class TestSegWitAddress(unittest.TestCase):

    def test_valid(self):
        for data in segwit_valid_addresses:
            address = SegWitAddress.from_string(data['address'], check_network=False)
            script = ScriptBuilder.identify(data['script'])
            self.assertEqual(address.hash, script.address().hash)
            if len(data['script']) == 44:
                self.assertEqual(P2wpkhV0Script(address), script)
            elif len(data['script']) == 68:
                self.assertEqual(P2wshV0Script(address), script)

    def test_invalid(self):
        for address in segwit_invalid_addresses:
            with self.assertRaises(CouldNotDecode):
                print(SegWitAddress.from_string(address, check_network=False))


class TestReplace(unittest.TestCase):

    def test_success(self):
        for transaction in transactions:
            tx = MutableTransaction.unhexlify(transaction['raw'])
            self.assertEqual(tx.is_replaceable(), transaction['replaceable'])
            if len(tx.ins) > 2:
                tx.ins[1].sequence = Sequence(0xfffffffd)
                self.assertTrue(tx.ins[1].is_replaceable())
                self.assertFalse(tx.ins[2].is_replaceable())
                self.assertTrue(tx.is_replaceable())


class TestStackData(unittest.TestCase):

    @staticmethod
    def get_test_data():
        from os import walk
        files = next(walk('./stack_data/data/rand_data'))[2]
        for file in files:
            with open('stack_data/data/rand_data/'+file, 'rb') as infile:
                yield bytearray(infile.read())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fail_sizes = [2**32 + 1]

    def test_success(self):
        stored_data = TestStackData.get_test_data()
        for data in stored_data:
            stack = StackData.from_bytes(data)
            push_op = stack.to_push_op()
            if len(data) == 1 and 0 <= data[0] <= 16:
                self.assertTrue(len(push_op) == len(data))
            elif 1 <= len(data) <= 75:
                self.assertTrue(len(push_op) == len(data) + 1)
                self.assertTrue(push_op[0] == len(data))
            elif 76 <= len(data) <= 255:
                self.assertTrue(len(push_op) == len(data) + 2)
                self.assertTrue(push_op[0] == 76)
                self.assertTrue(push_op[1] == len(data))
            elif 256 <= len(data) <= 2**16 - 1:
                self.assertTrue(len(push_op) == len(data) + 3)
                self.assertTrue(push_op[0] == 77)
                self.assertTrue(int.from_bytes(push_op[1:3], 'little') == len(data))
            elif 65536 <= len(data) <= 2**32 - 1:
                self.assertTrue(len(push_op) == len(data) + 5)
                self.assertTrue(push_op[0] == 78)
                self.assertTrue(int.from_bytes(push_op[1:5], 'little') == len(data))

    def test_failure(self):
        for size in self.fail_sizes:
            with patch('btcpy.structs.script.len', return_value=size, create=True):
                with self.assertRaises(WrongPushDataOp):
                    StackData(bytearray([0]))

    def test_int_conversion(self):
        import os
        path = os.path.realpath(__file__).rsplit('/', 1)[0]
        with open('{}/data/stack_data/rand_ints'.format(path)) as infile:
            ints = [int(x) for x in infile.read().split()]
        ints = list(range(1001)) + ints
        for x in ints:
            self.assertTrue(int(StackData.from_int(x)) == x)


class TestKeys(unittest.TestCase):

    def test_priv_to_pubhash(self):
        for priv, addr, _ in privk['derivations']:
            self.assertEqual(str(PrivateKey.from_wif(priv).pub().to_address(mainnet=False)),
                             addr)
            self.assertEqual(PrivateKey.from_wif(priv).pub().hash(),
                             Address.from_string(addr, check_network=False).hash)

    def test_derivation(self):
        m = ExtendedPrivateKey.decode(privk['master'])
        for priv, _, path in privk['derivations']:
            self.assertEqual(m.derive(path).key, PrivateKey.from_wif(priv))

    def test_to_wif(self):
        vectors = get_data('wif')
        for v in vectors:
            self.assertEqual(PrivateKey.from_wif(v['wif'], check_network=False).hexlify(), v['hex'])
            priv = PrivateKey.unhexlify(v['hex'])
            if not v['compressed']:
                priv.public_compressed = False
            self.assertEqual(priv.to_wif(v['mainnet']), v['wif'])


class TestPubkey(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.compressed = '03fe43d0c2c3daab30f9472beb5b767be020b81c7cc940ed7a7e910f0c1d9feef1'
        self.uncompressed = ('04fe43d0c2c3daab30f9472beb5b767be020b81c7cc940ed7a7e910f0c1d9feef10fe85eb3ce193405c2dd845'
                             '3b7aeb6c1752361efdbf4f52ea8bf8f304aab37ab')
        self.address = '1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa'

    def test_compression(self):
        pubk = PublicKey.unhexlify(self.uncompressed)
        self.assertTrue(hexlify(pubk.compressed).decode() == self.compressed)

    def test_uncompression(self):
        pubk = PublicKey.unhexlify(self.compressed)
        self.assertTrue(hexlify(pubk.uncompressed).decode() == self.uncompressed)

    def test_address_generation(self):
        pubk = PublicKey.unhexlify(self.uncompressed)
        self.assertTrue(str(pubk.to_address(True)) == self.address)


class TestPrivKey(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        from ecdsa import SigningKey, SECP256k1
        super().__init__(*args, **kwargs)
        self.privs = [ExtendedPrivateKey.decode(k[1], check_network=False).key for k in keys]
        self.vers = [SigningKey.from_string(p.key, curve=SECP256k1).get_verifying_key() for p in self.privs]

    def test_raw_sig_success(self):
        from os import urandom
        for _ in range(10):
            for ver, priv in zip(self.vers, self.privs):
                digest = bytearray(urandom(32))
                r, s, order = priv.raw_sign(digest)
                self.assertTrue(s in range(1, PrivateKey.highest_s))
                self.assertTrue(ver.verify_digest((r, s), digest, sigdecode=lambda sig, _: (sig[0], sig[1])))

    def test_der_sig_success(self):
        from os import urandom
        import struct
        for _ in range(10):
            for priv in self.privs:
                digest = bytearray(urandom(32))
                sig = priv.sign(digest)
                length_r = sig[3]
                length_s = sig[5 + length_r]
                s = int.from_bytes(bytearray(struct.unpack(str(length_s) + 'B', sig[6 + length_r:6 + length_r + length_s])), 'big')
                self.assertTrue(s in range(1, PrivateKey.highest_s))

    def test_derivation_success(self):
        for pub, priv in keys:
            pu = ExtendedPublicKey.decode(pub, check_network=False).key
            pr = ExtendedPrivateKey.decode(priv, check_network=False).key
            self.assertTrue(pr.pub() == pu)
            self.assertTrue(pr.pub().hexlify() == pu.hexlify())


class TestP2pk(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pubk = '0384478d41e71dc6c3f9edde0f928a47d1b724c05984ebfb4e7d0422e80abe95ff'

    def test_success(self):
        script = P2pkScript(PublicKey.unhexlify(self.pubk))
        self.assertTrue(script.decompile() == '{} OP_CHECKSIG'.format(self.pubk))
        self.assertTrue(script.hexlify() == '21{}ac'.format(self.pubk))

    def test_matching_fail_leftover(self):
        with self.assertRaises(WrongScriptTypeException):
            P2pkScript.unhexlify('21{}acac'.format(self.pubk))

    def test_matching_fail_long_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2pkScript.unhexlify('22{}11ac'.format(self.pubk))

    def test_matching_fail_short_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2pkScript.unhexlify('20{}ac'.format(self.pubk[:-2]))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            P2pkScript.unhexlify('21{}ad'.format(self.pubk))


class TestP2pkh(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pubk = PublicKey.unhexlify('0384478d41e71dc6c3f9edde0f928a47d1b724c05984ebfb4e7d0422e80abe95ff')
        self.pubkh = self.pubk.hash()
        self.address = Address.from_string('mquvJWnJJwTDUcdneQkUbrfN2wm9uiXd1p')

    def test_success_pubk(self):
        script = P2pkhScript(self.pubk)
        self.assertTrue(script.decompile() ==
                        'OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG'.format(hexlify(self.pubkh).decode()))
        self.assertTrue(script.hexlify() == '76a914{}88ac'.format(hexlify(self.pubkh).decode()))

    def test_success_hash(self):
        script = P2pkhScript(self.pubkh)
        self.assertTrue(script.decompile() ==
                        'OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG'.format(hexlify(self.pubkh).decode()))
        self.assertTrue(script.hexlify() == '76a914{}88ac'.format(hexlify(self.pubkh).decode()))

    def test_success_address(self):
        script = P2pkhScript(self.address)
        self.assertTrue(script.decompile() ==
                        'OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG'.format(hexlify(self.pubkh).decode()))
        self.assertTrue(script.hexlify() == '76a914{}88ac'.format(hexlify(self.pubkh).decode()))

    def test_matching_fail_leftover(self):
        with self.assertRaises(WrongScriptTypeException):
            P2pkScript.unhexlify('76a914{}88acac'.format(hexlify(self.pubkh).decode()))

    def test_matching_fail_long_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2pkScript.unhexlify('79a915{}1188ac'.format(hexlify(self.pubkh).decode()))

    def test_matching_fail_short_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2pkScript.unhexlify('79a913{}88ac'.format(hexlify(self.pubkh[:-1]).decode()))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            P2pkScript.unhexlify('79a914{}88ad'.format(hexlify(self.pubkh).decode()))


class TestPwpkhScript(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pubk = PublicKey.unhexlify('0384478d41e71dc6c3f9edde0f928a47d1b724c05984ebfb4e7d0422e80abe95ff')
        self.pubkh = self.pubk.hash()

    def test_success_pubk(self):
        script = P2wpkhV0Script(self.pubk)
        self.assertTrue(script.decompile() ==
                        'OP_0 {}'.format(hexlify(self.pubkh).decode()))
        self.assertTrue(script.hexlify() == '0014{}'.format(hexlify(self.pubkh).decode()))

    def test_success_hash(self):
        script = P2wpkhV0Script(self.pubkh)
        self.assertTrue(script.decompile() ==
                        'OP_0 {}'.format(hexlify(self.pubkh).decode()))
        self.assertTrue(script.hexlify() == '0014{}'.format(hexlify(self.pubkh).decode()))

    def test_matching_fail_leftover(self):
        with self.assertRaises(WrongScriptTypeException):
            P2wpkhV0Script.unhexlify('0014{}aa'.format(hexlify(self.pubkh).decode()))

    def test_matching_fail_long_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2wpkhV0Script.unhexlify('0015{}aa'.format(hexlify(self.pubkh).decode()))

    def test_matching_fail_short_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2wpkhV0Script.unhexlify('0013{}'.format(hexlify(self.pubkh[:-1]).decode()))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            P2wpkhV0Script.unhexlify('0114{}'.format(hexlify(self.pubkh).decode()))


class TestP2sh(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.redeem_script = P2pkhScript(PublicKey.unhexlify('0384478d41e71dc6c3f9edde0f928a47d1b724c'
                                                             '05984ebfb4e7d0422e80abe95ff'))
        self.as_data = StackData.from_bytes(self.redeem_script.p2sh_hash())
        self.address = self.redeem_script.to_address()

    def test_success_hash(self):
        script = P2shScript(self.redeem_script.p2sh_hash())
        self.assertTrue(script.decompile() ==
                        'OP_HASH160 {} OP_EQUAL'.format(self.as_data))
        self.assertTrue(script.hexlify() == 'a9{:02x}{}87'.format(len(self.as_data), self.as_data))

    def test_success_redeem(self):
        script = P2shScript(self.redeem_script)
        self.assertTrue(script.decompile() ==
                        'OP_HASH160 {} OP_EQUAL'.format(self.as_data))
        self.assertTrue(script.hexlify() == 'a9{:02x}{}87'.format(len(self.as_data), self.as_data))

    def test_success_addresses(self):

        for script_hex, address in p2sh.items():
            script = ScriptBuilder.identify(bytearray(unhexlify(script_hex)))
            from_addr = P2shScript(Address.from_string(address))
            from_script = P2shScript(script)
            self.assertTrue(str(from_addr.address()) == address)
            self.assertTrue(str(script.to_address()) == address)
            self.assertTrue(str(from_script.address()) == address)

        script = P2shScript(self.address)
        self.assertTrue(script.decompile() ==
                        'OP_HASH160 {} OP_EQUAL'.format(self.as_data))
        self.assertTrue(script.hexlify() == 'a9{:02x}{}87'.format(len(self.as_data), self.as_data))

    def test_matching_fail_leftover(self):
        with self.assertRaises(WrongScriptTypeException):
            P2shScript(Script('a9{:02x}{}87ac'.format(len(self.as_data), self.as_data)))

    def test_matching_fail_long_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2shScript.unhexlify('a9{:02x}{}aa87'.format(len(self.as_data)+1, self.as_data))

    def test_matching_fail_short_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2shScript.unhexlify('a9{:02x}{}87'.format(len(self.as_data)-1, str(self.as_data)[:-2]))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            P2shScript.unhexlify('a9{:02x}{}88'.format(len(self.as_data), self.as_data))


class TestP2wsh(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.redeem_script = P2pkhScript(PublicKey.unhexlify('0384478d41e71dc6c3f9edde0f928a47d1b724c'
                                                             '05984ebfb4e7d0422e80abe95ff'))
        self.as_data = StackData.from_bytes(self.redeem_script.p2wsh_hash())

    def test_success_hash(self):
        script = P2wshV0Script(self.redeem_script.p2wsh_hash())
        self.assertTrue(script.decompile() ==
                        'OP_0 {}'.format(self.as_data))
        self.assertTrue(script.hexlify() == '00{:02x}{}'.format(len(self.as_data), self.as_data))

    def test_success_redeem(self):
        script = P2wshV0Script(self.redeem_script)
        self.assertTrue(script.decompile() ==
                        'OP_0 {}'.format(self.as_data))
        self.assertTrue(script.hexlify() == '00{:02x}{}'.format(len(self.as_data), self.as_data))

    def test_matching_fail_leftover(self):
        with self.assertRaises(WrongScriptTypeException):
            P2wshV0Script.unhexlify('00{:02x}{}aa'.format(len(self.as_data), self.as_data))

    def test_matching_fail_long_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2wshV0Script.unhexlify('00{:02x}{}aa'.format(len(self.as_data) + 1, self.as_data))

    def test_matching_fail_short_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2wshV0Script.unhexlify('00{:02x}{}'.format(len(self.as_data) - 1, str(self.as_data)[:-2]))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            P2wshV0Script.unhexlify('01{:02x}{}'.format(len(self.as_data), self.as_data))


class TestNulldata(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = StackData.unhexlify('c97232cda052b9e9c312af692c310e4061dcf937910a335bdb96865a0fb9469b0622c6fa')

    def test_success(self):
        script = NulldataScript(self.data)
        self.assertTrue(script.decompile() ==
                        'OP_RETURN {}'.format(self.data))
        self.assertTrue(script.hexlify() == '6a{:02x}{}'.format(len(self.data), self.data))

    def test_matching_fail_leftover(self):
        with self.assertRaises(WrongScriptTypeException):
            P2shScript.unhexlify('a9{:02x}{}aa'.format(len(self.data), self.data))

    def test_matching_fail_long_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2shScript.unhexlify('a9{:02x}{}aa'.format(len(self.data)+1, self.data))

    def test_matching_fail_short_push(self):
        with self.assertRaises(WrongScriptTypeException):
            P2shScript.unhexlify('a9{:02x}{}'.format(len(self.data)-1, str(self.data)[:-2]))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            P2shScript.unhexlify('a8{:02x}{}'.format(len(self.data), self.data))


class TestMultisig(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.m = 2
        self.pubkeys = [PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bfad09a89e211aeb926242"),
                        PublicKey.unhexlify("033e81519ecf373ea3a5c7e1c051b71a898fb3438c9550e274d980f147eb4d069d"),
                        PublicKey.unhexlify("036d568125a969dc78b963b494fa7ed5f20ee9c2f2fc2c57f86c5df63089f2ed3a")]
        self.n = 3
        self.hex_template = '{:02x}{}{:02x}ae'.format(self.m + 80,
                                                      ''.join('{:02x}{}'.format(len(pk), pk) for pk in self.pubkeys),
                                                      self.n + 80)

    def test_success(self):
        script = MultisigScript(self.m, *(self.pubkeys + [self.n]))
        expected = 'OP_{} {} OP_{} OP_CHECKMULTISIG'.format(self.m, ' '.join(str(pk) for pk in self.pubkeys), self.n)
        self.assertTrue(script.decompile() == expected)
        self.assertTrue(script.hexlify() == self.hex_template)

    def test_matching_fail_leftover(self):
        with self.assertRaises(WrongScriptTypeException):
            MultisigScript.unhexlify(self.hex_template+'aa')

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            MultisigScript.unhexlify(self.hex_template[:-2]+'aa')


class TestIf(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inner_script = MultisigScript(2,
                                           PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bfad09a89e2"
                                                               "11aeb926242"),
                                           PublicKey.unhexlify("033e81519ecf373ea3a5c7e1c051b71a898fb3438c9550e274d980f"
                                                               "147eb4d069d"),
                                           PublicKey.unhexlify("036d568125a969dc78b963b494fa7ed5f20ee9c2f2fc2c57f86c5df"
                                                               "63089f2ed3a"),
                                           3)


class TestIfElse(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.if_script = MultisigScript(2,
                                        PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bfad09a89e2"
                                                            "11aeb926242"),
                                        PublicKey.unhexlify("033e81519ecf373ea3a5c7e1c051b71a898fb3438c9550e274d980f"
                                                            "147eb4d069d"),
                                        PublicKey.unhexlify("036d568125a969dc78b963b494fa7ed5f20ee9c2f2fc2c57f86c5df"
                                                            "63089f2ed3a"),
                                        3)
        self.else_script = P2shScript(P2pkhScript(PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bf"
                                                                      "ad09a89e211aeb926242")))

    def test_success(self):
        script = IfElseScript(self.if_script, self.else_script)
        self.assertTrue(script.decompile() ==
                        'OP_IF {} OP_ELSE {} OP_ENDIF'.format(self.if_script.decompile(), self.else_script.decompile()))
        self.assertTrue(script.hexlify() == '63{}67{}68'.format(self.if_script.hexlify(), self.else_script.hexlify()))

    def test_matching_fail_leftover(self):
        with self.assertRaises(WrongScriptTypeException):
            IfElseScript.unhexlify('63{}67{}68aa'.format(self.if_script.hexlify(), self.else_script.hexlify()))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            IfElseScript.unhexlify('63{}aa{}68'.format(self.if_script.hexlify(), self.else_script.hexlify()))


class TestTimelock(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.locktime = 500000
        self.locked_script = P2shScript(P2pkhScript(PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bf"
                                                                        "ad09a89e211aeb926242")))

    def test_success(self):
        script = TimelockScript(Locktime(self.locktime), self.locked_script)
        self.assertTrue(script.decompile() ==
                        '{} OP_CHECKLOCKTIMEVERIFY OP_DROP {}'.format(Locktime(self.locktime).for_script(),
                                                                      self.locked_script.decompile()))
        self.assertTrue(script.hexlify() == '{}b175{}'.format(Locktime(self.locktime).for_script().hexlify(),
                                                              self.locked_script.hexlify()))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            TimelockScript.unhexlify('{}b1aa{}'.format(Locktime(self.locktime).for_script().hexlify(),
                                                       self.locked_script.hexlify()))


class TestRelativeTimelock(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sequence = 500000
        self.locked_script = P2shScript(P2pkhScript(PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bf"
                                                                        "ad09a89e211aeb926242")))

    def test_success(self):
        script = RelativeTimelockScript(Sequence(self.sequence), self.locked_script)
        self.assertTrue(script.decompile() ==
                        '{} OP_CHECKSEQUENCEVERIFY OP_DROP {}'.format(Sequence(self.sequence).for_script(),
                                                                      self.locked_script.decompile()))
        self.assertTrue(script.hexlify() == '{}b275{}'.format(Sequence(self.sequence).for_script().hexlify(),
                                                              self.locked_script.hexlify()))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            RelativeTimelockScript.unhexlify('{}b2aa{}'.format(Sequence(self.sequence).for_script().hexlify(),
                                                               self.locked_script.hexlify()))


class TestHashlock(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hash = PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bfad09a89e211aeb926242").hash()
        self.locked_script = P2shScript(P2pkhScript(PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bf"
                                                                        "ad09a89e211aeb926242")))

    def test_success(self):
        script = Hashlock256Script(StackData.from_bytes(self.hash), self.locked_script)
        self.assertTrue(script.decompile() ==
                        'OP_HASH256 {} OP_EQUALVERIFY {}'.format(hexlify(self.hash).decode(),
                                                                 self.locked_script.decompile()))
        self.assertTrue(script.hexlify() == 'aa{:02x}{}88{}'.format(len(self.hash),
                                                                    hexlify(self.hash).decode(),
                                                                    self.locked_script.hexlify()))

    def test_matching_fail_wrong_op(self):
        with self.assertRaises(WrongScriptTypeException):
            Hashlock256Script.unhexlify('{:02x}{}a8aa{}'.format(len(self.hash),
                                                                hexlify(self.hash).decode(),
                                                                self.locked_script.hexlify()))


class TestAddress(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.good_addresses = {('mainnet', 'p2pkh', '1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa',
                                b'\xc8\xe9\t\x96\xc7\xc6\x08\x0e\xe0b\x84`\x0chN\xd9\x04\xd1L\\'),
                               ('testnet', 'p2pkh', 'mtH6FLMQNu2fFQ4mrb7UjEUjTAhUNCMFoi',
                                b'\x8b\xfas]\x98\xabb\x1e\xdbOw\xd7\xb7\xfe\nK\x1f\xfc\xc0$'),
                               ('testnet', 'p2pkh', 'n3wEvhujG7SDcgeKCXZMrty5QqhQZ7f6jW',
                                b'\xf5\xea\xa2K\x82\xc8\x1f4L\x9a\x16\xa8\xfb\x84t\xe1\x10\xfd\xb1\xc3'),
                               ('mainnet', 'p2sh', '3P14159f73E4gFr7JterCCQh9QjiTjiZrG',
                                b'\xe9\xc3\xdd\x0c\x07\xaa\xc7ay\xeb\xc7jlx\xd4\xd6|l\x16\n'),
                               ('testnet', 'p2sh', '2N6JFaB5rMtPwutovP6cirwBVxHuAVaHvMG',
                                b'\x8f,4\xa2<F\xe9\x80\xb7\x9e\x10\x9b\x11\xa2\xc8-9\x92\xeb\x95')}
        self.bad_addresses = {'vioqwV3F4YzpgnfyUukGVMB3Hv83ujehKCiGWyrYyx2Z7hiKQy7SWUV9KgfMdV9J',
                              'bc1a',
                              '3rE3tz',
                              '1KKKK6N21XKo48zWKuuKXdvSsCf95ibHFa'}

    def test_success(self):
        for net, addr_type, address, hashed_data in self.good_addresses:
            from_string = Address.from_string(address, check_network=False)
            self.assertTrue(address == str(from_string))
            self.assertTrue(from_string.type == addr_type)
            self.assertTrue(from_string.network == net)
            self.assertTrue(from_string.hash == hashed_data)

    def test_fail(self):
        for address in self.bad_addresses:
            with self.assertRaises(ValueError):
                Address.from_string(address, check_network=False)

    def test_conversions(self):
        for address, pkh in addresses:
            self.assertEqual(hexlify(Address.from_string(address, check_network=False).hash).decode(), pkh)
            self.assertEqual(str(P2pkhScript(bytearray(unhexlify(pkh))).address(mainnet=True)), address)
            self.assertEqual(P2pkhScript(Address.from_string(address, check_network=False)).pubkeyhash,
                             bytearray(unhexlify(pkh)))
            self.assertEqual(Address('p2pkh', bytearray(unhexlify(pkh)), mainnet=True).hash, bytearray(unhexlify(pkh)))


class TestStandardness(unittest.TestCase):

    def test_script_pubkey_success(self):
        # standard types
        self.assertTrue(eval(scripts['p2sh']['code']).is_standard())
        self.assertTrue(eval(scripts['p2pkh']['code']).is_standard())
        self.assertTrue(eval(scripts['p2pk']['code']).is_standard())
        self.assertTrue(eval(scripts['multisig']['code']).is_standard())
        self.assertTrue(eval(scripts['nulldata']['code']).is_standard())
        self.assertTrue(eval(scripts['p2wpkh']['code']).is_standard())
        self.assertTrue(eval(scripts['p2wsh']['code']).is_standard())

    def test_script_pubkey_fail(self):
        # nonstandard types
        self.assertFalse(eval(scripts['if_else_timelock']['code']).is_standard())
        self.assertFalse(eval(scripts['relativetimelock']['code']).is_standard())
        # n > 3
        self.assertFalse(
            MultisigScript(
                2,
                PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bfad09a89e211aeb926242"),
                PublicKey.unhexlify("033e81519ecf373ea3a5c7e1c051b71a898fb3438c9550e274d980f147eb4d069d"),
                PublicKey.unhexlify("036d568125a969dc78b963b494fa7ed5f20ee9c2f2fc2c57f86c5df63089f2ed3a"),
                PublicKey.unhexlify("036d568125a969dc78b963b494fa7ed5f20ee9c2f2fc2c57f86c5df63089f2ed3a"),
                4
            ).is_standard()
        )
        # m > n
        self.assertFalse(
            MultisigScript(
                4,
                PublicKey.unhexlify("02c08786d63f78bd0a6777ffe9c978cf5899756cfc32bfad09a89e211aeb926242"),
                PublicKey.unhexlify("033e81519ecf373ea3a5c7e1c051b71a898fb3438c9550e274d980f147eb4d069d"),
                PublicKey.unhexlify("036d568125a969dc78b963b494fa7ed5f20ee9c2f2fc2c57f86c5df63089f2ed3a"),
                3
            ).is_standard()
        )
        # >80-byte data
        self.assertFalse(NulldataScript(StackData.unhexlify(
            '444f4350524f4f463832bd18ceb0a7861f2a8198013047a3fb861261523c0fc4164abc044e517702444f4350524f4f463832bd18ce'
            'b0a7861f2a8198013047a3fb861261523c0fc4164abc044e51770211')).is_standard())

    def test_txin_success(self):
        # coinbase txin
        txin = Transaction.unhexlify('01000000010000000000000000000000000000000000000000000000000000000000000000'
                                     'ffffffff3d039920071c2f706f6f6c2e626974636f696e2e636f6d2f4249503130302f4238'
                                     '2f0a092f4542312f4144362f109c52640027ed852ba74c0741c3eb0100ffffffff01505266'
                                     '53000000001976a9143fa71ed2e38d431960f314e7e7aad476a5496b4c88ac00000000').ins[0]
        self.assertTrue(txin.is_standard())
        txin = Transaction.unhexlify('0100000001e4da173fbefe5e60ff63dfd38566ade407532294db655463b77a783f379ce6050000000'
                                     '06b483045022100af246c27890c2bc07a0b7450d3d82509702a44a4defdff766355240b114ee2ac02'
                                     '207bb67b468452fa1b325dd5583879f5c1412e0bb4dae1c2c96c7a408796ab76f1012102ab9e85755'
                                     '36a1e99604a158fc60fe2ebd1cb1839e919b4ca42b8d050cfad71b2ffffffff0100c2eb0b00000000'
                                     '1976a914df76c017354ac39bde796abe4294d31de8b5788a88ac00000000').ins[0]
        self.assertTrue(txin.is_standard())

        # actual redeem script (15 sigops: 14 OP_CHECKMULTISIGVERIFY + OP_CHECKSIG)
        script_sig = ScriptSig(bytearray(b'F0C\x02\x1f\x19\xeewU\xa5w\xd8G\x03\x8f;2K\x8b\xfb\xc4 \x006"\xe73\xa9'
                                         b'\x953\x88:,!\xc2\x16\x02 \x1asWN\x01\xb6fw\xc7\r\x93\x0c|\x19\x182W\x04'
                                         b'\xb0\xe6\xd0.\x92\xe6\xb0\xcdk\xc2\xf0n\r\x8e\x01(\x00c^\xafh!\x02\xae'
                                         b'p6\xec\xd9\xda\xc4\xef)\xff\x0b1\x03\xc1\xa8\xfb[\xa0\xbe=\xed\xf65\xd6'
                                         b'\xfa\xa6\x1f\x06K\xef\x07\xff\xac'))
        prev_script = P2shScript(bytearray(b'\xa9\x14\x00H\xee[\x92\xbc\xc9kx\xa0W\x1e\xdch\x14`\xe8B`\xa5\x87'))
        txin = TxIn('4a0884b0aa0c3d34a81ea747aca1368effd9359d573f79873d2d6b4045e49205',
                    9,
                    script_sig,
                    0xffffffff)
        self.assertTrue(txin.is_standard(prev_script))

        # 14 sigops redeem script
        script_sig = ScriptSig(bytearray(b'F0C\x02\x1f\x19\xeewU\xa5w\xd8G\x03\x8f;2K\x8b\xfb\xc4 \x006"\xe73\xa9'
                                         b'\x953\x88:,!\xc2\x16\x02 \x1asWN\x01\xb6fw\xc7\r\x93\x0c|\x19\x182W\x04'
                                         b'\xb0\xe6\xd0.\x92\xe6\xb0\xcdk\xc2\xf0n\r\x8e\x01(\x00c^\xafh!\x02\xae'
                                         b'p6\xec\xd9\xda\xc4\xef)\xff\x0b1\x03\xc1\xa8\xfb[\xa0\xbe=\xed\xf65\xd6'
                                         b'\xfa\xa6\x1f\x06K\xef\x07\xff\xac'))
        prev_script = P2shScript(bytearray(b'\xa9\x14\x00H\xee[\x92\xbc\xc9kx\xa0W\x1e\xdch\x14`\xe8B`\xa5\x87'))
        txin = TxIn('4a0884b0aa0c3d34a81ea747aca1368effd9359d573f79873d2d6b4045e49205',
                    9,
                    script_sig,
                    0xffffffff)
        self.assertTrue(txin.is_standard(prev_script))

    def test_txin_fail(self):
        # redeem script with 16 sigops (same as above + b'\xac')
        script_sig = ScriptSig(bytearray(b'F0C\x02\x1f\x19\xeewU\xa5w\xd8G\x03\x8f;2K\x8b\xfb\xc4 \x006"\xe73\xa9'
                                         b'\x953\x88:,!\xc2\x16\x02 \x1asWN\x01\xb6fw\xc7\r\x93\x0c|\x19\x182W\x04'
                                         b'\xb0\xe6\xd0.\x92\xe6\xb0\xcdk\xc2\xf0n\r\x8e\x01(\x00c^\xafh!\x02\xae'
                                         b'p6\xec\xd9\xda\xc4\xef)\xff\x0b1\x03\xc1\xa8\xfb[\xa0\xbe=\xed\xf65\xd6'
                                         b'\xfa\xa6\x1f\x06K\xef\x07\xff\xac' + b'\xac'))
        prev_script = P2shScript(bytearray(b'\xa9\x14\x00H\xee[\x92\xbc\xc9kx\xa0W\x1e\xdch\x14`\xe8B`\xa5\x87'))
        txin = TxIn('4a0884b0aa0c3d34a81ea747aca1368effd9359d573f79873d2d6b4045e49205',
                    9,
                    script_sig,
                    0xffffffff)
        self.assertFalse(txin.is_standard(prev_script))

        # nonstandard prev_script
        script_sig = ScriptSig(bytearray(b'F0C\x02\x1f\x19\xeewU\xa5w\xd8G\x03\x8f;2K\x8b\xfb\xc4 \x006"\xe73\xa9'
                                         b'\x953\x88:,!\xc2\x16\x02 \x1asWN\x01\xb6fw\xc7\r\x93\x0c|\x19\x182W\x04'
                                         b'\xb0\xe6\xd0.\x92\xe6\xb0\xcdk\xc2\xf0n\r\x8e\x01(\x00c^\xafh!\x02\xae'
                                         b'p6\xec\xd9\xda\xc4\xef)\xff\x0b1\x03\xc1\xa8\xfb[\xa0\xbe=\xed\xf65\xd6'
                                         b'\xfa\xa6\x1f\x06K\xef\x07\xff\xac'))
        prev_script = UnknownScript('\xac')
        txin = TxIn('4a0884b0aa0c3d34a81ea747aca1368effd9359d573f79873d2d6b4045e49205',
                    9,
                    script_sig,
                    0xffffffff)
        self.assertFalse(txin.is_standard(prev_script))

    def test_tx_success(self):
        pass

    def test_tx_fail(self):
        pass

    def test_witness_success(self):
        pass

    def test_witness_fail(self):
        pass


class TestSegwitSigs(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = segsig

    def test_hash_prevouts(self):
        for tx in self.data:
            unsigned = SegWitTransaction.unhexlify(tx['unsigned_tx'])
            self.assertEqual(unsigned._hash_prevouts(), bytearray(unhexlify(tx['hash_prevouts'])))

    def test_hash_sequence(self):
        for tx in self.data:
            unsigned = SegWitTransaction.unhexlify(tx['unsigned_tx'])
            self.assertEqual(unsigned._hash_sequence(), bytearray(unhexlify(tx['hash_sequence'])))

    def test_hash_outputs(self):
        for tx in self.data:
            unsigned = SegWitTransaction.unhexlify(tx['unsigned_tx'])
            self.assertEqual(unsigned._hash_outputs(), bytearray(unhexlify(tx['hash_outputs'])))

    def test_digest_preimage(self):
        for tx in self.data:
            unsigned = SegWitTransaction.unhexlify(tx['unsigned_tx'])
            for j, txin in enumerate(tx['txins']):
                if 'digest_preimage' in txin:
                    self.assertEqual(unsigned._get_segwit_digest_preimage(j,
                                                                          ScriptBuilder.identify(txin['prev_script']),
                                                                          txin['prev_amount']).hexlify(),
                                     txin['digest_preimage'])

    def test_digest(self):
        for tx in self.data:
            unsigned = SegWitTransaction.unhexlify(tx['unsigned_tx'])
            for j, txin in enumerate(tx['txins']):
                if 'digest' in txin:
                    self.assertEqual(hexlify(unsigned.get_segwit_digest(j,
                                                                        ScriptBuilder.identify(txin['prev_script']),
                                                                        txin['prev_amount'])).decode(),
                                     txin['digest'])

    def test_sig(self):
        for tx in self.data:
            if 'signature' in tx:
                for txin in tx['txins']:
                    if 'privk' in txin and 'digest' in txin:
                        self.assertEqual(hexlify(PrivateKey.unhexlify(txin['privk']).sign(bytearray(unhexlify(txin['digest'])),
                                                                                          deterministic=True)).decode(),
                                         tx['signature'])


if __name__ == '__main__':
    unittest.main()
