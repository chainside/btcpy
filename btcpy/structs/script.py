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

import json
import hashlib
from hashlib import sha256
from binascii import hexlify, unhexlify
from abc import ABCMeta, abstractmethod

from ..lib.types import HexSerializable, Immutable, cached
from ..lib.parsing import ScriptParser, Parser, Stream, UnexpectedOperationFound
from ..lib.opcodes import OpCodeConverter
from .crypto import WrongPubKeyFormat
from .address import Address, SegWitAddress


class WrongScriptTypeException(Exception):
    pass


class WrongPushDataOp(Exception):
    pass


# noinspection PyUnresolvedReferences
class StackData(Immutable, HexSerializable):
    """
    Represents data pushed on the stack. This class has commodity methods to get the length in bytes of the data
    and the push operation needed in a script to push those data on the stack
    """

    max_size = 2**32

    @classmethod
    def zero(cls):
        return cls(bytearray([0]))

    @classmethod
    def unhexlify(cls, hexa):
        return cls.from_bytes(bytearray(unhexlify(hexa)))

    @classmethod
    def from_bytes(cls, bytes_):
        data_len = len(bytes_)

        if data_len == 0:
            return cls.zero()

        if data_len == 1:
            if bytes_[0] == 0:
                raise ValueError('Trying to push byte 0x00 with a literal byte instead of empty array')
            if 1 <= bytes_[0] <= 16:
                return cls(bytearray([80 + bytes_[0]]))

        # this should execute when data_len == 1 and it
        # does not fall in the previous conditions
        if data_len <= 75:
            return cls(bytearray([data_len]), bytes_)
        else:
            if data_len <= 0xff:
                size = 1
            elif data_len <= 0xffff:
                size = 2
            elif data_len <= 0xffffffff:
                size = 4
            else:
                raise ValueError('Data length too big to push: {} bytes'.format(data_len))
            return cls(bytearray([OpCodeConverter.to_int('OP_PUSHDATA{}'.format(size))])
                       + bytearray(data_len.to_bytes(size, 'little')),
                       bytes_)

    @classmethod
    def from_int(cls, integer):
        from math import ceil
        if integer == 0:
            return cls.zero()
        if integer == -1:
            return cls(bytearray([0x4f]))
        sign = True if integer < 0 else False
        absolute = bytearray(abs(integer).to_bytes(ceil(abs(integer).bit_length() / 8), 'little'))
        if absolute[-1] & (1 << 7):
            # using all the bits: need to add a whole byte for the sign
            absolute.append((1 << 7) if sign else 0)
        else:
            absolute[-1] |= (1 << 7) if sign else 0
        return cls.from_bytes(absolute)

    @classmethod
    def from_push_op(cls, parser, push_op):
        try:

            if push_op == 0:
                return cls.zero()

            if 1 <= push_op <= 75:
                return cls(bytearray([push_op]), parser >> push_op)

            if 76 <= push_op <= 78:
                push_size_in_bytes = parser >> 2**(push_op - 76)  # 1, 2 or 4 depending on the push op
                push_size = int.from_bytes(push_size_in_bytes, 'little')
                return cls(bytearray([push_op]) + push_size_in_bytes, parser >> push_size)

            if 79 <= push_op <= 96:
                if push_op == 80:
                    raise UnexpectedOperationFound('Trying to use OP_RESERVED (0x50) as a push operation')
                return cls(bytearray([push_op]))

            raise UnexpectedOperationFound('Invalid push operation: {}'.format(push_op))

        except StopIteration:
            raise WrongPushDataOp('Reached end of script while parsing pushdata operation')

    @staticmethod
    def check_op(push_op, data):

        if len(data) > StackData.max_size:
            raise WrongPushDataOp('Trying to create StackData with size: {}'.format(len(data)))

        if not push_op:
            raise WrongPushDataOp('Empty bytearray is not a valid push operation')

        if len(push_op) == 1:
            # one-byte push op
            if 1 <= push_op[0] <= 75:
                # push op must equal len(data)
                if push_op[0] != len(data):
                    raise WrongPushDataOp('Push op does not match data length: {}, {}'.format(push_op, len(data)))
            elif 79 <= push_op[0] <= 96 or push_op[0] == 0:
                # TODO understand whether this breaks consensus rules!
                if push_op[0] == 80:
                    raise WrongPushDataOp('Trying to use OP_RESERVED (0x50) as a push operation')
                # pushing data between 0 and 16, no further data required
                if data:
                    raise WrongPushDataOp('Push op is OP_{} but some data was provided: {}'
                                          .format(0 if push_op[0] == 0 else push_op[0] - 80, data))
            else:
                raise WrongPushDataOp('One-byte push operation not recognized: {}'.format(push_op[0]))
        elif 76 <= push_op[0] <= 78:
            n = 1 + 2**(push_op[0] - 76)  # number of bytes required for the push op
            if len(push_op) != n:
                raise WrongPushDataOp('We need {} bytes for PUSHDATA{}, found {}'.format(n, n-1, len(push_op)))
            if int.from_bytes(push_op[1:n], 'little') != len(data):
                raise WrongPushDataOp('Push op does not match data length: {}, {}'.format(push_op, len(data)))
        else:
            raise WrongPushDataOp('Push operation not recognized: {}'.format(push_op))

    def __init__(self, push_op, data=None):
        """
        :param push_op: a bytearray representing a push operation
        :param data: a bytearray of stack data
        """
        if data is None:
            data = bytearray()

        StackData.check_op(push_op, data)

        object.__setattr__(self, 'push_op', push_op)
        object.__setattr__(self, 'data', bytearray(data))

    def __str__(self):
        if not self.data:
            if self.push_op[0] == 0:
                return ''
            else:
                return OpCodeConverter.from_int(self.push_op[0])
        return hexlify(self.data).decode()

    def __len__(self):
        if not self.data:
            # OP_0 to OP_16
            return 1
        return len(self.data)

    def __int__(self):

        if self.push_op[0] == 0:
            return 0

        if 79 <= self.push_op[0] <= 96:
            return self.push_op[0] - 80

        sign = bool(self.data[-1] & (1 << 7))  # store sign
        first_byte = self.data[-1] & ~(1 << 7)  # remove sign
        absolute = int.from_bytes(self.data[:-1] + bytearray([first_byte]), 'little')
        return absolute * (-1 if sign else 1)

    def to_push_op(self):
        return self.push_op + self.data

    @cached
    def serialize(self):
        if self.data:
            return Parser.to_varint(len(self)) + self.data
        else:
            if self.push_op[0] == 0:
                return Parser.to_varint(0) + bytearray()
            else:
                if self.push_op[0] in (79, 80):
                    return Parser.to_varint(1) + bytearray([(self.push_op[0])])
                else:
                    return Parser.to_varint(1) + bytearray([(self.push_op[0] - 80)])


# noinspection PyUnresolvedReferences
class BaseScript(Immutable, HexSerializable, metaclass=ABCMeta):

    # noinspection PyMethodOverriding
    @classmethod
    def from_json(cls, string):
        dic = json.loads(string)
        return cls(dic['hex'])

    @classmethod
    def unhexlify(cls, hex_string):
        return cls(Script(bytearray(unhexlify(hex_string))))

    @staticmethod
    def compile(string):
        result = Stream()
        opcodes = string.split(' ')
        for opcode in opcodes:
            try:
                result << OpCodeConverter.to_int(opcode)
            except ValueError:
                result << StackData.unhexlify(opcode).to_push_op()
        return result.serialize()

    def __init__(self, bytes_):
        object.__setattr__(self, 'body', bytes_)

    def __len__(self):
        return len(self.body)

    def __str__(self):
        return self.decompile()

    def __add__(self, other):
        return UnknownScript(self.body + other.body)

    def __eq__(self, other):
        return self.body == other.body

    def serialize(self):
        return self.body

    def __iter__(self):
        return iter(self.decompile().split())

    @cached
    def decompile(self):
        opcodes = []

        parser = ScriptParser(self.body)

        while parser:
            op = next(parser)
            if 1 <= op <= 78:  # pushdata
                opcodes.append(parser.get_push(op))
            else:
                try:
                    opcodes.append(OpCodeConverter.from_int(op))
                except ValueError:
                    raise ValueError('Invalid opcode {} in script {}'.format(op, self.hexlify()))

        return ' '.join(str(opcode) for opcode in opcodes)

    def is_standard(self):
        pass

    @cached
    def get_sigop_count(self):
        sigops = 0
        lastop = None
        for op in self:
            if op in {'OP_CHECKSIG', 'OP_CHECKSIGVERIFY'}:
                sigops += 1
            elif op in {'OP_CHECKMULTISIG', 'OP_CHECKMULTISIGVERIFY'}:
                if lastop is None:
                    # OP_CHECKMULTISIG(VERIFY) is the first op of the script. This means the script is invalid
                    return 0
                if OpCodeConverter.to_int('OP_1') <= OpCodeConverter.to_int(lastop) <= OpCodeConverter.to_int('OP_16'):
                    sigops += OpCodeConverter.to_int(lastop) - 80
            lastop = op
        return sigops

    @property
    @abstractmethod
    def type(self):
        raise NotImplemented

    @cached
    def is_push_only(self):
        for op in self:
            try:
                if OpCodeConverter.to_int(op) > OpCodeConverter.to_int('OP_16'):
                    return False
            except ValueError:
                continue
        return True

    @cached
    def get_data(self):
        parser = ScriptParser(self.body)
        data = []
        while True:
            try:
                data.append(parser.get_push())
            except UnexpectedOperationFound:
                pass
            except StopIteration:
                break
        return data


class Script(BaseScript):

    @property
    def type(self):
        return 'Script'


class ScriptSig(BaseScript):

    @staticmethod
    def empty():
        return ScriptSig(bytearray())

    @staticmethod
    def from_stack_data(stack_data):
        return ScriptSig(bytearray([byte_ for item in stack_data for byte_ in item.to_push_op()]))

    @cached
    def to_json(self):
        return {'asm': str(self),
                'hex': self.hexlify()}

    def is_standard(self, spends_p2sh=False):

        if len(self) > 1650:
            return False

        if not self.is_push_only():
            return False

        if spends_p2sh:
            redeem_script = ScriptBuilder.identify(self.get_data()[-1].data)
            if redeem_script.get_sigop_count() > 15:
                return False

        return True

    @cached
    def to_witness(self):
        from .transaction import Witness
        return Witness(self.get_data())

    @property
    def type(self):
        return 'scriptSig'


class CoinBaseScriptSig(ScriptSig):

    def is_standard(self, *args, **kwargs):
        if len(self) > 1650:
            return False
        return True

    def to_json(self):
        return {'hex': self.hexlify()}


# noinspection PyUnresolvedReferences
class ScriptPubKey(BaseScript, metaclass=ABCMeta):
    """
    Subclasses must either redefine `template` or reimplement their own `verify()` static method.
    They also must implement the `type` property.
    """
    template = None

    @classmethod
    def verify(cls, bytes_):
        parser = ScriptParser(bytes_)
        if not bytes_:
            raise WrongScriptTypeException('Empty script')
        try:
            args = [data for data in parser.match(cls.template)]
        except UnexpectedOperationFound as exc:
            # print(exc)
            raise WrongScriptTypeException(str(exc))
        if len(args) == 1:
            return args[0]
        return args

    @staticmethod
    def empty():
        return ScriptPubKey(bytearray())

    def to_json(self):
        result = {'asm': str(self),
                  'hex': self.hexlify(),
                  'type': self.type}
        if self.address() is not None:
            result['address'] = str(self.address())
        return result

    @property
    def type(self):
        return 'scriptPubKey'

    @cached
    def p2sh_hash(self):
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(self.body).digest())
        return bytearray(ripemd160.digest())

    @cached
    def p2wsh_hash(self):
        return bytearray(sha256(self.body).digest())

    @cached
    def to_stack_data(self):
        return StackData.from_bytes(self.serialize())

    def to_address(self, segwit_version=None):
        if segwit_version is not None:
            return SegWitAddress('p2wsh', self.p2wsh_hash(), segwit_version)
        else:
            return Address('p2sh', self.p2sh_hash())

    def is_standard(self):
        """Subclasses which have standard types should reimplement this method"""
        return False

    def address(self):
        """Subclasses which have a meaningful concept of address should reimplement this. For the moment
        we consider to have a meaningful address only for the following types: P2pkh, P2sh, P2wpkh, P2wsh"""
        return None


# noinspection PyUnresolvedReferences
class P2pkhScript(ScriptPubKey):

    template = 'OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG'

    compile_fmt = 'OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG'

    def __init__(self, param):
        """
        :param param: can be either of type `Script`, `PublicKey`, `Address` or `bytearray`.
        In the first case the script is verified and the public key hash is extracted.
        In the second case the script is built hashing the public key.
        In the third case, the script is built extracting the pubkeyhash from the address
        In the fourth case, the script is built from the public key hash (represented by the bytearray)
        """
        from .crypto import PublicKey
        if isinstance(param, Script):
            object.__setattr__(self, 'pubkeyhash', self.verify(param.body).data)
            super().__init__(param.body)
            # note: if we do not return here, we are going to call super().__init__ twice
            return

        if isinstance(param, PublicKey):
            object.__setattr__(self, 'pubkeyhash', param.hash())
        elif isinstance(param, bytearray):
            object.__setattr__(self, 'pubkeyhash', param)
        elif isinstance(param, Address):
            if param.type != self.type:
                raise ValueError('Non-p2pkh address provided. Address type: {}'.format(param.type))
            object.__setattr__(self, 'pubkeyhash', param.hash)
        else:
            raise TypeError('Wrong type for P2pkhScript __init__: {}'.format(type(param)))

        super().__init__(self.compile(self.compile_fmt.format(hexlify(self.pubkeyhash).decode())))

    def __repr__(self):
        return "P2pkhScript('{}')".format(hexlify(self.pubkeyhash).decode())

    @property
    def type(self):
        return 'p2pkh'

    def address(self, mainnet=None):
        return Address('p2pkh', self.pubkeyhash, mainnet)

    def is_standard(self):
        return True


class P2wpkhV0Script(P2pkhScript):

    template = 'OP_0 <20>'

    compile_fmt = 'OP_0 {}'

    def __init__(self, param):
        if isinstance(param, SegWitAddress):
            if param.type != 'p2wpkh':
                raise ValueError('Non-p2wpkh address provided. Address type: {}'.format(param.type))
            else:
                param = param.hash

        super().__init__(param)

    def __repr__(self):
        return "P2wpkhScript('{}')".format(hexlify(self.pubkeyhash).decode())

    @property
    def type(self):
        return 'p2wpkhv0'

    def address(self, mainnet=None):
        return SegWitAddress('p2wpkh', self.pubkeyhash, 0)

    def get_scriptcode(self):
        return P2pkhScript(self.pubkeyhash).to_stack_data()


class P2wpkhScript(ScriptPubKey, metaclass=ABCMeta):

    versions = {0: P2wpkhV0Script}

    @classmethod
    def get(cls, segwit_version):
        return cls.versions[segwit_version]


# noinspection PyUnresolvedReferences
class P2shScript(ScriptPubKey):

    template = 'OP_HASH160 <20> OP_EQUAL'

    compile_fmt = 'OP_HASH160 {} OP_EQUAL'

    def __init__(self, param):
        """
        :param param: can be either of type `Script`, `ScriptPubKey`, `Address` or `bytearray`.
        In the first case, the script is verified and the hash of the redeem script is extracted.
        In the second case, the script is built by hashing the redeem script.
        In the third case, the script is built by base58 decoding the address
        In the fourth case, the script is built from the script hash (represented by the bytearray)
        """
        if isinstance(param, Script):
            object.__setattr__(self, 'scripthash', self.verify(param.body).data)
            super().__init__(param.body)
            # note: if we do not return here, we are going to call super().__init__ twice
            return

        if isinstance(param, ScriptPubKey):
            object.__setattr__(self, 'scripthash', param.p2sh_hash())
        elif isinstance(param, Address):
            if param.type != self.type:
                raise ValueError('Non-p2sh address provided. Address type: {}'.format(param.type))
            object.__setattr__(self, 'scripthash', param.hash)
        elif isinstance(param, bytearray):
            object.__setattr__(self, 'scripthash', param)
        else:
            raise TypeError('Wrong type for P2shScript __init__: {}'.format(type(param)))

        super().__init__(self.compile(self.compile_fmt.format(hexlify(self.scripthash).decode())))

    def __repr__(self):
        return "P2shScript('{}')".format(hexlify(self.scripthash).decode())

    @property
    def type(self):
        return 'p2sh'

    def is_standard(self):
        return True

    def address(self):
        return Address('p2sh', self.scripthash)

    def to_address(self, segwit_version=None):
        return self.address()


# noinspection PyUnresolvedReferences
class P2wshV0Script(P2shScript):

    template = 'OP_0 <32>'

    compile_fmt = 'OP_0 {}'

    def __init__(self, param):
        # segwit p2wsh have different hashing method than regular p2sh scripts!
        if isinstance(param, ScriptPubKey):
            param = param.p2wsh_hash()
        if isinstance(param, SegWitAddress):
            if param.type != 'p2wsh':
                raise ValueError('Non-p2wsh address provided. Address type: {}'.format(param.type))
            else:
                param = param.hash

        super().__init__(param)

    def __repr__(self):
        return "P2wshV0Script('{}')".format(hexlify(self.scripthash).decode())

    @property
    def type(self):
        return 'p2wshv0'

    def address(self):
        return SegWitAddress('p2wsh', self.scripthash, 0)

    def to_address(self, segwit_version=None):
        if segwit_version is not None:
            raise ValueError("Can't request p2wsh address of p2wsh script")
        return self.address()


class P2wshScript(ScriptPubKey, metaclass=ABCMeta):

    versions = {0: P2wshV0Script}

    @classmethod
    def get(cls, segwit_version):
        return cls.versions[segwit_version]


# noinspection PyUnresolvedReferences
class P2pkScript(ScriptPubKey):

    template = '<33|65> OP_CHECKSIG'

    def __init__(self, param):
        """
        :param param: can be either of type `Script` or `PublicKey`.
        In the first case it is verifyed and the public key is extracted.
        In the second case the script is built from the public key
        """
        from .crypto import PublicKey
        if isinstance(param, Script):
            object.__setattr__(self, 'pubkey', PublicKey(self.verify(param.body).data))
            super().__init__(param.body)
        elif isinstance(param, PublicKey):
            object.__setattr__(self, 'pubkey', param)
            super().__init__(self.compile('{} OP_CHECKSIG'.format(self.pubkey.hexlify())))
        else:
            raise TypeError('Wrong type for P2pkScript __init__: {}'.format(type(param)))

    def __repr__(self):
        return "P2pkScript('{}')".format(self.pubkey)

    @property
    def type(self):
        return 'p2pk'

    def is_standard(self):
        return True


# noinspection PyUnresolvedReferences
class NulldataScript(ScriptPubKey):

    template = 'OP_RETURN <1-83>'
    max_nulldata_data_size = 80

    def __init__(self, param):
        """
        :param param: can be either of type `Script` or `StackData`.
        In the first case the script is verified and the data is extracted.
        In the second case the script is built from the data provided.
        """
        if isinstance(param, Script):
            object.__setattr__(self, 'data', self.verify(param.body))
            super().__init__(param.body)
        elif isinstance(param, StackData):
            object.__setattr__(self, 'data', param)
            super().__init__(self.compile('OP_RETURN {}'.format(param)))
        else:
            raise TypeError('Wrong type for NulldataScript __init__: {}'.format(type(param)))

    def __repr__(self):
        return "NulldataScript('{}')".format(self.data.hexlify())

    @property
    def type(self):
        return 'nulldata'

    def is_standard(self):
        # 1-byte OP_RETURN + 2-byte pushdata + 80-byte data
        return len(self.data) <= self.max_nulldata_data_size and len(self.body) <= self.max_nulldata_data_size + 3


# noinspection PyUnresolvedReferences
class MultisigScript(ScriptPubKey):

    template = '<>+ OP_CHECKMULTISIG'

    def __init__(self, *args):
        """
        :param args: if one arg is provided that is interpreted as a precompiled script which needs
        verification to see if it belongs to this type. Once verification is done, `m`, a list of pubkeys
        and `n` are extracted and saved.
        If more than one arg is provided, we assume that the parameters are `m, pubkey1, ..., pubkeyn, n`.
        """
        from .crypto import PublicKey

        if len(args) == 0:
            raise TypeError('Wrong number of params for MultisigScript __init__: {}'.format(len(args)))
        if len(args) == 1:
            # we expect something of type Script
            script = args[0]
            super().__init__(script.body)
            m, *pubkeys, n = self.verify(script.body)
            m = int(m)
            pubkeys = [PublicKey(pk.data) for pk in pubkeys]
            n = int(n)
        else:
            m, *pubkeys, n = args

        if n != len(pubkeys):
            raise ValueError('Pushed {} keys but n is {}'.format(len(pubkeys), n))

        object.__setattr__(self, 'm', m)
        object.__setattr__(self, 'pubkeys', pubkeys)
        object.__setattr__(self, 'n', n)

        if len(args) != 1:
            # in this case we haven't called super().__init__() yet
            super().__init__(self.compile('{} {} {} '
                                          'OP_CHECKMULTISIG'.format(StackData.from_int(self.m),
                                                                    ' '.join([pubk.hexlify() for pubk in self.pubkeys]),
                                                                    StackData.from_int(len(self.pubkeys)))))

    def __repr__(self):
        return "MultisigScript('{}', {}, '{}')".format(self.m,
                                                       ', '.join("'{}'".format(pk) for pk in self.pubkeys),
                                                       self.n)

    @property
    def type(self):
        return 'multisig'

    @property
    def req_sigs(self):
        return self.m

    def is_standard(self):
        return (1 <= self.n <= 3) and (1 <= self.m <= self.n)


# noinspection PyUnresolvedReferences
class IfElseScript(ScriptPubKey):

    @staticmethod
    def verify(bytes_):
        try:
            parser = ScriptParser(bytes_)
            if_counter = 0
            if_script = Stream()
            else_script = Stream()
            current_script = if_script
            else_found = False

            try:
                if parser[-1] != OpCodeConverter.to_int('OP_ENDIF'):
                    raise WrongScriptTypeException('Script is not OP_ENDIF terminated')
            except IndexError:
                raise WrongScriptTypeException

            parser.require('OP_IF')
            # print('################### Parsing IfElseScript ######################')
            for op in parser:
                # print('Parsing op: {}'.format(op))
                if op == OpCodeConverter.to_int('OP_IF'):
                    current_script << op
                    if_counter += 1
                elif op == OpCodeConverter.to_int('OP_ENDIF'):
                    if_counter -= 1
                    if if_counter == -1:
                        break
                    current_script << op
                elif op == OpCodeConverter.to_int('OP_ELSE'):
                    if if_counter == 0:
                        # switch script
                        else_found = True
                        # print('Switching script. If script is: {}'.format(if_script.hexlify()))
                        current_script = else_script
                    else:
                        current_script << op
                else:
                    try:
                        push_data = parser.get_push(op)
                        current_script << push_data.to_push_op()
                    except UnexpectedOperationFound:
                        # not a push operation, we can move on
                        current_script << op

            if not else_found:
                raise WrongScriptTypeException('No OP_ELSE found matching outer OP_IF')

            parser.require_empty()
            # print('IF SCRIPT: {}'.format(if_script.hexlify()))
            # print('ELSE SCRIPT: {}'.format(else_script.hexlify()))
            return (ScriptBuilder.identify(if_script.serialize(), inner=True),
                    ScriptBuilder.identify(else_script.serialize(), inner=True))
        except UnexpectedOperationFound as exc:
            raise WrongScriptTypeException(str(exc))

    # noinspection PyMissingConstructor
    def __init__(self, *args):
        """
        :param args: if one arg is provided, it is interpreted as a script, which is in turn
        verified and if-branch and else-branch are extracted. If two args are provided they
        are supposed to be the if-branch and else-branch. In this case the script is created
        from these data
        """

        if len(args) == 1:
            # we expect something of type Script
            script = args[0]
            if_script, else_script = self.verify(script.body)
            object.__setattr__(self, 'if_script', if_script)
            object.__setattr__(self, 'else_script', else_script)
            super().__init__(script.body)
        elif len(args) == 2:
            if_script, else_script = args
            object.__setattr__(self, 'if_script', if_script)
            object.__setattr__(self, 'else_script', else_script)
            super().__init__(bytearray([OpCodeConverter.to_int('OP_IF')]) +
                             self.if_script.serialize() +
                             bytearray([OpCodeConverter.to_int('OP_ELSE')]) +
                             self.else_script.serialize() +
                             bytearray([OpCodeConverter.to_int('OP_ENDIF')]))
        else:
            raise TypeError('Wrong number of params for IfElseScript __init__: {}'.format(len(args)))

    def __repr__(self):
        return 'IfElseScript({}, {})'.format(self.if_script, self.else_script)

    @property
    def type(self):
        return 'if{{ {} }}else{{ {} }}'.format(self.if_script.type, self.else_script.type)


# noinspection PyUnresolvedReferences
class TimelockScript(ScriptPubKey):

    @staticmethod
    def verify(bytes_):
        try:
            parser = ScriptParser(bytes_)
            locktime = int(parser.get_push())
            parser.require('OP_CHECKLOCKTIMEVERIFY')
            parser.require('OP_DROP')
            script = parser >> len(parser)
            return locktime, ScriptBuilder.identify(script, inner=True)
        except (UnexpectedOperationFound, StopIteration) as exc:
            raise WrongScriptTypeException(str(exc))

    def __init__(self, *args):
        """
        :param args: if one arg is provided it is interpreted as a script, which is in turn
        verified and `locktime` and `locked_script` are extracted. If two args are provided,
        they are interpreted as `locktime` and `locked_script` respectively, the script is
        then generated from these params
        """
        from .transaction import Locktime
        if len(args) == 1:
            script = args[0]
            locktime, locked_script = self.verify(script.body)
            object.__setattr__(self, 'locked_script', locked_script)
            object.__setattr__(self, 'locktime', locktime)

            super().__init__(script.body)
        elif len(args) == 2:
            locktime, locked_script = args
            if not isinstance(locktime, Locktime):
                raise TypeError('locktime is not of type Locktime, {} instead'.format(type(locktime)))
            if not isinstance(locked_script, BaseScript):
                raise TypeError('locked_script is not of type Script, {} instead'.format(type(locked_script)))
            object.__setattr__(self, 'locked_script', locked_script)
            object.__setattr__(self, 'locktime', locktime)

            script_body = Stream()
            script_body << self.locktime.for_script().to_push_op()
            script_body << OpCodeConverter.to_int('OP_CHECKLOCKTIMEVERIFY')
            script_body << OpCodeConverter.to_int('OP_DROP')
            script_body << self.locked_script

            super().__init__(script_body.serialize())

        else:
            raise TypeError('Wrong number of params for TimelockScript __init__: {}'.format(len(args)))

    def __repr__(self):
        return 'TimelockScript({}, {})'.format(self.locktime, self.locked_script)

    @property
    def type(self):
        return '[timelock] {}'.format(self.locked_script.type)


# noinspection PyUnresolvedReferences
class RelativeTimelockScript(ScriptPubKey):

    @staticmethod
    def verify(bytes_):
        try:
            parser = ScriptParser(bytes_)
            sequence = parser.get_push()
            parser.require('OP_CHECKSEQUENCEVERIFY')
            parser.require('OP_DROP')
            script = parser >> len(parser)
            return sequence, ScriptBuilder.identify(script, inner=True)
        except (UnexpectedOperationFound, StopIteration) as exc:
            raise WrongScriptTypeException(str(exc))

    def __init__(self, *args):
        """
        :param args: if one arg is provided, it is interpreted as a script, which is in turn
        verified and `sequence` and `locked_script` are extracted. If two args are provided,
        they are interpreted as `sequence` and `locked_script` respectively, the script is
        then generated from these params
        """
        from .transaction import Sequence
        if len(args) == 1:
            script = args[0]
            sequence, locked_script = self.verify(script.body)
            object.__setattr__(self, 'locked_script', locked_script)
            object.__setattr__(self, 'sequence', Sequence(int(sequence)))
            super().__init__(script.body)
        elif len(args) == 2:
            sequence, locked_script = args
            object.__setattr__(self, 'sequence', sequence)
            object.__setattr__(self, 'locked_script', locked_script)
            script_body = Stream()
            script_body << self.sequence.for_script().to_push_op()
            script_body << OpCodeConverter.to_int('OP_CHECKSEQUENCEVERIFY')
            script_body << OpCodeConverter.to_int('OP_DROP')
            script_body << self.locked_script

            super().__init__(script_body.serialize())
        else:
            raise TypeError('Wrong number of params for RelativeTimelockScript __init__: {}'.format(len(args)))

    def __repr__(self):
        return 'RelativeTimelockScript({}, {})'.format(self.sequence, self.locked_script)

    @property
    def type(self):
        return '[relativetimelock] {}'.format(self.locked_script.type)


class HashlockScript(ScriptPubKey):

    @staticmethod
    @abstractmethod
    def hash_func(data):
        raise NotImplemented

    @staticmethod
    @abstractmethod
    def hash_op():
        raise NotImplemented

    @staticmethod
    @abstractmethod
    def hash_size():
        raise NotImplemented

    @classmethod
    def from_preimage(cls, preimage, script):
        return cls([StackData.from_bytes(cls.hash_func(preimage)), script])

    @classmethod
    def verify(cls, bytes_):
        try:
            parser = ScriptParser(bytes_)
            parser.require(cls.hash_op())
            secret_hash = parser.require_push(str(cls.hash_size()))
            parser.require('OP_EQUALVERIFY')
            script = parser >> len(parser)
            return secret_hash, ScriptBuilder.identify(script, inner=True)
        except (UnexpectedOperationFound, StopIteration) as exc:
            raise WrongScriptTypeException(str(exc))

    def __init__(self, *args):
        """
        :param args: if one arg is provided, it is interpreted as a script, which is in turn
        verified and `hash` and `locked_script` are extracted. If two args are provided,
        they are interpreted as `hash` and `locked_script` respectively, the script is
        then generated from these params
        """

        if len(args) == 1:
            script = args[0]
            lock_hash, locked_script = self.verify(script.body)
            object.__setattr__(self, 'locked_script', locked_script)
            if not isinstance(lock_hash, StackData):
                lock_hash = StackData.from_bytes(lock_hash)
            object.__setattr__(self, 'hash', lock_hash)
            super().__init__(script.body)
        elif len(args) == 2:
            lock_hash, locked_script = args
            object.__setattr__(self, 'locked_script', locked_script)
            if not isinstance(lock_hash, StackData):
                lock_hash = StackData.from_bytes(lock_hash)
            object.__setattr__(self, 'hash', lock_hash)
            script_body = Stream()
            script_body << OpCodeConverter.to_int(self.__class__.hash_op())
            script_body << self.hash.to_push_op()
            script_body << OpCodeConverter.to_int('OP_EQUALVERIFY')
            script_body << self.locked_script
            super().__init__(script_body.serialize())
        else:
            raise TypeError('Wrong number of params for HashlockScript __init__: {}'.format(len(args)))

    def __repr__(self):
        return '{}({}, {})'.format(self.__class__.__name__, self.hash.hexlify(), self.locked_script)

    @property
    def type(self):
        return '[hashlock] {}'.format(self.locked_script.type)


class Hashlock256Script(HashlockScript):

    @staticmethod
    def hash_op():
        return 'OP_HASH256'

    @staticmethod
    def hash_func(data):
        return bytearray(sha256(sha256(data).digest()).digest())

    @staticmethod
    def hash_size():
        return 32


class Hashlock160Script(HashlockScript):

    @staticmethod
    def hash_op():
        return 'OP_HASH160'

    @staticmethod
    def hash_func(data):
        sha = sha256(data).digest()
        ripe = hashlib.new('ripemd160')
        ripe.update(sha)
        return bytearray(ripe.digest())

    @staticmethod
    def hash_size():
        return 20


class UnknownScript(ScriptPubKey):

    @property
    def type(self):
        return 'nonstandard'

    def decompile(self):
        return self.hexlify()


class ScriptBuilder(object):

    # never change the order of the elements in this list
    types = [P2pkhScript,
             P2shScript,
             NulldataScript,
             P2pkScript,
             MultisigScript,
             IfElseScript,
             RelativeTimelockScript,
             TimelockScript,
             Hashlock256Script,
             Hashlock160Script,
             P2wpkhV0Script,
             P2wshV0Script]

    not_allowed_inner = {P2wshV0Script, P2wpkhV0Script, P2shScript}  # can't be an internal ScriptPubKey format
    not_allowed_redeem = {P2shScript}  # can't be an external RedeemScript format

    @staticmethod
    def identify(raw_script, inner=False, redeem=False):

        if isinstance(raw_script, str):
            raw_script = bytearray(unhexlify(raw_script))

        if inner:
            ignore = ScriptBuilder.not_allowed_inner
        elif redeem:
            ignore = ScriptBuilder.not_allowed_redeem
        else:
            ignore = set()

        for script_type in [script for script in ScriptBuilder.types if script not in ignore]:
            try:
                # print('Trying {}...'.format(script_type.__name__))
                candidate = script_type(Script(raw_script))
                # print('Success')
                return candidate
            except (WrongScriptTypeException, WrongPubKeyFormat, WrongPushDataOp):
                # print('Failed')
                pass
        return UnknownScript(raw_script)

"""
# Example usage:

from .crypto import PublicKey
from .transaction import Sequence

IfElseScript(
    MultisigScript(
        2,
        PublicKey.unhexlify("021b98b2e4ba9dae9f869bcf948c45df6b6f8e6bb623915cf144237f5e6ab98cf4"),
        PublicKey.unhexlify("0376d53363bbeefed905fc685e4d4e1fe0cbf9959e8f59e9f5f209f489b3a62857"),
        2
    ),
    RelativeTimelockScript(
        Sequence(5),
        P2pkhScript(
            PublicKey.unhexlify("0376d53363bbeefed905fc685e4d4e1fe0cbf9959e8f59e9f5f209f489b3a62857")
        )
    )
)
"""
