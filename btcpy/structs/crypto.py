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
from base58 import b58decode_check, b58encode_check
from hashlib import sha256
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der
from functools import partial
from abc import ABCMeta

from ..lib.types import HexSerializable
from .address import Address, SegWitAddress
from ..constants import NETWORKS
from ..setup import net_name


class Key(HexSerializable, metaclass=ABCMeta):
    pass


class PrivateKey(Key):

    highest_s = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
    wif_prefixes = None

    @staticmethod
    def from_wif(wif, check_network=True):

        if not 51 <= len(wif) <= 52:
            raise ValueError('Invalid wif length: {}'.format(len(wif)))

        decoded = b58decode_check(wif)
        prefix, *rest = decoded

        if prefix not in NETWORKS[net_name()].wif_prefixes.values():
            raise ValueError('Unknown private key prefix: {:02x}'.format(prefix))

        if check_network:
            if prefix != NETWORKS[net_name()].wif_prefixes[net_name()]:
                raise ValueError('Prefix for wrong network using {}'.format(net_name()))

        public_compressed = len(rest) == 33
        privk = rest[0:32]

        return PrivateKey(bytearray(privk), public_compressed)

    @staticmethod
    def unhexlify(hexa):
        return PrivateKey(bytearray(unhexlify(hexa)))

    def __init__(self, priv, public_compressed=True):
        self.key = priv
        self.public_compressed = public_compressed

    def to_wif(self, mainnet=None):
        network = mainnet
        if mainnet is True:
            network = 'mainnet'
        if mainnet is False:
            network = 'testnet'
        if mainnet is None:
            network = net_name()
        prefix = bytearray([NETWORKS[net_name()].wif_prefixes[network]])
        decoded = prefix + self.key
        if self.public_compressed:
            decoded.append(0x01)
        return b58encode_check(bytes(decoded))

    def pub(self, compressed=None):
        if compressed is None:
            compressed = self.public_compressed
        raw_pubkey = bytearray(SigningKey.from_string(self.key, curve=SECP256k1).get_verifying_key().to_string())
        uncompressed = PublicKey(bytearray([0x04]) + raw_pubkey)
        if compressed:
            return PublicKey(uncompressed.compressed)
        else:
            return uncompressed

    def serialize(self):
        return self.key

    def raw_sign(self, data, deterministic=True):
        sig_key = SigningKey.from_string(self.key, curve=SECP256k1)
        sig_func = partial(sig_key.sign_digest_deterministic, hashfunc=sha256) if deterministic else sig_key.sign_digest
        r, s, order = sig_func(data, sigencode=lambda *x: x)
        if s < 0x01:
            raise ValueError('Too low s value for signature: {}'.format(s))
        # ref: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures
        if s > PrivateKey.highest_s:
            s = order - s
        if s.to_bytes(32, 'big')[0] > 0x7f:
            s = int.from_bytes(b'\x00' + s.to_bytes(32, 'big'), 'big')
        if r.to_bytes(32, 'big')[0] > 0x7f:
            r = int.from_bytes(b'\x00' + r.to_bytes(32, 'big'), 'big')
        return r, s, order

    def sign(self, data, deterministic=True):
        return sigencode_der(*self.raw_sign(data, deterministic))

    def __eq__(self, other):
        return self.key == other.key

    def __str__(self):
        return self.hexlify()


class WrongPubKeyFormat(Exception):
    pass


class PublicKey(Key):

    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    uncompressed_bytes = 64
    compressed_bytes = uncompressed_bytes // 2
    types = {0x02: 'even',
             0x03: 'odd',
             0x04: 'uncompressed'}

    headers = {val: key for key, val in types.items()}

    @staticmethod
    def from_point(point, compressed=True):
        result = PublicKey(bytearray([0x04]) + point.x().to_bytes(32, 'big') + point.y().to_bytes(32, 'big'))
        if compressed:
            return result.compress()
        return result

    @staticmethod
    def unhexlify(hexa):
        return PublicKey(bytearray(unhexlify(hexa)))

    @staticmethod
    def from_priv(priv):
        return priv.pub()

    @staticmethod
    def uncompress(pubkey):
        header, *body = pubkey
        if header not in {0x02, 0x03}:
            raise WrongPubKeyFormat('Pubkey header does not indicate compressed key: 0x{:02x}'.format(header))
        PublicKey.check(pubkey)
        parity = header - 2  # if 0x02 parity is 0, if 0x03 parity is 1
        x = int.from_bytes(body, 'big')
        alpha = (pow(x, 3, PublicKey.p) + 7) % PublicKey.p
        y = pow(alpha, (PublicKey.p + 1)//4, PublicKey.p)
        if y % 2 != parity:
            y = -y % PublicKey.p
        return bytearray([0x04]) + bytearray(body) + bytearray(y.to_bytes(PublicKey.compressed_bytes, 'big'))

    @staticmethod
    def check(pubkey):
        if type(pubkey) not in {bytes, bytearray}:
            raise ValueError('Unexpected data type for pubkey: {}'.format(type(pubkey)))

        try:
            header, *body = pubkey
        except ValueError:
            raise WrongPubKeyFormat('Got only one byte')

        if header == 0x04:
            if len(body) != PublicKey.uncompressed_bytes:
                raise WrongPubKeyFormat('Unexpected length for uncompressed pubkey: {}'.format(len(body)))
        elif header in {0x02, 0x03}:
            if len(body) != PublicKey.compressed_bytes:
                raise WrongPubKeyFormat('Unexpected length for compressed pubkey: {}'.format(len(body)))
        else:
            raise WrongPubKeyFormat('Unknown pubkey header: 0x{:02x}'.format(header))

    def __init__(self, pubkey):
        self.__class__.check(pubkey)
        self.type = PublicKey.types[pubkey[0]]
        if self.type == 'uncompressed':
            self.uncompressed = pubkey
            header = 0x03 if self.uncompressed[-1] % 2 else 0x02
            self.compressed = bytearray([header]) + self.uncompressed[1:-PublicKey.compressed_bytes]
        else:
            self.compressed = pubkey
            self.uncompressed = PublicKey.uncompress(pubkey)

    def __str__(self):
        return self.hexlify()

    def __len__(self):
        return len(str(self)) // 2

    def hash(self):
        import hashlib
        original = self.uncompressed if self.type == 'uncompressed' else self.compressed
        sha = hashlib.sha256(original).digest()
        ripe = hashlib.new('ripemd160')
        ripe.update(sha)
        return bytearray(ripe.digest())

    def serialize(self):
        return self.uncompressed if self.type == 'uncompressed' else self.compressed

    def to_address(self, mainnet=None):
        network = mainnet
        if mainnet is True:
            network = 'mainnet'
        if mainnet is False:
            network = 'testnet'
        if mainnet is None:
            network = net_name()
        return Address('p2pkh', self.hash(), network)

    def to_segwit_address(self, mainnet=None):
        if self.type == 'uncompressed':
            pubk = PublicKey(self.compressed)
        else:
            pubk = self
        return SegWitAddress('p2wpkh', pubk.hash(), mainnet)

    def compress(self):
        if self.type != 'uncompressed':
            return self
        return PublicKey(self.compressed)

    def __eq__(self, other):
        return (self.type, self.compressed, self.uncompressed) == (other.type, other.compressed, other.uncompressed)

    def __lt__(self, other):
        return self.compressed < other.compressed

