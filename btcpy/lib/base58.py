'''Base58 encoding

Implementations of Base58 and Base58Check endcodings that are compatible
with the bitcoin network.
'''

from hashlib import sha256

# 58 character alphabet used
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

iseq = lambda s: s
bseq = bytes
buffer = lambda s: s.buffer


def b58encode(v: bytes) -> str:
    '''Encode a string using Base58'''

    origlen = len(v)
    v = v.lstrip(b'\0')
    newlen = len(v)

    p, acc = 1, 0
    for c in iseq(v[::-1]):
        acc += p * c
        p = p << 8

    result = ''
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result += alphabet[mod]

    return (result + alphabet[0] * (origlen - newlen))[::-1]


def b58decode(v: str) -> bytes:
    '''Decode a Base58 encoded string'''

    origlen = len(v)
    v = v.lstrip(alphabet[0])
    newlen = len(v)

    p, acc = 1, 0
    for c in v[::-1]:
        acc += p * alphabet.index(c)
        p *= 58

    result = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.append(mod)

    return (bseq(result) + b'\0' * (origlen - newlen))[::-1]


def b58encode_check(v: bytes) -> str:
    '''Encode a string using Base58 with a 4 character checksum'''

    digest = sha256(sha256(v).digest()).digest()
    return b58encode(v + digest[:4])


def b58decode_check(v: str) -> bytes:
    '''Decode and verify the checksum of a Base58 encoded string'''

    result = b58decode(v)
    result, check = result[:-4], result[-4:]
    digest = sha256(sha256(result).digest()).digest()

    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result
