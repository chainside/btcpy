import unittest
from binascii import hexlify, unhexlify
from btcpy.lib.base58 import b58decode, b58encode
from btcpy.lib.base58 import b58decode_check, b58encode_check


# following test cases come from: https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_encode_decode.json
test_strings = [
            ["", ""],
            ["61", "2g"],
            ["626262", "a3gV"],
            ["636363", "aPEr"],
            ["73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"],
            ["00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"],
            ["516b6fcd0f", "ABnLTmg"],
            ["bf4f89001e670274dd", "3SEo3LWLoPntC"],
            ["572e4794", "3EFU7m"],
            ["ecac89cad93923c02321", "EJDM8drfXA6uyA"],
            ["10c8511e", "Rt5zm"],
            ["00000000000000000000", "1111111111"]
    ]


class B58Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('''Starting P2TH test...''')

    def test_b58encode(self):

        for i in test_strings:
            self.assertEqual(b58encode(unhexlify(i[0])), i[1])

    def test_b58encode_check(self):

        self.assertEqual(b58encode_check('hello world.'.encode()), 'DthHcFYf2SzzprfFbBgfuH')

    def test_b58decode(self):

        for i in test_strings:
            i = i[::-1]  # flip it
            self.assertEqual(hexlify(b58decode(i[0])).decode(), i[1])

    def test_b58decode_check(self):

        self.assertEqual(b58decode_check('DthHcFYf2SzzprfFbBgfuH'), b'hello world.')

if __name__ == '__main__':
    unittest.main()
