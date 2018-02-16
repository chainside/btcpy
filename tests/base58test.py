import unittest
from btcpy.lib.base58 import b58decode, b58encode
from btcpy.lib.base58 import b58decode_check, b58encode_check


class P2THTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('''Starting P2TH test...''')

    def test_b58encode(self):

        self.assertEqual(b58encode("hello".encode()), 'Cn8eVZg')

    def test_b58encode_check(self):

        self.assertEqual(b58encode_check('hello world.'.encode()), 'DthHcFYf2SzzprfFbBgfuH')

    def test_b58decode(self):

        self.assertEqual(b58decode('Cn8eVZg'), b'hello')

    def test_b58decode_check(self):

        self.assertEqual(b58decode_check('DthHcFYf2SzzprfFbBgfuH'), b'hello world.')

if __name__ == '__main__':
    unittest.main()
