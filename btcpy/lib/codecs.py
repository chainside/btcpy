from abc import ABCMeta, abstractmethod
from base58 import b58encode_check, b58decode_check


class CouldNotDecode(ValueError):
    pass


class Codec(metaclass=ABCMeta):

    @staticmethod
    @abstractmethod
    def encode(data: bytearray) -> bytearray:
        raise NotImplemented

    @staticmethod
    @abstractmethod
    def decode(data: bytearray) -> bytearray:
        raise NotImplemented


class Base58Codec(Codec):

    @staticmethod
    def encode(data):
        return bytearray(b58encode_check(bytes(data)).encode())

    @staticmethod
    def decode(data):
        try:
            return bytearray(b58decode_check(data))
        except ValueError:
            raise CouldNotDecode('Could not decode string: {}'.format(data))


class Bech32Codec(Codec):

    @staticmethod
    def encode(data):
        pass

    @staticmethod
    def decode(data):
        pass
