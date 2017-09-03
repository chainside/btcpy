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

from abc import ABCMeta, abstractmethod

from binascii import hexlify
from functools import wraps


def cached(method):

    @wraps(method)
    def wrapper(self):
        if self.__class__._allow_caching:
            cache = '_{}_{}__cached'.format(self.__class__.__name__, method.__name__)
            if not hasattr(self, cache):
                # this is a workaround to allow caching of attributes also for immutable objects
                object.__setattr__(self, cache, method(self))
            return getattr(self, cache)
        return method(self)

    return wrapper


class Cacheable(metaclass=ABCMeta):

    _allow_caching = True


class Uncacheable(metaclass=ABCMeta):

    _allow_caching = False


class Immutable(Cacheable):

    def __setattr__(self, key, value):
        raise AttributeError('Trying to set attribute `{}` of immutable class `{}`'.format(key, self.__class__))

    def __delattr__(self, item):
        raise AttributeError('Trying to delete attribute `{}` of immutable class `{}`'.format(item, self.__class__))


class Mutable(Uncacheable):

    def __setattr__(self, key, value):
        object.__setattr__(self, key, value)

    def __delattr__(self, item):
        object.__delattr__(self, item)


class Jsonizable(metaclass=ABCMeta):

    @classmethod
    @abstractmethod
    def from_json(cls, string):
        pass

    @abstractmethod
    def to_json(self):
        pass


class Serializable(metaclass=ABCMeta):

    @abstractmethod
    def serialize(self):
        raise NotImplemented


class Hexlifiable(metaclass=ABCMeta):

    @abstractmethod
    def hexlify(self):
        raise NotImplemented


class HexSerializable(Hexlifiable, Serializable, metaclass=ABCMeta):

    def hexlify(self):
        return hexlify(self.serialize()).decode()
