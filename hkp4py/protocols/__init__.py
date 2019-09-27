from enum import Enum

from .hkp import HKPKey, Identity
from .vks import VKSKey


class Protocol(Enum):
    HKP = 'hkp'
    HKPS = 'hkps'
    VKS = 'vks'


class UnsupportedProtocol(Exception):
    msg = "Suported are: {}".format(
        "://, ".join([protocol.value for protocol in Protocol]))


__all__ = ["VKSKey", "HKPKey", "Identity", "Protocol", "UnsupportedProtocol"]
