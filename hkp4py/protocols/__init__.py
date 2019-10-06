from enum import Enum

from .hkp import HKPKey, Identity
from .vks import VKSKey


class Protocol(Enum):
    HKP = 'hkp'
    HKPS = 'hkps'
    VKS = 'vks'
    WKS = 'wks'


__all__ = ["VKSKey", "HKPKey", "Identity", "Protocol"]
