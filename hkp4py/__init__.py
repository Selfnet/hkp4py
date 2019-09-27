"""
Python HKP client module
"""
from hkp4py.client import HKPClient, HKPClient as KeyServer
from hkp4py.client import HKPKey, HKPKey as Key
from hkp4py.client import Identity, VKSCLient

__all__ = ["Key", "HKPKey", "Identity", "HKPClient", "VKSCLient", "KeyServer"]
