from typing import Tuple, Union, List

import requests

from .exceptions import MalformedURL, UnsupportedProtocol
from .protocols import HKPKey, Identity, Protocol, VKSKey
from .utils import CA

try:
    # python2
    from urlparse import urlparse, urljoin, quote
except ImportError:
    # python3
    from urllib.parse import urlparse, urljoin, quote


class Client(object):
    supported_protocols = tuple([protocol.value for protocol in Protocol])

    def __init__(
        self,
        host: str,
        proxies: dict = {},
        headers: dict = {},
        verify: bool = True
    ) -> 'Client':
        if not host.startswith(self.supported_protocols):
            raise UnsupportedProtocol
        self.protocol = Client._get_protocol(host)
        self.url = self._get_url(host)
        self.session = requests.session()
        self.session.headers = headers
        self.session.proxies = proxies
        self.session.verify = verify

    @staticmethod
    def uri_validator(uri: str) -> Tuple[str, bool]:
        try:
            result = urlparse(uri)
            return result.scheme, all([result.scheme, result.netloc])
        except ValueError:
            return "", False

    @staticmethod
    def _get_protocol(host: str) -> Protocol:
        protocol, is_valid = Client.uri_validator(host)
        if is_valid:
            return Protocol(protocol)
        raise MalformedURL

    def _get_url(self, host: str) -> str:
        if self.protocol is Protocol.HKP:
            return host.replace(self.protocol.value, 'http', 1)
        elif (
            self.protocol is Protocol.HKPS or
            self.protocol is Protocol.VKS or
            self.protocol is Protocol.WKS
        ):
            return host.replace(self.protocol.value, 'https', 1)
        raise UnsupportedProtocol

    def get_url(self, path: str) -> str:
        return urljoin(
            self.url,
            path
        )


class VKSClient(Client):
    """
        VKS Client for Hagrid --> https://keys.openpgp.org/about/api
    """
    v1 = '/vks/v1'

    def __init__(self, host, **kwargs) -> 'VKSClient':
        super().__init__(host, **kwargs)

    @staticmethod
    def no_legaxy_0x(id: str):
        if id.startswith("0x"):
            raise LookupError

    def get_by_fingerprint(self, fingerprint: str) -> Union[VKSKey, None]:
        VKSClient.no_legaxy_0x(fingerprint)
        url = self.get_url(
            '{0}/by-fingerprint/{1}'.format(self.v1, fingerprint)
        )
        return VKSKey(url, self.session, fingerprint=fingerprint)

    def get_by_keyid(self, keyid: str) -> Union[VKSKey, None]:
        VKSClient.no_legaxy_0x(keyid)
        url = self.get_url(
            '{0}/by-keyid/{1}'.format(self.v1, quote(keyid))
        )
        return VKSKey(url, self.session, keyid=keyid)

    def get_by_email(self, email: str) -> Union[VKSKey, None]:
        url = self.get_url(
            '{0}/by-email/{1}'.format(self.v1, quote(email))
        )
        return VKSKey(url, self.session, uid=email)

    def upload(self, key: Union[VKSKey, str, bytes]):
        pass


class HKPClient(Client):
    """
        HKP/HKPS Client object used for search queries.
    """

    def __init__(self, host: str, verify: bool = True, **kwargs):
        if host.endswith("hkps.pool.sks-keyservers.net"):
            kwargs['verify'] = CA().pem
        super().__init__(host, **kwargs)

    def __parse_index(self, response) -> List[Union[HKPKey, None]]:
        """
        Parse machine readable index response.
        """
        lines = response.splitlines()[1:]
        result, key = [], None

        for line in iter(lines):
            items = line.split(':')
            if 'pub' in items[0]:
                key = HKPKey(self.url, *items[1:], session=self.session)
                result.append(key)
            if 'uid' in items[0] and key:
                key.identities.append(Identity(*items[1:]))
        return result

    def search(
        self,
        query: str,
        exact: bool = False,
        nm: bool = False
    ) -> List[Union[HKPKey, None]]:
        """
        Searches for given query, returns list of key objects.
        """
        opts = (
            ('mr', True), ('nm', nm),
        )

        params = {
            'op': 'index',
            'options': ','.join(name for name, val in opts if val),
            'search': query,
            'exact': exact and 'on' or 'off',
        }

        url = self.get_url('/pks/lookup')
        response = self.session.get(
            url,
            params=params)
        if response.ok:
            response = response.text
        elif response.status_code == requests.codes.not_found:
            return None
        else:
            response.raise_for_status()
        return self.__parse_index(response)

    def add(self, key: Union[HKPKey, str, bytes]):
        """
        Upload key to the keyserver.
        """
        url = self.get_url('/pks/add')
        data = {'keytext': key}
        response = self.session.post(
            url,
            data=data)
        response.raise_for_status()
