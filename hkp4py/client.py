from typing import Union
import requests
from .exceptions import MalformedURL, UnsupportedProtocol
from .protocols import HKPKey, Identity, Protocol, VKSKey
from .protocols.key import IKey
from .utils import CA

try:
    # python2
    from urlparse import urlparse, urljoin, quote
except:
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
    ):
        if not host.startswith(self.supported_protocols):
            raise UnsupportedProtocol
        self.protocol = self.get_protocol(host)
        self.url = self.get_url(host)
        self.session = requests.session()
        self.session.headers = headers
        self.session.proxies = proxies
        self.session.verify = verify

    @staticmethod
    def uri_validator(uri: str) -> tuple:

        try:
            result = urlparse(uri)
            return result.scheme, all([result.scheme, result.netloc])
        except:
            return "", False

    def get_protocol(self, host: str):
        protocol, is_valid = Client.uri_validator(host)
        if is_valid:
            return Protocol(protocol)
        raise MalformedURL

    def get_url(self, host: str):
        if self.protocol is Protocol.HKP:
            return host.replace(self.protocol.value, 'http', 1)
        elif (
            self.protocol is Protocol.HKPS or
            self.protocol is Protocol.VKS or
            self.protocol is Protocol.WKS
        ):
            return host.replace(self.protocol.value, 'https', 1)
        raise UnsupportedProtocol


class VKSCLient(Client):
    """
        VKS Client for Hagrid --> https://keys.openpgp.org/about/api
    """
    v1 = '/vks/v1'

    def __init__(self, host, **kwargs):
        if not host.startswith("vks"):
            raise UnsupportedProtocol
        super(VKSCLient, self).__init__(host, **kwargs)

    @staticmethod
    def no_legaxy_0x(id: str):
        if id.startswith("0x"):
            raise LookupError

    def get_by_fingerprint(self, fingerprint: str) -> IKey:
        VKSCLient.no_legaxy_0x(fingerprint)
        url = urljoin(
            self.url, '{0}/by-fingerprint/{1}'.format(self.v1, fingerprint))
        return VKSKey(url, self.session, fingerprint=fingerprint)

    def get_by_keyid(self, keyid: str):
        VKSCLient.no_legaxy_0x(keyid)
        url = urljoin(
            self.url, '{0}/by-keyid/{1}'.format(self.v1, quote(keyid)))
        return VKSKey(url, self.session, keyid=keyid)

    def get_by_email(self, email: str):
        url = urljoin(
            self.url, '{0}/by-email/{1}'.format(self.v1, quote(email)))
        return VKSKey(url, self.session, uid=email)

    def upload(self, key: Union[VKSKey, str, bytes]):
        pass


class HKPClient(Client):
    """
        HKP/HKPS Client object used for search queries.
    """

    def __init__(self, host: str, verify: bool = True, **kwargs):
        if not host.startswith("hkp"):
            raise UnsupportedProtocol
        if host.endswith("hkps.pool.sks-keyservers.net"):
            kwargs['verify'] = CA().pem
        super(HKPClient, self).__init__(host, **kwargs)

    def __parse_index(self, response):
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

    def search(self, query: str, exact: bool = False, nm: bool = False):
        """
        Searches for given query, returns list of key objects.
        """
        opts = (
            ('mr', True), ('nm', nm),
        )

        params = {
            'search': query,
            'op': 'index',
            'options': ','.join(name for name, val in opts if val),
            'exact': exact and 'on' or 'off',
        }

        request_url = '{}/pks/lookup'.format(self.url)
        response = self.session.get(
            request_url,
            params=params)
        if response.ok:
            response = response.text
        else:
            return None
        return self.__parse_index(response)

    def add(self, key: Union[HKPKey, str, bytes]):
        """
        Upload key to the keyserver.
        """
        request_url = '{}/pks/add'.format(self.url)
        data = {'keytext': key}
        response = self.session.post(
            request_url,
            data=data)
        response.raise_for_status()
