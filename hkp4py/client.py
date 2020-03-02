"""
Python HKP protocol client implementation based on current draft spec
http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00

Taken from: 
https://github.com/dgladkov/python-hkp/blob/master/hkp/client.py
"""
import sys
from datetime import datetime
import requests
try:
    import urllib.parse as parse
except ImportError:
    import urlparse as parse
import hkp4py.utils as utils


__all__ = ['Key', 'Identity', 'KeyServer']

# Loosely taken from RFC2440 (http://tools.ietf.org/html/rfc2440#section-9.1)
ALGORITHMS = {
    0: 'unknown',
    1: 'RSA (Encrypt or Sign)',
    2: 'RSA Encrypt-Only',
    3: 'RSA Sign-Only',
    16: 'Elgamal (Encrypt-Only)',
    17: 'DSA (Digital Signature Standard)',
    18: 'Elliptic Curve',
    19: 'ECDSA',
    20: 'Elgamal (Encrypt or Sign)',
    21: 'Reserved for Diffie-Hellman',
    22: 'EdDSA',
}


class Key(object):
    """
    Public key object.
    """

    _begin_header = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
    _end_header = '-----END PGP PUBLIC KEY BLOCK-----'

    def __init__(self, host, port, keyid, algo, keylen,
                 creation_date, expiration_date, flags, session=None):
        """
        Takes keyserver host and port used to look up ASCII armored key, and
        data as it is present in search query result.
        """
        self.host = host
        self.port = port
        self.keyid = keyid
        algo = int(algo)
        self.algo = ALGORITHMS.get(algo, algo)
        self.key_length = int(keylen)
        self.creation_date = datetime.fromtimestamp(int(creation_date))
        self.session = session

        if expiration_date:
            self.expiration_date = datetime.fromtimestamp(int(expiration_date))
        else:
            self.expiration_date = None

        self.revoked = self.disabled = self.expired = False
        if 'r' in flags:
            self.revoked = True
        if 'd' in flags:
            self.disabled = True
        if 'e' in flags:
            self.expired = True

        self.identities = []

    def __repr__(self):
        return 'Key {} {}'.format(self.keyid, self.algo)

    def __str__(self):
        return repr(self)

    @utils.cached_property
    def key(self):
        return self.retrieve()

    @utils.cached_property
    def key_blob(self):
        return self.retrieve(blob=True)

    def retrieve(self, nm=False, blob=False):
        """
        Retrieve public key from keyserver and strip off any enclosing HTML.
        """
        opts = (
            ('mr', True), ('nm', nm),
        )

        keyid = self.keyid
        params = {
            'search': keyid.startswith('0x') and keyid or '0x{}'.format(keyid),
            'op': 'get',
            'options': ','.join(name for name, val in opts if val),
        }
        request_url = '{}:{}/pks/lookup'.format(self.host, self.port)
        response = self.session.get(
            request_url, params=params)
        if response.ok:
            # strip off enclosing text or HTML. According to RFC headers MUST be
            # always preserved, so we rely on them
            response = response.text
            key = response.split(self._begin_header)[
                1].split(self._end_header)[0]
            key = '{}{}{}'.format(self._begin_header, key, self._end_header)
            if blob:
                # cannot use requests.content because of potential html
                # provided by keyserver. (see above comment)
                return bytes(key.encode("utf-8"))
            else:
                return key
        else:
            return None


class Identity(object):
    """
    Key owner's identity. Constructor takes data as it is present in search
    query result.
    """

    def __init__(self, uid, creation_date, expiration_date, flags):
        self.uid = parse.unquote(uid)

        if creation_date:
            self.creation_date = datetime.fromtimestamp(int(creation_date))
        else:
            self.creation_date = None

        if expiration_date:
            self.expiration_date = datetime.fromtimestamp(int(expiration_date))
        else:
            self.expiration_date = None

        self.revoked = self.disabled = self.expired = False

        if 'r' in flags:
            self.revoked = True
        if 'd' in flags:
            self.disabled = True
        if 'e' in flags:
            self.expired = True

    def __repr__(self):
        return 'Identity {}'.format(self.uid)

    def __str__(self):
        return repr(self)


class KeyServer(object):
    """
    Keyserver object used for search queries.
    """

    def __init__(self, host, port=11371, proxies=None, headers=None, verify=True):
        if host.startswith('hkp://') or host.startswith('hkps://'):
            host = host.replace("hkp", "http", 1)
            if host.startswith('https'):
                if port == 11371:
                    port = 443
        else:
            raise Exception("Unsupported protocol, hkp|hkps are supported.")
        self.host = host
        self.port = port
        # Buildup Session
        self.session = requests.session()
        self.session.headers = headers
        self.session.proxies = proxies
        if host.endswith("hkps.pool.sks-keyservers.net"):
            verify = utils.ca().pem
        self.session.verify = verify

    def __parse_index(self, response):
        """
        Parse machine readable index response.
        """
        lines = response.splitlines()[1:]
        result, key = [], None

        for line in iter(lines):
            items = line.split(':')
            if 'pub' in items[0]:
                key = Key(self.host, self.port, *
                          items[1:], session=self.session)
                result.append(key)
            if 'uid' in items[0] and key:
                key.identities.append(Identity(*items[1:]))
        return result

    def search(self, query, exact=False, nm=False):
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

        request_url = '{}:{}/pks/lookup'.format(self.host, self.port)
        response = self.session.get(
            request_url,
            params=params)
        if response.ok:
            response = response.text
        elif response.status_code == requests.codes.not_found:
            return None
        else:
            raise Exception(
                '{}\nRequest URL: {}\nResponse:\n{}'.format(response.status_code, response.request.url, response.text))
        return self.__parse_index(response)

    def add(self, key):
        """
        Upload key to the keyserver.
        """
        request_url = '{}:{}/pks/add'.format(self.host, self.port)
        data = {'keytext': key}
        response = self.session.post(
            request_url,
            data=data)
        response.raise_for_status()
