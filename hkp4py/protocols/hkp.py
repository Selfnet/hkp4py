from datetime import datetime
try:
    import urllib.parse as parse
except ImportError:
    import urlparse as parse
from .key import IKey
from ..utils import cached_property


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


class HKPKey(IKey):
    """
    Public key object for HKP Servers.
    """

    def __init__(self, url: str, keyid: str, algo, keylen,
                 creation_date, expiration_date, flags, session=None):
        """
        Takes keyserver host and port used to look up ASCII armored key, and
        data as it is present in search query result.
        """
        self.keyid = keyid
        algo = int(algo)
        self.algo = ALGORITHMS.get(algo, algo)
        self.key_length = int(keylen)
        self.creation_date = datetime.fromtimestamp(int(creation_date))

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

        super(HKPKey, self).__init__(url, session)

    def __repr__(self):
        return 'Key {} {}'.format(self.keyid, self.algo)

    def __str__(self):
        return repr(self)

    def retrieve(self, nm: bool = False, blob: bool = False):
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
        request_url = '{}/pks/lookup'.format(self.url)
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
