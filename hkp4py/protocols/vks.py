from .key import IKey
from requests import Session


class VKSKey(IKey):
    """
    Public key object for VKS (Hagrid) servers.
    """

    def __init__(
        self,
        url: str,
        session: Session,
        uid: str = None,
        keyid: str = None,
        fingerprint: str = None
    ):
        """
        Takes keyserver host and port used to look up ASCII armored key, and
        data as it is present in search query result.
        """
        self.keyid: str = keyid
        self.fingerprint: str = fingerprint
        self.uid: str = uid
        super(VKSKey, self).__init__(url, session)

    def __repr__(self):
        return 'Key {}'.format(self.keyid or self.fingerprint or self.uid)

    def __str__(self):
        return repr(self)

    def retrieve(self, blob: bool = False):
        """
        Retrieve public key from keyserver and ensure the right content-type
        """
        self.session.headers.update({'Content-Type': 'application/pgp-keys'})
        response = self.session.get(self.url)
        if response.ok:
            key = response.text.strip()
            if (
                not key.startswith(self._begin_header) or
                not key.endswith(self._end_header)
            ):
                raise Exception("No Key Response.")
            if blob:
                # cannot use requests.content because of potential html
                # provided by keyserver. (see above comment)
                return bytes(key.encode("utf-8"))
            else:
                return key
        else:
            return None
