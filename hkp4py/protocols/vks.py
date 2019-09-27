from .key import IKey


class VKSKey(IKey):
    """
    Public key object for VKS (Hagrid) servers.
    """

    def __init__(self, url: str, session, uid=None, keyid=None, fingerprint=None):
        """
        Takes keyserver host and port used to look up ASCII armored key, and
        data as it is present in search query result.
        """
        self.keyid = keyid
        self.fingerprint = fingerprint
        self.uid = uid
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
        print(response.text)
        if response.ok:
            key = response.text
            if not key.startswith(self._begin_header) or not key.endswith(self._end_header):
                raise Exception("Key broken?")
            if blob:
                # cannot use requests.content because of potential html
                # provided by keyserver. (see above comment)
                return bytes(key.encode("utf-8"))
            else:
                return key
        else:
            return None
