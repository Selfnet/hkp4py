from typing import Union

from requests import Session, codes

from ..exceptions import NoKeyResponse
from .key import IKey


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
        super().__init__(url, session)

    def __repr__(self) -> str:
        return 'Key {}'.format(self.keyid or self.fingerprint or self.uid)

    def __str__(self) -> str:
        return repr(self)

    def retrieve(self, blob: bool = False) -> Union[str, bytes]:
        """
        Retrieve public key from keyserver and ensure the right content-type
        """
        self.session.headers.update(
            {'Content-Type': 'application/pgp-keys'}
        )
        response = self.session.get(self.url)
        if response.ok:
            key = response.text.strip()
            if (
                not key.startswith(self._begin_header) or
                not key.endswith(self._end_header)
            ):
                raise NoKeyResponse
            if blob:
                return bytes(key.encode("utf-8"))
            else:
                return key
        elif response.status_code == codes.not_found:
            return None
        else:
            response.raise_for_status()
