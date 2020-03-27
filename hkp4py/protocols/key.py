from ..utils import cached_property
from requests import Session
from typing import Union


class IKey(object):
    """
        This ensures that every Key Object hast an key (ascii armored)
        and a Key Blob (binary) format available.
        It also makes sure that a session is available.
        And the text looks like a key.
    """

    _begin_header = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
    _end_header = '-----END PGP PUBLIC KEY BLOCK-----'

    def __init__(self, url: str, session: Session) -> 'IKey':
        self.url: str = url
        # Should be a requests.session object
        assert session is not None
        self.session: Session = session

    def retrieve(self, blob: bool = False) -> Union[str, bytes]:
        raise NotImplementedError

    def __str__(self) -> str:
        return repr(self)

    @cached_property
    def key_blob(self) -> bytes:
        return self.retrieve(blob=True)

    @cached_property
    def key(self) -> str:
        return self.retrieve()
