# hkp4py

A Library to get GPG/PGP keys from a Keyserver.
This library uses the requests module to get the keys.

## Tested Python Versions

### Python 2.7

* 2.7.15

### Python 3

* 3.7

## Intstall via [AUR](https://aur.archlinux.org/packages/python-hkp4py-git/)

## Install via [PyPI](https://pypi.org/project/hkp4py/)

```bash
pip install hkp4py

pip3 install hkp4py
```

## KeyServer

This object represents a keyserver using the hkp protocol.

### Initialize

Initialize the KeyServer object.

```python
# python2and3 compliance
from __future__ import absolute_import, unicode_literals, print_function

from hkp4py import KeyServer


server = KeyServer("hkps://pgp.ext.selfnet.de")
```

#### HKPS support via following pool.

The hkps pool is also supported.

```url
hkps://hkps.pool.sks-keyservers.net
```

### Add

Add keys to a keyserver.

```python
key = "a long key"
server.add(key)
```

### Search

Find keys with the keyserver object.

```python
keys = server.search('@gnupg.org') # search by string
keys = server.search('0x{}'.format('6F4B4E15768C8C4E'), exact=True) #search by fingerprint
```

### Key Object

```python
for key in keys:
    # Key Basic Information
    print("Key Algorithm:\t{}".format(key.algo))
    print("Key fpr:\t{}".format(key.keyid))
    print("Key Length:\t{}".format(key.key_length))
    print("Disabled?\t{}".format('yes' if key.disabled else 'no'))
    print("Expired?\t{}".format('yes' if key.expired else 'no'))
    print("Revoked?\t{}".format('yes' if key.revoked else 'no'))
    print("From Host:\t{}".format(key.host))
    print("From Port:\t{}".format(key.port))
    print("Date Created:\t{}".format(key.creation_date))
    print("Date Expired:\t{}".format(key.expiration_date))
    print(key.key)
    print(key.key_blob)
```

#### Identity Object

```python
    for identity in key.identities:
        print("Identity:\t{}".format(identity.uid))
        print("\tDisabled?\t{}".format('yes' if identity.disabled else 'no'))
        print("\tExpired?\t{}".format('yes' if identity.expired else 'no'))
        print("\tRevoked?\t{}".format('yes' if identity.revoked else 'no'))
        print("\tDate Created:\t{}".format(identity.creation_date))
        print("\tDate Expired:\t{}".format(identity.expiration_date))
```

## More Advanced options

To set a different User-Agent and proxies for veiling purposes.
The KeyServer has the following additional options for the connection.

```python
server = KeyServer("hkps://pgp.ext.selfnet.de",
                   proxies={"http": "socks5h://localhost:5050", "https":
                   "socks5h://localhost:5050"},
                   headers={"User-Agent": "Testing"})
```

## Import key with gpgme python bindings

```python
from __future__ import absolute_import, unicode_literals

import gpg

result = gpg.Context().key_import(key.key_blob)
```
