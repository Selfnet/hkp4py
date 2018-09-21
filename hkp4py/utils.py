"""
Utils used by hkp module.
"""
import subprocess
import sys
import os

__all__ = ['cached_property']


class _Missing(object):

    def __repr__(self):
        return 'no value'

    def __reduce__(self):
        return '_missing'


_missing = _Missing()


class cached_property(object):
    """A decorator that converts a function into a lazy property.  The
    function wrapped is called the first time to retrieve the result
    and then that calculated result is used the next time you access
    the value::

        class Foo(object):

            @cached_property
            def foo(self):
                # calculate something important here
                return 42

    The class has to have a `__dict__` in order for this property to
    work.

    Taken from Werkzeug: http://werkzeug.pocoo.org/
    """

    # implementation detail: this property is implemented as non-data
    # descriptor.  non-data descriptors are only invoked if there is
    # no entry with the same name in the instance's __dict__.
    # this allows us to completely get rid of the access function call
    # overhead.  If one choses to invoke __get__ by hand the property
    # will still work as expected because the lookup logic is replicated
    # in __get__ for manual invocation.

    def __init__(self, func, name=None, doc=None):
        self.__name__ = name or func.__name__
        self.__module__ = func.__module__
        self.__doc__ = doc or func.__doc__
        self.func = func

    def __get__(self, obj, type=None):
        if obj is None:
            return self
        value = obj.__dict__.get(self.__name__, _missing)
        if value is _missing:
            value = self.func(obj)
            obj.__dict__[self.__name__] = value
        return value


class ca(object):

    def __init__(
        self,
        domain='sks-keyservers.net',
        pem_url="https://sks-keyservers.net/sks-keyservers.netCA.pem",
        pem_filename='sks-keyservers.netCA.pem'
    ):
        self.domain = domain
        self.pem_url = pem_url
        self.pem_filename = pem_filename

    @cached_property
    def pem(self):
        if sys.platform == "win32":
            gpgconfcmd = ["gpgconf.exe", "--list-dirs", "datadir"]
        else:
            gpgconfcmd = ["/usr/bin/env", "gpgconf", "--list-dirs", "datadir"]

        try:
            output = subprocess.check_output(gpgconfcmd)
            if sys.version_info[0] == 2:
                datadir = output.strip()
            else:
                datadir = output.decode(sys.stdout.encoding).strip()
        except subprocess.CalledProcessError:
            datadir = ""
            pass

        pempath = "{0}{1}{2}".format(datadir, os.sep, self.pem_filename)

        if os.path.exists(pempath):
            pemfile = pempath
        else:
            pemfile = self.pem_url

        return pemfile

    def __repr__(self):
        return 'CA {0}, PEM {1}'.format(self.domain, self.pem)

    def __str__(self):
        return repr(self)
