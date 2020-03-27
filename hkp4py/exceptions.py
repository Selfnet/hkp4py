from .protocols import Protocol


class MalformedURL(Exception):
    pass


class UnsupportedProtocol(Exception):
    msg = "Suported are: {}".format(
        "://, ".join([protocol.value for protocol in Protocol]))


class NoKeyResponse(Exception):
    msg = "No Key Response."
