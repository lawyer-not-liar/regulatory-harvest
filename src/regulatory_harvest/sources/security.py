"""Network destination validation for supplied source URLs."""

import ipaddress
import socket
from urllib.parse import urlsplit


class UnsafeSourceError(ValueError):
    """Raised when a source URL could reach a prohibited destination."""


def _resolved_addresses(
    hostname: str, port: int
) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise UnsafeSourceError("source hostname could not be resolved") from error
        return {ipaddress.ip_address(result[4][0]) for result in results}
    return {literal}


def validate_public_url(url: str) -> str:
    """Return an HTTP(S) URL only when every resolved address is globally routable."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeSourceError("source URL must use HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeSourceError("source URL must not contain credentials")
    if parsed.hostname is None:
        raise UnsafeSourceError("source URL requires a hostname")

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise UnsafeSourceError("source URL has an invalid port") from error

    addresses = _resolved_addresses(parsed.hostname, port)
    if not addresses or any(not address.is_global for address in addresses):
        raise UnsafeSourceError("source hostname resolves to a non-public address")
    return url
