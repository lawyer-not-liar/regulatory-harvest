import socket

import pytest

from regulatory_harvest.sources import UnsafeSourceError, validate_public_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://198.51.100.10/rule",
        "http://127.0.0.1/admin",
        "http://[::1]/admin",
        "http://169.254.169.254/latest/meta-data",
        "https://user:pass@198.51.100.10/rule",
    ],
)
def test_validate_public_url_rejects_unsafe_destinations(url: str) -> None:
    """Removing scheme, credential, or address checks would make these URLs pass."""
    with pytest.raises(UnsafeSourceError):
        validate_public_url(url)


def test_validate_public_url_accepts_global_literal() -> None:
    """Rejecting every literal IP would block legitimate public sources."""
    assert validate_public_url("https://93.184.216.34/rule") == (
        "https://93.184.216.34/rule"
    )


def test_validate_public_url_rejects_hostname_resolving_to_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checking only hostname syntax would leave DNS-based SSRF open."""

    def private_result(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", private_result)

    with pytest.raises(UnsafeSourceError, match="non-public"):
        validate_public_url("https://publisher.example/rule")

