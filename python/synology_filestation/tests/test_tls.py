"""TLS certificate verification.

The client used to pass ``danger_accept_invalid_certs(true)`` unconditionally,
so ``https=True`` bought encryption against a passive observer and nothing else:
anything able to intercept the connection could present its own certificate and
read the password out of the login exchange. Verification is now on by default
and ``verify_ssl=False`` is the explicit opt-out.

These run against a real HTTPS server holding a certificate from a throwaway CA
that the system trust store has never heard of — the same shape as a DSM
appliance's self-signed certificate. Asserting that the kwarg exists would not
tell us whether it is actually wired to anything.
"""
from __future__ import annotations

import ssl
from typing import Iterator

import pytest
import trustme
from pytest_httpserver import HTTPServer

from synology_filestation import Client, TlsError, TransportError

from .conftest import LOGIN_OK


@pytest.fixture(scope="module")
def https_server() -> Iterator[HTTPServer]:
    """An HTTPS server whose certificate chains to a CA nobody trusts.

    Built directly rather than through the ``httpserver`` fixture: the TLS
    context is bound when pytest-httpserver creates its session-scoped server,
    so overriding ``httpserver_ssl_context`` in one module would not reliably
    apply to it.
    """
    ca = trustme.CA()
    cert = ca.issue_cert("localhost")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with cert.private_key_and_cert_chain_pem.tempfile() as pem:
        context.load_cert_chain(pem)

    server = HTTPServer(host="localhost", port=0, ssl_context=context)
    server.start()
    yield server
    server.clear()
    server.stop()


@pytest.fixture(autouse=True)
def _login_route(https_server: HTTPServer) -> Iterator[None]:
    https_server.expect_request("/webapi/auth.cgi").respond_with_json(LOGIN_OK)
    yield
    https_server.clear()


def test_login_rejects_an_untrusted_certificate_by_default(https_server: HTTPServer) -> None:
    with pytest.raises(TlsError):
        Client.login(
            "localhost",
            https_server.port,
            "alice",
            "secret",
            https=True,
        )


def test_verify_ssl_false_accepts_an_untrusted_certificate(https_server: HTTPServer) -> None:
    client = Client.login(
        "localhost",
        https_server.port,
        "alice",
        "secret",
        https=True,
        verify_ssl=False,
    )
    assert client is not None


def test_the_rejection_names_the_certificate_as_the_cause(https_server: HTTPServer) -> None:
    """The failure has to be diagnosable. Before the transport error carried its
    source chain, every TLS rejection surfaced as a bare "error sending request
    for url (...)" with nothing pointing at the certificate."""
    with pytest.raises(TlsError) as excinfo:
        Client.login("localhost", https_server.port, "alice", "secret", https=True)

    message = str(excinfo.value).lower()
    assert "certificate" in message or "unknownissuer" in message, message


@pytest.mark.asyncio
async def test_async_client_honours_verify_ssl(https_server: HTTPServer) -> None:
    from synology_filestation.aio import AsyncClient

    with pytest.raises(TlsError):
        await AsyncClient.login(
            "localhost", https_server.port, "alice", "secret", https=True
        )

    client = await AsyncClient.login(
        "localhost", https_server.port, "alice", "secret", https=True, verify_ssl=False
    )
    assert client is not None
