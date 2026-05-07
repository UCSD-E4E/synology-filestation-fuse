"""Tests for the exception hierarchy and DSM-code → exception mapping."""
from __future__ import annotations

import pytest

from synology_filestation import (
    AlreadyExists,
    AuthError,
    Client,
    DSMError,
    FileStationError,
    InvalidArg,
    NoSpace,
    NoSuchFile,
    NotEmpty,
    NotSupported,
    PermissionDenied,
    SidNotFound,
    TransportError,
)


class TestHierarchy:
    """The exception hierarchy is a public contract — callers may catch
    FileStationError to get *any* DSM error, or catch a specific subclass."""

    def test_sid_not_found_is_auth_error(self):
        assert issubclass(SidNotFound, AuthError)

    def test_auth_error_is_filestation_error(self):
        assert issubclass(AuthError, FileStationError)

    def test_all_typed_errors_inherit_filestation_error(self):
        for cls in (
            AuthError,
            SidNotFound,
            NoSuchFile,
            PermissionDenied,
            AlreadyExists,
            NoSpace,
            NotEmpty,
            InvalidArg,
            NotSupported,
            TransportError,
            DSMError,
        ):
            assert issubclass(cls, FileStationError), f"{cls.__name__} is not a FileStationError"

    def test_filestation_error_is_exception(self):
        assert issubclass(FileStationError, Exception)


class TestDSMCodeMapping:
    """When DSM returns a known error code, the binding raises the matching
    typed exception. Unknown codes raise DSMError with the .code attribute set."""

    @pytest.mark.parametrize(
        "code, expected_cls",
        [
            (400, InvalidArg),
            (408, PermissionDenied),
            (414, NoSuchFile),
            (415, NoSuchFile),
            (416, NotEmpty),
            (418, AlreadyExists),
            (419, NoSpace),
            (1101, AlreadyExists),
            (1804, NoSpace),
            (1805, PermissionDenied),
        ],
    )
    def test_known_codes_map_to_typed_exceptions(
        self, httpserver, host_port, code, expected_cls
    ):
        """We drive the test through ``delete`` rather than ``getinfo``
        because ``getinfo`` deliberately remaps DSM code 408 to NoSuchFile —
        DSM uses 408 in per-entry getinfo responses to mean "no permission
        OR no such file", and NoSuchFile is the more useful semantic for
        ``os.stat``-shaped callers. The baseline DSM-code mapping (no
        per-method overrides) is what this test pins down.
        """
        from synology_filestation import Client

        httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
            {"success": True, "data": {"sid": "s"}}
        )
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {"success": False, "error": {"code": code}}
        )

        host, port = host_port
        c = Client.login(host, port, "alice", "secret", https=False, auto_relogin=False)
        with pytest.raises(expected_cls):
            c.delete("/share/x")

    def test_unknown_code_raises_dsm_error_with_code_attribute(
        self, httpserver, host_port
    ):
        httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
            {"success": True, "data": {"sid": "s"}}
        )
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {"success": False, "error": {"code": 9999}}
        )

        host, port = host_port
        c = Client.login(host, port, "alice", "secret", https=False, auto_relogin=False)
        with pytest.raises(DSMError) as excinfo:
            c.getinfo("/share/x")
        assert excinfo.value.code == 9999
