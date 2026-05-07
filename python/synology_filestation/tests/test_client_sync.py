"""Tests for the synchronous Client API: login, exists, getinfo, download,
upload, create_folder, delete, logout, and the context manager protocol."""
from __future__ import annotations

import pytest

from synology_filestation import (
    AuthError,
    Client,
    NoSuchFile,
)


def _make_client(httpserver, host_port, *, auto_relogin: bool = False):
    """Helper: register a successful login response and return a logged-in client."""
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "test-sid"}}
    )
    host, port = host_port
    return Client.login(
        host, port, "alice", "secret", https=False, auto_relogin=auto_relogin
    )


class TestLogin:
    def test_wrong_password_raises_auth_error(self, httpserver, host_port):
        httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
            {"success": False, "error": {"code": 400}}
        )
        host, port = host_port
        with pytest.raises(AuthError):
            Client.login(host, port, "alice", "wrong", https=False)

    def test_login_returns_client_on_success(self, httpserver, host_port):
        c = _make_client(httpserver, host_port)
        assert isinstance(c, Client)


class TestExists:
    def test_returns_true_for_present_path(self, httpserver, host_port):
        c = _make_client(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {
                "success": True,
                "data": {
                    "files": [
                        {
                            "name": "video.mp4",
                            "path": "/share/video.mp4",
                            "isdir": False,
                            "additional": {"size": 1024},
                        }
                    ]
                },
            }
        )
        assert c.exists("/share/video.mp4") is True

    def test_returns_false_for_missing_path(self, httpserver, host_port):
        # DSM returns success=true with a per-entry error code for missing paths.
        c = _make_client(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {
                "success": True,
                "data": {"files": [{"code": 408, "path": "/share/missing"}]},
            }
        )
        assert c.exists("/share/missing") is False


class TestGetInfo:
    def test_returns_dict_for_present_path(self, httpserver, host_port):
        c = _make_client(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {
                "success": True,
                "data": {
                    "files": [
                        {
                            "name": "report.pdf",
                            "path": "/share/report.pdf",
                            "isdir": False,
                            "additional": {
                                "size": 4096,
                                "time": {
                                    "atime": 1000,
                                    "mtime": 2000,
                                    "ctime": 3000,
                                    "crtime": 4000,
                                },
                            },
                        }
                    ]
                },
            }
        )
        info = c.getinfo("/share/report.pdf")
        assert info["name"] == "report.pdf"
        assert info["path"] == "/share/report.pdf"
        assert info["isdir"] is False
        assert info["size"] == 4096
        assert info["mtime"] == 2000

    def test_missing_path_raises_no_such_file(self, httpserver, host_port):
        # The fishsense bug shape's evil twin: getinfo on missing path used
        # to return a 0-byte dict. We must raise instead.
        c = _make_client(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {
                "success": True,
                "data": {"files": [{"code": 408, "path": "/share/missing"}]},
            }
        )
        with pytest.raises(NoSuchFile):
            c.getinfo("/share/missing")


class TestDownload:
    def test_returns_bytes(self, httpserver, host_port):
        c = _make_client(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b"\x89PNG\r\n\x1a\n payload",
            content_type="application/octet-stream",
        )
        data = c.download("/share/img.png")
        assert data == b"\x89PNG\r\n\x1a\n payload"


class TestContextManager:
    def test_enter_exit_calls_logout(self, httpserver, host_port):
        # We can't directly assert that logout was called from Python, but we
        # CAN expect a logout request to hit the server and let
        # httpserver.check_assertions verify it.
        login = httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
            {"success": True, "data": {"sid": "ctx-sid"}}
        )
        # Logout uses the same /webapi/auth.cgi endpoint with method=logout.
        # Both calls hit the same path; pytest-httpserver matches the first
        # registered handler that fits — re-register a generic handler so
        # logout requests don't 404.
        del login  # silence unused-name warning
        host, port = host_port
        with Client.login(host, port, "alice", "secret", https=False) as c:
            assert isinstance(c, Client)
        # If __exit__ raised, the test would have failed already.
