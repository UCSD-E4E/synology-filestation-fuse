"""Tests for the auto-relogin session-expiry recovery path.

The contract: when ``Client.login(..., auto_relogin=True)`` is used, an
``ApiError(119)`` from any operation triggers a transparent re-authentication
followed by exactly one retry. The caller never sees ``SidNotFound`` unless
the re-login itself fails.
"""
from __future__ import annotations

import json

import pytest

from synology_filestation import Client, SidNotFound


def _login_response(sid: str = "fresh") -> dict:
    return {"success": True, "data": {"sid": sid}}


class TestAutoRelogin:
    def test_119_triggers_relogin_then_retry_success(
        self, httpserver, host_port, tmp_path
    ):
        # Login → ok. download → 119, then payload bytes.
        httpserver.expect_request(
            "/webapi/auth.cgi"
        ).respond_with_json(_login_response("first"))

        # First download attempt: 119 in JSON envelope.
        httpserver.expect_oneshot_request("/webapi/entry.cgi").respond_with_data(
            json.dumps({"success": False, "error": {"code": 119}}),
            content_type="application/json",
        )
        # Subsequent: real bytes.
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b"recovered after relogin",
            content_type="application/octet-stream",
        )

        host, port = host_port
        c = Client.login(host, port, "alice", "secret", https=False, auto_relogin=True)
        dest = tmp_path / "out.bin"
        c.download_to("/share/file.bin", str(dest))

        assert dest.read_bytes() == b"recovered after relogin"

    def test_119_with_relogin_failure_raises_auth_error(self, httpserver, host_port):
        # First login: ok. Second login (the re-login): fails with bad creds.
        # The download repeatedly returns 119.
        httpserver.expect_oneshot_request(
            "/webapi/auth.cgi"
        ).respond_with_json(_login_response())
        httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
            {"success": False, "error": {"code": 400}}
        )

        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            json.dumps({"success": False, "error": {"code": 119}}),
            content_type="application/json",
        )

        host, port = host_port
        c = Client.login(host, port, "alice", "secret", https=False, auto_relogin=True)

        # Re-login failure (auth error 400) should surface — not the original 119.
        from synology_filestation import AuthError

        with pytest.raises(AuthError):
            c.download("/share/file.bin")

    def test_119_with_no_auto_relogin_surfaces_sid_not_found(
        self, httpserver, host_port
    ):
        # auto_relogin=False (default in our test fixture): 119 reaches caller.
        httpserver.expect_request(
            "/webapi/auth.cgi"
        ).respond_with_json(_login_response())
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            json.dumps({"success": False, "error": {"code": 119}}),
            content_type="application/json",
        )

        host, port = host_port
        c = Client.login(host, port, "alice", "secret", https=False, auto_relogin=False)

        with pytest.raises(SidNotFound):
            c.download("/share/file.bin")

    def test_persistent_119_only_retries_once(self, httpserver, host_port):
        """If both the initial call and the retry return 119, the binding
        must not loop forever — it gives up and raises."""
        httpserver.expect_request(
            "/webapi/auth.cgi"
        ).respond_with_json(_login_response())
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            json.dumps({"success": False, "error": {"code": 119}}),
            content_type="application/json",
        )

        host, port = host_port
        c = Client.login(host, port, "alice", "secret", https=False, auto_relogin=True)

        # The retry also returns 119. Caller sees SidNotFound (or the
        # re-login was successful but the operation still failed; either way
        # the call must terminate).
        with pytest.raises(SidNotFound):
            c.download("/share/file.bin")
