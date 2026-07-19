"""Throttle surface on the Python client.

The throttle itself (concurrency cap, rate belt, jittered backoff, error
classification, per-file attempt cap) is exercised exhaustively in the Rust
core's unit tests. These tests pin the *binding* contract: the kwargs exist and
default sensibly, opting out works, and the transient-vs-permanent
classification is wired through — a permanent DSM error is raised without an
inner retry storm (the behavior the NAS incident demanded).
"""
from __future__ import annotations

from typing import Iterator

from pytest_httpserver import HTTPServer

from synology_filestation import Client, NoSuchFile

LOGIN_OK = {"success": True, "data": {"sid": "test-sid-123"}}
DSM_415 = {"success": False, "error": {"code": 415}}  # No such file/folder


def _download_requests(httpserver: HTTPServer) -> list:
    """Every recorded request that was a FileStation download call."""
    return [
        req
        for req, _resp in httpserver.log
        if req.path == "/webapi/entry.cgi" and b"method=download" in req.query_string
    ]


def _login(httpserver: HTTPServer, **throttle_kwargs) -> Client:
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(LOGIN_OK)
    return Client.login(
        httpserver.host,
        httpserver.port,
        "alice",
        "secret",
        https=False,
        auto_relogin=False,
        **throttle_kwargs,
    )


class TestThrottleSurface:
    def test_login_accepts_throttle_kwargs_and_downloads(self, httpserver: HTTPServer):
        c = _login(
            httpserver,
            max_concurrency=2,
            min_interval_ms=0,
            max_attempts=5,
            backoff_base_ms=1,
            backoff_max_ms=5,
        )
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b"payload", content_type="application/octet-stream"
        )
        assert c.download("/share/f.bin") == b"payload"

    def test_throttle_can_be_disabled(self, httpserver: HTTPServer):
        c = _login(httpserver, throttle=False)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b"unthrottled", content_type="application/octet-stream"
        )
        assert c.download("/share/f.bin") == b"unthrottled"

    def test_permanent_error_is_not_retried(self, httpserver: HTTPServer):
        # A missing-file download must fail fast — no inner retry loop, even
        # though max_attempts allows 5. Exactly one download request hits the
        # server. min_interval_ms=0 keeps the test quick.
        c = _login(httpserver, min_interval_ms=0, max_attempts=5)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(DSM_415)

        try:
            c.download("/share/missing.bin")
            raised = None
        except NoSuchFile as e:  # codes 403/414/415
            raised = e

        assert raised is not None, "expected NoSuchFile for DSM 415"
        assert len(_download_requests(httpserver)) == 1, "permanent error was retried"
