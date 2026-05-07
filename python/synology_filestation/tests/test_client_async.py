"""Async API smoke tests.

The async client mirrors the sync surface; we cover one happy-path test per
operation plus the SID-expiry recovery and atomic-download regressions, since
those are the contract guarantees that distinguish this package from the
``synology-api`` PyPI library.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from synology_filestation import (
    AuthError,
    NoSuchFile,
    PermissionDenied,
    SidNotFound,
)
from synology_filestation.aio import AsyncClient


pytestmark = pytest.mark.asyncio


async def test_login_returns_async_client(httpserver, host_port):
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "async-sid"}}
    )
    host, port = host_port
    c = await AsyncClient.login(host, port, "alice", "secret", https=False)
    assert isinstance(c, AsyncClient)


async def test_login_wrong_password_raises_auth_error(httpserver, host_port):
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": False, "error": {"code": 400}}
    )
    host, port = host_port
    with pytest.raises(AuthError):
        await AsyncClient.login(host, port, "alice", "wrong", https=False)


async def test_download_returns_bytes(httpserver, host_port):
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "s"}}
    )
    httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
        b"async download payload",
        content_type="application/octet-stream",
    )
    host, port = host_port
    c = await AsyncClient.login(host, port, "alice", "secret", https=False)
    data = await c.download("/share/file.bin")
    assert data == b"async download payload"


async def test_getinfo_missing_path_raises_no_such_file(httpserver, host_port):
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "s"}}
    )
    httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
        {
            "success": True,
            "data": {"files": [{"code": 408, "path": "/share/missing"}]},
        }
    )
    host, port = host_port
    c = await AsyncClient.login(host, port, "alice", "secret", https=False)
    with pytest.raises(NoSuchFile):
        await c.getinfo("/share/missing")


async def test_exists_returns_bool(httpserver, host_port):
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "s"}}
    )
    httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
        {
            "success": True,
            "data": {
                "files": [
                    {
                        "name": "x",
                        "path": "/share/x",
                        "isdir": False,
                        "additional": {"size": 1},
                    }
                ]
            },
        }
    )
    host, port = host_port
    c = await AsyncClient.login(host, port, "alice", "secret", https=False)
    assert await c.exists("/share/x") is True


async def test_download_to_no_zero_byte_file_on_dsm_error(
    httpserver, host_port, tmp_path: Path
):
    """Async equivalent of the fishsense regression test."""
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "s"}}
    )
    httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
        json.dumps({"success": False, "error": {"code": 119}}),
        content_type="application/json",
    )
    host, port = host_port
    c = await AsyncClient.login(
        host, port, "alice", "secret", https=False, auto_relogin=False
    )

    dest = tmp_path / "must_not_exist.bin"
    with pytest.raises(SidNotFound):
        await c.download_to("/share/file.bin", str(dest))
    assert not dest.exists()
    assert not (tmp_path / "must_not_exist.bin.part").exists()


async def test_119_triggers_relogin_then_retry_success(
    httpserver, host_port, tmp_path: Path
):
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "any"}}
    )
    httpserver.expect_oneshot_request("/webapi/entry.cgi").respond_with_data(
        json.dumps({"success": False, "error": {"code": 119}}),
        content_type="application/json",
    )
    httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
        b"async recovered",
        content_type="application/octet-stream",
    )
    host, port = host_port
    c = await AsyncClient.login(
        host, port, "alice", "secret", https=False, auto_relogin=True
    )
    dest = tmp_path / "recovered.bin"
    await c.download_to("/share/file.bin", str(dest))
    assert dest.read_bytes() == b"async recovered"


async def test_dsm_permission_denied_async(httpserver, host_port):
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "s"}}
    )
    httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
        {"success": False, "error": {"code": 1805}}
    )
    host, port = host_port
    c = await AsyncClient.login(host, port, "alice", "secret", https=False)
    with pytest.raises(PermissionDenied):
        await c.delete("/share/locked")
