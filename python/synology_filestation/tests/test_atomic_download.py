"""The fishsense regression tests.

The bug being prevented: synology-api's ``get_file(mode='download')`` opens
the destination in ``'wb'`` mode (truncating to 0 bytes), and when DSM
returns ``200 OK`` with body ``{"success":false,"error":{"code":119}}``
the call returns an error tuple the caller doesn't inspect — leaving a
zero-byte file at the final destination.

These tests pin down the fix:
  * ``download_to(remote, local)`` writes to a temp path first.
  * On any failure (DSM JSON-error envelope, network drop, mid-stream
    abort) the destination must NOT exist on disk and the temp file must
    be cleaned up.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from synology_filestation import Client, SidNotFound


def _logged_in_client(httpserver, host_port, *, auto_relogin: bool = False):
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "test-sid"}}
    )
    host, port = host_port
    return Client.login(
        host, port, "alice", "secret", https=False, auto_relogin=auto_relogin
    )


class TestAtomicDownload:
    def test_happy_path_writes_complete_file(
        self, httpserver, host_port, tmp_path: Path
    ):
        c = _logged_in_client(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b"hello from the NAS", content_type="application/octet-stream"
        )
        dest = tmp_path / "out.bin"
        c.download_to("/share/file.bin", str(dest))
        assert dest.read_bytes() == b"hello from the NAS"
        # No leftover .part file.
        assert not (tmp_path / "out.bin.part").exists()

    def test_dsm_json_error_does_not_create_zero_byte_file(
        self, httpserver, host_port, tmp_path: Path
    ):
        """**The fishsense regression test.**

        DSM replies ``200 OK`` with a JSON error envelope. Old behavior:
        ``open('wb')`` truncates the destination, then the function returns
        without writing anything, leaving a 0-byte file. New behavior:
        ``download_to`` raises ``SidNotFound`` and the destination is never
        created.
        """
        c = _logged_in_client(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b'{"success":false,"error":{"code":119}}',
            content_type="application/json",
        )
        dest = tmp_path / "should_not_exist.bin"

        with pytest.raises(SidNotFound):
            c.download_to("/share/file.bin", str(dest))

        assert not dest.exists(), (
            "destination must not exist after a failed download — no zero-byte stub"
        )
        assert not (tmp_path / "should_not_exist.bin.part").exists(), (
            ".part tmp file must be cleaned up on failure"
        )

    def test_dsm_permission_denied_does_not_create_destination(
        self, httpserver, host_port, tmp_path: Path
    ):
        c = _logged_in_client(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b'{"success":false,"error":{"code":408}}',
            content_type="application/json",
        )
        dest = tmp_path / "denied.bin"

        from synology_filestation import PermissionDenied

        with pytest.raises(PermissionDenied):
            c.download_to("/share/file.bin", str(dest))
        assert not dest.exists()

    def test_writes_to_part_file_then_renames(
        self, httpserver, host_port, tmp_path: Path
    ):
        # Sanity check that the .part path is in fact what's written first:
        # if we look at the directory immediately after a successful download,
        # only the final file should be present (rename happened).
        c = _logged_in_client(httpserver, host_port)
        payload = b"renamed atomically"
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            payload, content_type="application/octet-stream"
        )
        dest = tmp_path / "atomic.bin"
        c.download_to("/share/file.bin", str(dest))

        assert dest.read_bytes() == payload
        assert sorted(p.name for p in tmp_path.iterdir()) == ["atomic.bin"]

    def test_does_not_overwrite_existing_destination_on_failure(
        self, httpserver, host_port, tmp_path: Path
    ):
        """If the destination already exists and the download fails, the
        existing file must be left intact. This is a stricter form of the
        zero-byte-stub test."""
        c = _logged_in_client(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b'{"success":false,"error":{"code":119}}',
            content_type="application/json",
        )

        dest = tmp_path / "preexisting.bin"
        dest.write_bytes(b"original content do not touch")
        before = dest.read_bytes()

        with pytest.raises(SidNotFound):
            c.download_to("/share/file.bin", str(dest))

        # Failure must not have replaced the existing file.
        assert dest.read_bytes() == before
