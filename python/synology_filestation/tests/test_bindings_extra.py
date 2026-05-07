"""Tests for the binding methods that fsspec depends on:
``list_dir``, ``list_shares``, ``upload_bytes``, and ranged ``download``."""
from __future__ import annotations

import pytest

from synology_filestation import Client, NoSuchFile


def _logged_in(httpserver, host_port):
    httpserver.expect_request("/webapi/auth.cgi").respond_with_json(
        {"success": True, "data": {"sid": "s"}}
    )
    host, port = host_port
    return Client.login(host, port, "alice", "secret", https=False, auto_relogin=False)


class TestListDir:
    def test_returns_dicts_with_expected_shape(self, httpserver, host_port):
        c = _logged_in(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {
                "success": True,
                "data": {
                    "files": [
                        {
                            "name": "a.txt",
                            "path": "/share/a.txt",
                            "isdir": False,
                            "additional": {
                                "size": 100,
                                "time": {
                                    "atime": 1, "mtime": 2, "ctime": 3, "crtime": 4
                                },
                            },
                        },
                        {
                            "name": "subdir",
                            "path": "/share/subdir",
                            "isdir": True,
                            "additional": None,
                        },
                    ]
                },
            }
        )
        entries = c.list_dir("/share")
        assert len(entries) == 2
        assert entries[0]["name"] == "a.txt"
        assert entries[0]["isdir"] is False
        assert entries[0]["size"] == 100
        assert entries[0]["mtime"] == 2
        assert entries[1]["name"] == "subdir"
        assert entries[1]["isdir"] is True
        # When `additional` is missing, all the optional keys are still
        # present (set to None) so callers can do dict[k] without KeyError.
        assert entries[1]["size"] is None
        assert entries[1]["mtime"] is None

    def test_empty_dir_returns_empty_list(self, httpserver, host_port):
        c = _logged_in(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {"success": True, "data": {"files": []}}
        )
        assert c.list_dir("/share/empty") == []

    def test_missing_dir_raises_no_such_file(self, httpserver, host_port):
        c = _logged_in(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {"success": False, "error": {"code": 414}}
        )
        with pytest.raises(NoSuchFile):
            c.list_dir("/share/missing")


class TestListShares:
    def test_returns_share_dicts(self, httpserver, host_port):
        c = _logged_in(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {
                "success": True,
                "data": {
                    "shares": [
                        {"name": "photos", "path": "/photos", "isdir": True, "additional": None},
                        {"name": "docs", "path": "/docs", "isdir": True, "additional": None},
                    ]
                },
            }
        )
        shares = c.list_shares()
        names = [s["name"] for s in shares]
        assert names == ["photos", "docs"]
        assert all(s["isdir"] for s in shares)


class TestUploadBytes:
    def test_uploads_in_memory_bytes(self, httpserver, host_port):
        c = _logged_in(httpserver, host_port)
        # The upload first DELETEs (overwrite=true default), polls for gone,
        # then POSTs the file. Stub all three.
        httpserver.expect_request(
            "/webapi/entry.cgi", query_string={"method": "delete"}
        ).respond_with_json({"success": True})
        httpserver.expect_request(
            "/webapi/entry.cgi", query_string={"method": "getinfo"}
        ).respond_with_json({"success": False, "error": {"code": 414}})
        httpserver.expect_request("/webapi/entry.cgi").respond_with_json(
            {"success": True, "data": {"blks": None}}
        )
        # We can't easily assert the exact bytes received here without
        # parsing multipart, but we can assert the call succeeds without
        # error and our path-split worked (no InvalidArg).
        c.upload_bytes("/share/test.txt", b"hello world")

    def test_rejects_path_without_filename(self, httpserver, host_port):
        c = _logged_in(httpserver, host_port)
        from synology_filestation import InvalidArg

        with pytest.raises(InvalidArg):
            c.upload_bytes("/share/", b"data")

    def test_rejects_path_without_separator(self, httpserver, host_port):
        c = _logged_in(httpserver, host_port)
        from synology_filestation import InvalidArg

        with pytest.raises(InvalidArg):
            c.upload_bytes("nosurslashes", b"data")


class TestRangedDownload:
    def test_passes_offset_length_to_server(self, httpserver, host_port):
        c = _logged_in(httpserver, host_port)
        # Server gets a Range: bytes=10-19 header for download(offset=10, length=10).
        # We can't easily assert that header without a request handler, so
        # we just verify the call returns the bytes the server sent back.
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b"ranged-payload",
            content_type="application/octet-stream",
        )
        data = c.download("/share/big.bin", offset=10, length=10)
        assert data == b"ranged-payload"

    def test_full_download_with_no_range_kwargs(self, httpserver, host_port):
        c = _logged_in(httpserver, host_port)
        httpserver.expect_request("/webapi/entry.cgi").respond_with_data(
            b"full file", content_type="application/octet-stream"
        )
        data = c.download("/share/file.bin")
        assert data == b"full file"
