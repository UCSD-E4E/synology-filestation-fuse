# synology-filestation

Python bindings for the Synology FileStation HTTP client (Rust core via PyO3).

This package is a drop-in replacement for the `synology-api` PyPI package's
FileStation surface, designed to fix three concrete footguns:

1. **DSM JSON-error responses are typed exceptions, not silent successes.**
   When DSM returns `200 OK` with body `{"success":false,"error":{"code":119}}`,
   `download` raises `SidNotFound`, not bytes.

2. **Atomic downloads.** `download_to(remote, local)` writes to `<local>.part`
   first, fsyncs, then renames. The destination either contains the complete
   file or doesn't exist — no zero-byte stubs after a failed download.

3. **Transparent session-expiry recovery.** Long-running scripts can opt into
   auto-relogin: when the DSM SID expires (~30 min idle), the client
   re-authenticates and retries the operation once. The caller never sees
   `SidNotFound` unless the re-login itself fails.

## Installation

```bash
pip install synology-filestation
```

## Usage

```python
from synology_filestation import Client

with Client.login("nas.example.com", 5001, "alice", "secret") as nas:
    if nas.exists("/photos/2026"):
        info = nas.getinfo("/photos/2026")
        print(info["size"])
    nas.download_to("/photos/2026/img.orf", "/tmp/img.orf")
```

Async API:

```python
from synology_filestation.aio import AsyncClient

async with AsyncClient.login("nas.example.com", 5001, "alice", "secret") as nas:
    data = await nas.download("/photos/2026/img.orf")
```

## fsspec backend

`pip install synology-filestation[fsspec]` registers the `synofs` protocol so you can use FileStation with any fsspec-aware tool (pandas, dask, polars, pyarrow):

```python
import fsspec

fs = fsspec.filesystem(
    "synofs",
    host="nas.example.com", port=5001,
    username="alice", password="secret",
)

# Atomic get — inherits download_to's <local>.part + rename semantics, so a
# DSM error never leaves a 0-byte file at the destination.
fs.get("/photos/2026/img.orf", "/tmp/img.orf")

# Or as pandas storage_options
import pandas as pd
df = pd.read_csv(
    "synofs://share/data.csv",
    storage_options={
        "host": "nas.example.com", "port": 5001,
        "username": "alice", "password": "secret",
    },
)
```

Both sync and async fsspec APIs are supported — `fs._cat_file(path)` returns an awaitable; `fs.cat_file(path)` is the auto-generated sync wrapper.

## Exceptions

```
FileStationError                  # base
├── AuthError                     # login failed
│   └── SidNotFound               # SID expired / not found (DSM code 119)
├── NoSuchFile                    # codes 403, 414, 415
├── PermissionDenied              # codes 408, 1805
├── AlreadyExists                 # codes 418, 1101
├── NoSpace                       # codes 419, 1804
├── NotEmpty                      # code 416
├── InvalidArg                    # code 400
├── NotSupported                  # operation not supported
├── TransportError                # network or parse error
└── DSMError                      # any unmapped DSM code; `.code` is set
```

All exceptions carry `.code` (the DSM error code, or `None`) and `.message`.
