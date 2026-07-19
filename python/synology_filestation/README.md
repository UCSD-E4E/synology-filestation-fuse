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

4. **Built-in throttle so bulk transfers can't take the NAS down.** Downloads
   and uploads are capped to a small concurrency, spaced by a rate-limit belt,
   and retried with bounded jittered backoff. On by default — see
   [Throttling & reliability](#throttling--reliability).

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

## Throttling & reliability

The FileStation Download API is proxied through `nginx → synoscgi`, a shared
per-request CGI backend for the whole appliance. It is sized for a handful of
large streams, **not** a task-per-file fan-out. Parallel downloads — not total
volume — are what saturate it, and an inner retry storm (the same file fetched
hundreds of times) turns a blip into an outage.

Every `Client` / `AsyncClient` therefore ships with a throttle, **enabled by
default**, that wraps `download`/`download_to`/`upload`:

| Lever | Default | What it does |
|---|---|---|
| `max_concurrency` | `4` | Global semaphore around all transfer calls. Single-digit — a few big streams, not one request per file. |
| `min_interval_ms` | `150` | Rate-limit belt: minimum spacing between request starts, even at full concurrency. |
| `max_attempts` | `5` | Hard per-file retry cap. Once exhausted the error is raised — no unbounded inner loop. |
| `backoff_base_ms` / `backoff_max_ms` | `1000` / `60000` | Full-jitter exponential backoff between attempts (1s → 60s). |

```python
# Defaults are conservative; tune per-workload or disable with throttle=False.
nas = Client.login(
    "nas.example.com", 5001, "alice", "secret",
    max_concurrency=3,      # ≈3–4 is the safe band for synoscgi
    min_interval_ms=200,
    max_attempts=5,
)
```

**Error classification.** The throttle distinguishes transient from permanent
failures so it never retries something a retry can't fix:

- **Transient → back off + bounded retry:** HTTP 502/503/504, HTTP 407 (the
  backend fail-closing), connection/read errors, and DSM 402 *system busy*
  (backed off *harder*).
- **Permanent → fail fast, no retry:** missing file / no permission / invalid
  argument and any other DSM code. Retrying these wastes the backend's
  attention exactly like a 502 storm.

### Using this under Temporal (or any outer retry policy)

This client caps retries at `max_attempts` **and then raises** — deliberately.
Do **not** wrap it in your own inner retry loop. Let the failure propagate out
of the activity and let Temporal's retry policy reschedule it with its own
(longer, jittered) backoff. Two nested retry loops are exactly what produced the
200–250×-per-file storm that saturated the appliance. One activity ≈ one file;
bound the work here, reschedule out there.

## Bulk staging: prefer SMB/NFS over the Download API

For sustained bulk transfer of large binaries (e.g. staging raw `.ORF` frames),
the **structural fix is to not use the HTTP Download API at all**. It is an
interactive file-browser endpoint; streaming gigabytes through `synoscgi` is
outside what it is built for.

If your host can mount the share over **SMB or NFS** (the UCSD campus firewall
already permits both), read the bytes straight off the mounted share — that
bypasses `synoscgi` entirely, so there is no CGI backend to saturate. Treat this
package's HTTP Download path as the **fallback**, not the default, for bulk raw
staging. The throttle above is the safety net for when the API path must be
used; SMB/NFS is how you avoid needing it.

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
