//! C ABI bindings for the Synology FileStation client and mount driver.
//!
//! Consumed by the desktop GUI via P/Invoke. The design mirrors the PyO3
//! binding ([`python/synology_filestation`]): an opaque [`SynoClient`] wraps an
//! `Arc<SynologyClient>` plus a per-client Tokio runtime, and every blocking
//! call funnels through `runtime.block_on`. Errors are reported through a
//! [`SynoError`] out-param carrying a typed `kind`, the raw DSM code, and a
//! human-readable message; the `kind`/`dsm_code` classification mirrors the
//! PyO3 exception mapping so both bindings agree.
//!
//! Every exported function wraps its body in `catch_unwind`: a panic in the
//! Rust core (or, for the mount, the WinFsp worker thread) is converted to a
//! `Panic` status rather than unwinding across the FFI boundary (UB).

use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;

use synology_filestation_core::client::SynologyClient;
use synology_filestation_core::error::SynoFsError;
use synology_filestation_core::types::SynoFileInfo;
use synology_filestation_fuse::{is_otp_required, spawn_mount, MountOptions};
use tokio::runtime::Runtime;

mod logging;

const DOWNLOAD_CHUNK: u64 = 4 * 1024 * 1024;

// ─── Status / error reporting ────────────────────────────────────────────────

/// Status codes returned by every fallible export. `Ok` is 0; the rest mirror
/// the `SynoFsError` variants, plus a few FFI-specific cases.
#[repr(i32)]
#[derive(Clone, Copy)]
pub enum SynoStatus {
    Ok = 0,
    NotFound = 1,
    PermissionDenied = 2,
    AlreadyExists = 3,
    NotEmpty = 4,
    InvalidArg = 5,
    NoSpace = 6,
    NotSupported = 7,
    Io = 8,
    Api = 9,
    LoginFailed = 10,
    /// Login needs a 2FA / OTP code — the GUI should prompt and retry connect.
    OtpRequired = 11,
    /// A required pointer argument was null.
    NullArg = 12,
    /// A panic was caught at the FFI boundary.
    Panic = 13,
}

/// Out-param filled on error. `message` is a heap UTF-8 C string owned by the
/// caller; free it with [`syno_string_free`]. `dsm_code` is the raw Synology
/// API code when applicable, else 0.
#[repr(C)]
pub struct SynoError {
    pub kind: i32,
    pub dsm_code: u32,
    pub message: *mut c_char,
}

/// Map a core error to (typed status, raw DSM code). Mirrors the PyO3
/// `synofs_to_pyerr` routing so the GUI sees the same classes the Python
/// bindings expose.
fn classify(err: &SynoFsError) -> (SynoStatus, u32) {
    use SynoStatus as S;
    match err {
        SynoFsError::NotFound => (S::NotFound, 0),
        SynoFsError::PermissionDenied => (S::PermissionDenied, 0),
        SynoFsError::AlreadyExists => (S::AlreadyExists, 0),
        SynoFsError::NotEmpty => (S::NotEmpty, 0),
        SynoFsError::InvalidArg => (S::InvalidArg, 0),
        SynoFsError::NoSpace => (S::NoSpace, 0),
        SynoFsError::NotSupported => (S::NotSupported, 0),
        SynoFsError::Io(_) => (S::Io, 0),
        SynoFsError::LoginFailed(inner) => {
            let code = match inner.as_ref() {
                SynoFsError::ApiError(c) => *c,
                _ => 0,
            };
            (S::LoginFailed, code)
        }
        SynoFsError::ApiError(c) => {
            let s = match *c {
                400 => S::InvalidArg,
                403 | 414 | 415 => S::NotFound,
                408 | 1805 => S::PermissionDenied,
                416 => S::NotEmpty,
                418 | 1101 => S::AlreadyExists,
                419 | 1804 => S::NoSpace,
                _ => S::Api,
            };
            (s, *c)
        }
    }
}

/// Write a status + message into `*err` (if non-null) and return the status as
/// an `i32`. Always returns the numeric status so callers can `return set_err(…)`.
unsafe fn set_err(err: *mut SynoError, status: SynoStatus, dsm: u32, message: &str) -> i32 {
    if !err.is_null() {
        let msg = CString::new(message).unwrap_or_default().into_raw();
        (*err).kind = status as i32;
        (*err).dsm_code = dsm;
        (*err).message = msg;
    }
    status as i32
}

unsafe fn set_core_err(err: *mut SynoError, e: &SynoFsError) -> i32 {
    let (status, dsm) = classify(e);
    set_err(err, status, dsm, &e.to_string())
}

/// Run `f`, converting any panic into a `Panic` status written to `err`.
fn guard<F: FnOnce() -> i32>(err: *mut SynoError, f: F) -> i32 {
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => unsafe { set_err(err, SynoStatus::Panic, 0, "panic in native code") },
    }
}

/// Borrow a required C string; returns `Err(status)` (already written to `err`)
/// when null or non-UTF-8.
unsafe fn req_str<'a>(p: *const c_char, name: &str, err: *mut SynoError) -> Result<&'a str, i32> {
    if p.is_null() {
        return Err(set_err(
            err,
            SynoStatus::NullArg,
            0,
            &format!("`{name}` must not be null"),
        ));
    }
    CStr::from_ptr(p).to_str().map_err(|_| {
        set_err(
            err,
            SynoStatus::InvalidArg,
            0,
            &format!("`{name}` is not UTF-8"),
        )
    })
}

/// Borrow an optional C string (null → `None`).
unsafe fn opt_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        CStr::from_ptr(p).to_str().ok()
    }
}

// ─── JSON marshalling of file info ───────────────────────────────────────────

/// Flatten a `SynoFileInfo` into a stable, documented JSON shape. Keys are
/// always present (null when absent) so the C# side can deserialize into a
/// fixed record. Mirrors the PyO3 `fileinfo_to_pydict` contract.
fn fileinfo_json(info: &SynoFileInfo) -> serde_json::Value {
    let (size, mtime, atime, ctime, perm) = match &info.additional {
        Some(a) => (
            a.size,
            a.time.as_ref().map(|t| t.mtime),
            a.time.as_ref().map(|t| t.atime),
            a.time.as_ref().map(|t| t.ctime),
            a.perm.as_ref().map(|p| p.posix),
        ),
        None => (None, None, None, None, None),
    };
    serde_json::json!({
        "name": info.name,
        "path": info.path,
        "isdir": info.isdir,
        "size": size,
        "mtime": mtime,
        "atime": atime,
        "ctime": ctime,
        "perm": perm,
    })
}

unsafe fn emit_json(out: *mut *mut c_char, value: &serde_json::Value, err: *mut SynoError) -> i32 {
    if out.is_null() {
        return set_err(
            err,
            SynoStatus::NullArg,
            0,
            "output pointer must not be null",
        );
    }
    match CString::new(value.to_string()) {
        Ok(s) => {
            *out = s.into_raw();
            SynoStatus::Ok as i32
        }
        Err(_) => set_err(
            err,
            SynoStatus::Io,
            0,
            "result contained an interior NUL byte",
        ),
    }
}

// ─── Opaque handles ──────────────────────────────────────────────────────────

/// Opaque authenticated client handle.
pub struct SynoClient {
    inner: Arc<SynologyClient>,
    runtime: Arc<Runtime>,
}

/// Opaque live-mount handle.
pub struct SynoMount {
    handle: Option<synology_filestation_fuse::MountHandle>,
    // Keeps the runtime alive for the duration of the mount (the FUSE/WinFsp
    // callbacks block on it). Dropped after the mount is torn down.
    _runtime: Arc<Runtime>,
}

// ─── Connect / session lifecycle ─────────────────────────────────────────────

/// Log in and return an opaque client handle in `*out`.
///
/// Returns [`SynoStatus::OtpRequired`] (no client created) when the account
/// needs a 2FA code; the caller should prompt and call again with `otp` set.
///
/// # Safety
/// All string args must be valid NUL-terminated UTF-8 or null where optional.
#[no_mangle]
pub unsafe extern "C" fn syno_connect(
    host: *const c_char,
    port: u16,
    https: bool,
    username: *const c_char,
    password: *const c_char,
    otp: *const c_char,
    auto_relogin: bool,
    out: *mut *mut SynoClient,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let host = match req_str(host, "host", err) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let username = match req_str(username, "username", err) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let password = match req_str(password, "password", err) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let otp = opt_str(otp);
        if out.is_null() {
            return set_err(err, SynoStatus::NullArg, 0, "out pointer must not be null");
        }

        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(rt) => Arc::new(rt),
            Err(e) => {
                return set_err(
                    err,
                    SynoStatus::Io,
                    0,
                    &format!("failed to start runtime: {e}"),
                )
            }
        };

        let client = if auto_relogin {
            SynologyClient::with_auto_relogin(host, port, https)
        } else {
            SynologyClient::new(host, port, https)
        };

        match runtime.block_on(client.login(username, password, otp)) {
            Ok(()) => {
                let handle = Box::new(SynoClient {
                    inner: Arc::new(client),
                    runtime,
                });
                *out = Box::into_raw(handle);
                SynoStatus::Ok as i32
            }
            Err(e) if is_otp_required(&e) => set_err(
                err,
                SynoStatus::OtpRequired,
                0,
                "two-factor authentication code required",
            ),
            Err(e) => {
                // Present as a login failure regardless of the underlying code,
                // but preserve the DSM code in `dsm_code` for diagnostics.
                set_core_err(err, &SynoFsError::LoginFailed(Box::new(e)))
            }
        }
    })
}

/// Best-effort logout. Safe to call once; does not free the handle.
///
/// # Safety
/// `client` must be a live handle from [`syno_connect`] (or null).
#[no_mangle]
pub unsafe extern "C" fn syno_logout(client: *mut SynoClient) {
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if let Some(c) = client.as_ref() {
            let _ = c.runtime.block_on(c.inner.logout());
        }
    }));
}

/// Free a client handle. After this the pointer is invalid.
///
/// # Safety
/// `client` must have come from [`syno_connect`] and not been freed already.
#[no_mangle]
pub unsafe extern "C" fn syno_client_free(client: *mut SynoClient) {
    if !client.is_null() {
        drop(Box::from_raw(client));
    }
}

/// Free a string returned by this library (e.g. `SynoError::message` or any
/// `out_json`).
///
/// # Safety
/// `s` must have come from this library and not been freed already.
#[no_mangle]
pub unsafe extern "C" fn syno_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// ─── Helpers shared by the client ops ────────────────────────────────────────

/// Run an async op on the client's runtime with SID-expiry relogin retry.
unsafe fn run_op<F, Fut, T>(client: *mut SynoClient, op: F) -> Result<T, RunErr<SynoFsError>>
where
    F: Fn(Arc<SynologyClient>) -> Fut,
    Fut: std::future::Future<Output = Result<T, SynoFsError>>,
{
    let c = client.as_ref().ok_or(RunErr::Null)?;
    let inner = c.inner.clone();
    c.runtime
        .block_on(async { inner.with_relogin_retry(|| op(inner.clone())).await })
        .map_err(RunErr::Op)
}

enum RunErr<E> {
    Null,
    Op(E),
}

unsafe fn finish<T>(
    res: Result<T, RunErr<SynoFsError>>,
    err: *mut SynoError,
    on_ok: impl FnOnce(T) -> i32,
) -> i32 {
    match res {
        Ok(v) => on_ok(v),
        Err(RunErr::Null) => set_err(err, SynoStatus::NullArg, 0, "client must not be null"),
        Err(RunErr::Op(e)) => set_core_err(err, &e),
    }
}

// ─── Browse ──────────────────────────────────────────────────────────────────

/// List the top-level shares as a JSON array of file-info objects.
///
/// # Safety
/// `client` must be live; `out_json` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn syno_list_shares(
    client: *mut SynoClient,
    out_json: *mut *mut c_char,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let res = run_op(client, |c| async move { c.list_shares().await });
        finish(res, err, |items| {
            let arr: Vec<_> = items.iter().map(fileinfo_json).collect();
            emit_json(out_json, &serde_json::Value::Array(arr), err)
        })
    })
}

/// List a directory as a JSON array of file-info objects.
///
/// # Safety
/// `client` must be live; `path`/`out_json` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn syno_list_dir(
    client: *mut SynoClient,
    path: *const c_char,
    out_json: *mut *mut c_char,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let path = match req_str(path, "path", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let res = run_op(client, move |c| {
            let path = path.clone();
            async move { c.list_dir(&path).await }
        });
        finish(res, err, |items| {
            let arr: Vec<_> = items.iter().map(fileinfo_json).collect();
            emit_json(out_json, &serde_json::Value::Array(arr), err)
        })
    })
}

/// Get info for a single path as a JSON file-info object.
///
/// # Safety
/// `client` must be live; `path`/`out_json` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn syno_get_info(
    client: *mut SynoClient,
    path: *const c_char,
    out_json: *mut *mut c_char,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let path = match req_str(path, "path", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let res = run_op(client, move |c| {
            let path = path.clone();
            async move { c.get_info(&path).await }
        });
        finish(res, err, |info| {
            emit_json(out_json, &fileinfo_json(&info), err)
        })
    })
}

// ─── Transfers ───────────────────────────────────────────────────────────────

/// Progress callback: `(bytes_done, bytes_total, user_data)`. `total` is 0 when
/// the size is unknown.
pub type ProgressCb = extern "C" fn(done: u64, total: u64, user_data: *mut c_void);

fn report(cb: Option<ProgressCb>, user_data: *mut c_void, done: u64, total: u64) {
    if let Some(cb) = cb {
        cb(done, total, user_data);
    }
}

/// Download `remote` to `local`, reporting progress via the optional callback.
/// Streams the file in chunks so progress is fine-grained; writes to a
/// `.part` sidecar and renames on success for atomicity.
///
/// # Safety
/// `client` must be live; `remote`/`local` must be non-null. `progress` (if
/// non-null) and `user_data` must remain valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn syno_download_to(
    client: *mut SynoClient,
    remote: *const c_char,
    local: *const c_char,
    progress: Option<ProgressCb>,
    user_data: *mut c_void,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let remote = match req_str(remote, "remote", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let local = match req_str(local, "local", err) {
            Ok(v) => PathBuf::from(v),
            Err(c) => return c,
        };
        let c = match client.as_ref() {
            Some(c) => c,
            None => return set_err(err, SynoStatus::NullArg, 0, "client must not be null"),
        };
        let inner = c.inner.clone();

        // Stream into a `.part` sidecar, renamed on success for atomicity.
        // Computed out here so failure paths can clean it up (see below).
        let part = local.with_extension("part");

        let result: Result<(), SynoFsError> = c.runtime.block_on(async {
            use std::io::Write as _;

            // Determine total size up front for progress reporting.
            let total = inner
                .with_relogin_retry(|| inner.get_info(&remote))
                .await
                .ok()
                .and_then(|i| i.additional.and_then(|a| a.size))
                .unwrap_or(0);
            report(progress, user_data, 0, total);

            let mut file = std::fs::File::create(&part)
                .map_err(|e| SynoFsError::Io(format!("create {}: {e}", part.display())))?;

            let mut offset = 0u64;
            loop {
                let bytes = inner
                    .with_relogin_retry(|| inner.download(&remote, offset, DOWNLOAD_CHUNK))
                    .await?;
                if bytes.is_empty() {
                    break;
                }
                file.write_all(&bytes)
                    .map_err(|e| SynoFsError::Io(format!("write {}: {e}", part.display())))?;
                offset += bytes.len() as u64;
                // Report `total` as-is: 0 means "unknown" (the documented
                // contract). Using total.max(offset) would make an unknown-size
                // transfer report done == total every chunk, i.e. always 100%.
                report(progress, user_data, offset, total);
                // Stop at EOF: a short final chunk, or — when the size is known
                // and is an exact multiple of the chunk — having read it all
                // (avoids a spurious past-EOF range request).
                if (bytes.len() as u64) < DOWNLOAD_CHUNK || (total > 0 && offset >= total) {
                    break;
                }
            }
            file.flush()
                .map_err(|e| SynoFsError::Io(format!("flush {}: {e}", part.display())))?;
            drop(file);
            std::fs::rename(&part, &local)
                .map_err(|e| SynoFsError::Io(format!("rename into {}: {e}", local.display())))?;
            report(progress, user_data, offset, offset);
            Ok(())
        });

        match result {
            Ok(()) => SynoStatus::Ok as i32,
            Err(e) => {
                // Best-effort: don't leave a stale partial file behind on
                // failure (range error mid-transfer, rename failure, etc.).
                let _ = std::fs::remove_file(&part);
                set_core_err(err, &e)
            }
        }
    })
}

/// Upload `local` into the remote directory `remote_dir`. Progress is coarse
/// (0 → total) because the core upload is single-shot.
///
/// # Safety
/// `client` must be live; `local`/`remote_dir` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn syno_upload(
    client: *mut SynoClient,
    local: *const c_char,
    remote_dir: *const c_char,
    overwrite: bool,
    progress: Option<ProgressCb>,
    user_data: *mut c_void,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let local = match req_str(local, "local", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let remote_dir = match req_str(remote_dir, "remote_dir", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let c = match client.as_ref() {
            Some(c) => c,
            None => return set_err(err, SynoStatus::NullArg, 0, "client must not be null"),
        };

        // The core Upload API is single-shot (takes a full `Vec<u8>`), so the
        // whole file is buffered in memory — the same documented "write
        // buffering" limitation the CLI and PyO3 binding share. There is no
        // streaming path to prefer here; a streaming upload would have to land
        // in the core crate first.
        let data = match std::fs::read(&local) {
            Ok(d) => d,
            Err(e) => return set_err(err, SynoStatus::Io, 0, &format!("read {local}: {e}")),
        };
        let filename = match std::path::Path::new(&local)
            .file_name()
            .and_then(|n| n.to_str())
        {
            Some(n) => n.to_string(),
            None => return set_err(err, SynoStatus::InvalidArg, 0, "local path has no filename"),
        };
        let total = data.len() as u64;
        report(progress, user_data, 0, total);

        let inner = c.inner.clone();
        let result = c.runtime.block_on(async {
            inner
                .with_relogin_retry(|| {
                    inner.upload(&remote_dir, &filename, data.clone(), overwrite)
                })
                .await
        });
        match result {
            Ok(()) => {
                report(progress, user_data, total, total);
                SynoStatus::Ok as i32
            }
            Err(e) => set_core_err(err, &e),
        }
    })
}

/// Delete a file or directory.
///
/// # Safety
/// `client` must be live; `path` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn syno_delete(
    client: *mut SynoClient,
    path: *const c_char,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let path = match req_str(path, "path", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let res = run_op(client, move |c| {
            let path = path.clone();
            async move { c.delete(&path).await }
        });
        finish(res, err, |()| SynoStatus::Ok as i32)
    })
}

/// Create a folder named `name` under `parent`.
///
/// # Safety
/// `client` must be live; `parent`/`name` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn syno_create_folder(
    client: *mut SynoClient,
    parent: *const c_char,
    name: *const c_char,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let parent = match req_str(parent, "parent", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let name = match req_str(name, "name", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let res = run_op(client, move |c| {
            let parent = parent.clone();
            let name = name.clone();
            async move { c.create_folder(&parent, &name).await.map(|_| ()) }
        });
        finish(res, err, |()| SynoStatus::Ok as i32)
    })
}

/// Rename a file or directory (same-directory rename only).
///
/// # Safety
/// `client` must be live; `path`/`new_name` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn syno_rename(
    client: *mut SynoClient,
    path: *const c_char,
    new_name: *const c_char,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let path = match req_str(path, "path", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let new_name = match req_str(new_name, "new_name", err) {
            Ok(v) => v.to_string(),
            Err(c) => return c,
        };
        let res = run_op(client, move |c| {
            let path = path.clone();
            let new_name = new_name.clone();
            async move { c.rename(&path, &new_name).await.map(|_| ()) }
        });
        finish(res, err, |()| SynoStatus::Ok as i32)
    })
}

// ─── Mount lifecycle ─────────────────────────────────────────────────────────

/// Mount the FileStation share at `mountpoint`, in-process, on a background
/// thread. Returns immediately with a [`SynoMount`] handle in `*out` once the
/// mount is established (or an error if it fails to come up).
///
/// # Safety
/// `client` must be live; `mountpoint`/`out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn syno_mount(
    client: *mut SynoClient,
    mountpoint: *const c_char,
    cache_ttl: u64,
    read_cache_mb: u64,
    out: *mut *mut SynoMount,
    err: *mut SynoError,
) -> i32 {
    guard(err, || {
        let mountpoint = match req_str(mountpoint, "mountpoint", err) {
            Ok(v) => PathBuf::from(v),
            Err(c) => return c,
        };
        if out.is_null() {
            return set_err(err, SynoStatus::NullArg, 0, "out pointer must not be null");
        }
        let c = match client.as_ref() {
            Some(c) => c,
            None => return set_err(err, SynoStatus::NullArg, 0, "client must not be null"),
        };

        let opts = MountOptions {
            cache_ttl,
            read_cache_mb,
        };
        match spawn_mount(
            c.inner.clone(),
            c.runtime.handle().clone(),
            mountpoint,
            opts,
        ) {
            Ok(handle) => {
                let mount = Box::new(SynoMount {
                    handle: Some(handle),
                    _runtime: c.runtime.clone(),
                });
                *out = Box::into_raw(mount);
                SynoStatus::Ok as i32
            }
            Err(e) => set_core_err(err, &e),
        }
    })
}

/// Unmount and free a mount handle. Blocks until the background worker exits.
/// After this the pointer is invalid.
///
/// # Safety
/// `mount` must have come from [`syno_mount`] and not been freed already.
#[no_mangle]
pub unsafe extern "C" fn syno_unmount(mount: *mut SynoMount) {
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if mount.is_null() {
            return;
        }
        let mut mount = Box::from_raw(mount);
        if let Some(handle) = mount.handle.take() {
            handle.stop();
        }
    }));
}

// ─── Logging ─────────────────────────────────────────────────────────────────

/// Register a callback that receives the library's log lines. Pass a null
/// `cb` to clear it. Installs the tracing subscriber on first call.
///
/// # Safety
/// `cb`/`user_data` must remain valid until cleared with a null `cb`.
#[no_mangle]
pub unsafe extern "C" fn syno_set_log_callback(cb: Option<logging::LogCb>, user_data: *mut c_void) {
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        logging::set_callback(cb, user_data);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn empty_err() -> SynoError {
        SynoError {
            kind: 0,
            dsm_code: 0,
            message: ptr::null_mut(),
        }
    }

    unsafe fn err_message(err: &SynoError) -> String {
        if err.message.is_null() {
            String::new()
        } else {
            CStr::from_ptr(err.message).to_string_lossy().into_owned()
        }
    }

    /// Host/port for the FFI from a mock server URI ("http://127.0.0.1:PORT").
    fn host_port(server: &MockServer) -> (CString, u16) {
        let uri = server.uri();
        let without = uri.trim_start_matches("http://");
        let (host, port) = without.rsplit_once(':').unwrap();
        (cstr(host), port.parse().unwrap())
    }

    /// A multi-thread runtime that outlives the test so the mock server's
    /// background task keeps running while the (separate) FFI runtime drives
    /// blocking calls on the test's main thread.
    fn server_with<F>(setup: F) -> (Runtime, MockServer)
    where
        F: std::future::Future<Output = MockServer>,
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(setup);
        (rt, server)
    }

    fn login_ok() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {"sid": "sid-123"}
        }))
    }

    #[test]
    fn connect_then_list_shares() {
        let (_rt, server) = server_with(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/webapi/auth.cgi"))
                .respond_with(login_ok())
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/webapi/entry.cgi"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": true,
                    "data": {"shares": [{"name": "home", "path": "/home", "isdir": true}]}
                })))
                .mount(&server)
                .await;
            server
        });

        unsafe {
            let (host, port) = host_port(&server);
            let mut client: *mut SynoClient = ptr::null_mut();
            let mut err = empty_err();
            let rc = syno_connect(
                host.as_ptr(),
                port,
                false,
                cstr("alice").as_ptr(),
                cstr("secret").as_ptr(),
                ptr::null(),
                false,
                &mut client,
                &mut err,
            );
            assert_eq!(rc, SynoStatus::Ok as i32, "connect: {}", err_message(&err));
            assert!(!client.is_null());

            let mut out_json: *mut c_char = ptr::null_mut();
            let rc = syno_list_shares(client, &mut out_json, &mut err);
            assert_eq!(rc, SynoStatus::Ok as i32, "list: {}", err_message(&err));
            let json = CStr::from_ptr(out_json).to_string_lossy().into_owned();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value[0]["name"], "home");
            assert_eq!(value[0]["isdir"], true);

            syno_string_free(out_json);
            syno_logout(client);
            syno_client_free(client);
        }
    }

    #[test]
    fn connect_reports_otp_required() {
        let (_rt, server) = server_with(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/webapi/auth.cgi"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": false, "error": {"code": 403}
                })))
                .mount(&server)
                .await;
            server
        });

        unsafe {
            let (host, port) = host_port(&server);
            let mut client: *mut SynoClient = ptr::null_mut();
            let mut err = empty_err();
            let rc = syno_connect(
                host.as_ptr(),
                port,
                false,
                cstr("alice").as_ptr(),
                cstr("secret").as_ptr(),
                ptr::null(),
                false,
                &mut client,
                &mut err,
            );
            assert_eq!(rc, SynoStatus::OtpRequired as i32);
            assert!(client.is_null());
            syno_string_free(err.message);
        }
    }

    #[test]
    fn connect_bad_credentials_is_login_failed() {
        let (_rt, server) = server_with(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/webapi/auth.cgi"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": false, "error": {"code": 400}
                })))
                .mount(&server)
                .await;
            server
        });

        unsafe {
            let (host, port) = host_port(&server);
            let mut client: *mut SynoClient = ptr::null_mut();
            let mut err = empty_err();
            let rc = syno_connect(
                host.as_ptr(),
                port,
                false,
                cstr("alice").as_ptr(),
                cstr("wrong").as_ptr(),
                ptr::null(),
                false,
                &mut client,
                &mut err,
            );
            assert_eq!(rc, SynoStatus::LoginFailed as i32);
            assert_eq!(err.dsm_code, 400, "DSM code preserved on `.dsm_code`");
            syno_string_free(err.message);
        }
    }

    #[test]
    fn null_client_is_null_arg_not_panic() {
        unsafe {
            let mut out_json: *mut c_char = ptr::null_mut();
            let mut err = empty_err();
            let rc = syno_list_shares(ptr::null_mut(), &mut out_json, &mut err);
            assert_eq!(rc, SynoStatus::NullArg as i32);
            syno_string_free(err.message);
        }
    }
}
