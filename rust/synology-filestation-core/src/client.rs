use bytes::Bytes;
use reqwest::{multipart, Client};
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Semaphore, SemaphorePermit};
use tracing::{debug, warn};

use crate::error::{dsm_code_to_category, ErrorCategory, SynoFsError};
use crate::types::{
    AuthData, CreateFolderData, GetInfoData, ListData, ListShareData, RenameData, SynoFileInfo,
    SynoResponse, UploadData, ADDITIONAL_FIELDS, SHARE_ADDITIONAL_FIELDS,
};

/// Synology API error code returned when the SID has expired or is otherwise
/// not recognized by the server. DSM keeps sessions alive for ~30 minutes of
/// inactivity by default; after that any operation using the cached SID fails
/// with this code. When auto-relogin is enabled the client transparently
/// re-authenticates and retries the call.
#[allow(dead_code)] // unused by the FUSE binary today; consumed by python bindings.
const SID_NOT_FOUND: u32 = 119;

/// Stashed credentials used by the auto-relogin path. OTP codes are
/// intentionally not stored: TOTP values are single-use, so re-login after
/// session expiry would always fail for 2FA-enabled accounts. Auto-relogin is
/// therefore only meaningful for accounts without 2FA.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct StoredCreds {
    user: String,
    password: String,
}

/// Tuning for the request throttle that protects the DSM appliance's shared
/// `synoscgi` CGI backend from saturation. Attach via
/// [`SynologyClient::with_throttle`].
///
/// The throttle wraps the heavy transfer calls (`download`, `upload`) — not
/// interactive metadata lookups — with three cooperating limits:
///
/// * a global concurrency **semaphore** (`max_concurrency`) so only a handful
///   of transfers hit `:6021` at once — the CGI backend is sized for a few
///   large streams, not one request per file;
/// * a **rate-limit belt** (`min_interval`) that spaces request starts even at
///   full concurrency;
/// * **jittered exponential backoff** (`backoff_base`..`backoff_max`) on
///   transient/degraded responses, bounded by `max_attempts` so a failing file
///   is handed back to the caller (e.g. a Temporal activity) instead of being
///   retried forever in an inner loop.
///
/// Transient (back off + retry): HTTP 502/503/504, HTTP 407 (backend
/// fail-closing), connection/read errors, and DSM 402 (system busy, backed off
/// *harder*). Permanent (fail fast, no retry): missing file / no permission /
/// invalid argument and any other DSM error code.
#[derive(Debug, Clone)]
pub struct ThrottleConfig {
    /// Maximum number of concurrent transfer requests. Keep this single-digit.
    pub max_concurrency: usize,
    /// Minimum spacing between transfer request starts. `Duration::ZERO`
    /// disables the belt.
    pub min_interval: Duration,
    /// Hard cap on attempts per transfer call (the per-file retry bound). Once
    /// exhausted the error surfaces so the outer scheduler can reschedule.
    pub max_attempts: u32,
    /// Base delay for the full-jitter exponential backoff.
    pub backoff_base: Duration,
    /// Ceiling on any single backoff sleep.
    pub backoff_max: Duration,
}

impl Default for ThrottleConfig {
    /// Conservative defaults sized to keep `synoscgi` healthy: 4 concurrent
    /// transfers, a 150 ms belt, and ≤5 attempts per file with 1s→60s
    /// full-jitter backoff.
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            min_interval: Duration::from_millis(150),
            max_attempts: 5,
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
        }
    }
}

#[derive(Debug)]
struct Throttle {
    sem: Semaphore,
    min_interval: Duration,
    /// Earliest instant the next transfer request may start (rate-limit belt).
    next_earliest: Mutex<Instant>,
    max_attempts: u32,
    backoff_base: Duration,
    backoff_max: Duration,
}

/// Outcome of a single transfer attempt, deciding what the retry loop does next.
enum TransferOutcome {
    /// The request produced a final result.
    Done(Bytes),
    /// A permanent error — surface immediately, do not retry.
    Fatal(SynoFsError),
    /// A transient/degraded failure — back off and retry (unless attempts are
    /// exhausted). `hard` requests the longer "system busy" backoff.
    Retry { hard: bool, err: SynoFsError },
}

/// HTTP statuses that mean "backend degraded / fail-closing" — stand down and
/// retry rather than hammer through. Everything else (incl. 500) is treated as
/// permanent for a transfer.
fn http_status_is_transient(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 502 | 503 | 504 | 407)
}

/// Classify a successful (HTTP 200) download body. DSM violates HTTP convention
/// by returning `200 OK` with a JSON error envelope
/// (`{"success":false,"error":{"code":N}}`) instead of a 4xx. Small bodies that
/// plausibly *look* like an envelope are probed; real binary content passes
/// through untouched.
fn classify_download_body(body: Bytes) -> TransferOutcome {
    if body.len() < 1024 && body.first() == Some(&b'{') {
        if let Ok(envelope) = serde_json::from_slice::<SynoResponse<serde_json::Value>>(&body) {
            if !envelope.success {
                let code = envelope.error.map(|e| e.code).unwrap_or(0);
                // 402 (system busy) is transient — back off harder and retry.
                if dsm_code_to_category(code) == ErrorCategory::Busy {
                    return TransferOutcome::Retry {
                        hard: true,
                        err: SynoFsError::ApiError(code),
                    };
                }
                return TransferOutcome::Fatal(SynoFsError::ApiError(code));
            }
        }
    }
    TransferOutcome::Done(body)
}

/// Full-jitter backoff: a random duration in `[0, cap]`. Wall-clock nanoseconds
/// seed the jitter so we avoid an RNG crate dependency — good enough to keep a
/// fleet of retriers from resynchronising into a thundering herd.
fn full_jitter(cap: Duration) -> Duration {
    if cap.is_zero() {
        return Duration::ZERO;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let frac = nanos as f64 / 1_000_000_000.0_f64;
    cap.mul_f64(frac)
}

#[derive(Debug)]
pub struct SynologyClient {
    http: Client,
    base_url: String,
    sid: RwLock<Option<String>>,
    /// Optional request throttle protecting the NAS from bulk-transfer
    /// saturation. `None` = unthrottled (the FUSE/CLI mount path); the Python
    /// and FFI bulk entry points attach one via [`SynologyClient::with_throttle`].
    throttle: Option<Throttle>,
    /// When true, operations that fail with `ApiError(119)` (SID not found)
    /// trigger a transparent re-login + single retry instead of surfacing the
    /// error. Off by default to preserve existing FUSE/WebDAV/WinFsp
    /// behavior; opt in via [`SynologyClient::with_auto_relogin`].
    auto_relogin: bool,
    creds: RwLock<Option<StoredCreds>>,
}

impl SynologyClient {
    pub fn new(host: &str, port: u16, https: bool) -> Self {
        let scheme = if https { "https" } else { "http" };
        let base_url = format!("{}://{}:{}/webapi", scheme, host, port);
        let http = Client::builder()
            .danger_accept_invalid_certs(true) // common for self-signed NAS certs
            // Drop idle connections after 4 s so we don't reuse connections the NAS
            // has already closed on its side (~7 s keep-alive on most DSM versions).
            .pool_idle_timeout(Duration::from_secs(4))
            // Fail fast if the NAS is unreachable rather than waiting for the OS-level
            // TCP timeout (~75 s on macOS, ETIMEDOUT / os error 60).
            .connect_timeout(Duration::from_secs(10))
            // Send TCP keepalive probes so stalled mid-transfer connections are
            // detected in seconds rather than waiting for the full OS TCP timeout
            // (~75 s on macOS, ETIMEDOUT / os error 60).
            .tcp_keepalive(Duration::from_secs(10))
            // Bound how long we'll wait for data on a request. Without this, a
            // silently-dead connection (e.g. routes changed when a VPN comes up
            // mid-session) hangs the FUSE callback indefinitely — the user sees
            // their file manager freeze with no error. read_timeout fires when
            // no bytes have arrived for the duration, so it doesn't cap
            // legitimately long large-file uploads.
            .read_timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self {
            http,
            base_url,
            sid: RwLock::new(None),
            auto_relogin: false,
            creds: RwLock::new(None),
            throttle: None,
        }
    }

    /// Attach a [`ThrottleConfig`] that caps concurrency, spaces requests, and
    /// bounds retries for the transfer calls (`download`/`upload`).
    ///
    /// Off by default: the FUSE/CLI mount path leaves it unset so interactive
    /// ranged reads and prefetch stay snappy. The Python bindings and the FFI
    /// `syno_connect` entry point — the bulk-transfer consumers that can
    /// saturate the appliance — enable it. Metadata calls (list/getinfo/…) are
    /// never gated by the semaphore, so a transfer holding a permit can never
    /// deadlock on its own metadata lookup.
    pub fn with_throttle(mut self, cfg: ThrottleConfig) -> Self {
        self.throttle = Some(Throttle {
            sem: Semaphore::new(cfg.max_concurrency.max(1)),
            min_interval: cfg.min_interval,
            next_earliest: Mutex::new(Instant::now()),
            max_attempts: cfg.max_attempts.max(1),
            backoff_base: cfg.backoff_base,
            backoff_max: cfg.backoff_max,
        });
        self
    }

    /// Attempts a transfer call may make. Without a throttle this preserves the
    /// historical behavior (3 tries).
    fn max_transfer_attempts(&self) -> u32 {
        self.throttle.as_ref().map(|t| t.max_attempts).unwrap_or(3)
    }

    /// Reserve a transfer slot: apply the rate-limit belt, then acquire a
    /// concurrency permit. Returns `None` when unthrottled (the caller runs as
    /// before). The permit releases when the returned guard is dropped, so
    /// callers must hold it only for the request+body read and drop it before
    /// backing off.
    async fn acquire_transfer_slot(&self) -> Option<SemaphorePermit<'_>> {
        let t = self.throttle.as_ref()?;
        // Rate-limit belt: reserve this request's slot and sleep until it opens,
        // without holding the lock across the sleep.
        if t.min_interval > Duration::ZERO {
            let wait = {
                let mut next = t.next_earliest.lock().await;
                let now = Instant::now();
                let scheduled = (*next).max(now);
                *next = scheduled + t.min_interval;
                scheduled.saturating_duration_since(now)
            };
            if wait > Duration::ZERO {
                tokio::time::sleep(wait).await;
            }
        }
        Some(
            t.sem
                .acquire()
                .await
                .expect("throttle semaphore never closed"),
        )
    }

    /// Sleep for a jittered exponential backoff before the next attempt.
    /// `hard` (DSM 402 busy) doubles the base delay. No-op when unthrottled, so
    /// the mount path retries with no added delay exactly as before.
    async fn backoff_before_retry(&self, attempt: u32, hard: bool) {
        let t = match self.throttle.as_ref() {
            Some(t) => t,
            None => return,
        };
        let base = if hard {
            t.backoff_base.saturating_mul(2)
        } else {
            t.backoff_base
        };
        let factor = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
        let cap = base.saturating_mul(factor).min(t.backoff_max);
        let delay = full_jitter(cap);
        if delay > Duration::ZERO {
            tokio::time::sleep(delay).await;
        }
    }

    /// Build a client that transparently re-authenticates and retries once
    /// when an operation fails with `ApiError(119)` (SID expired). Use this
    /// for long-running scripts where the DSM session may outlast the ~30 min
    /// idle timeout.
    ///
    /// 2FA caveat: OTP codes are not stored, so re-login of a 2FA-enabled
    /// account after expiry will fail. Use plain [`SynologyClient::new`] for
    /// 2FA accounts and prompt for a fresh OTP at each login.
    #[allow(dead_code)] // unused by the FUSE binary today; consumed by python bindings.
    pub fn with_auto_relogin(host: &str, port: u16, https: bool) -> Self {
        let mut c = Self::new(host, port, https);
        c.auto_relogin = true;
        c
    }

    fn sid(&self) -> String {
        self.sid.read().unwrap().clone().unwrap_or_default()
    }

    /// Issue a GET request and return the response body as a string, retrying up
    /// to 3 times on transient connection errors (connection reset, read
    /// timeout, etc.). Used by every read-only API call so a momentary network
    /// blip — e.g. a VPN coming up and silently killing existing TCP
    /// connections — recovers transparently instead of bubbling up as EIO.
    async fn get_text_retried(
        &self,
        url: &str,
        params: &[(&str, &str)],
    ) -> Result<String, SynoFsError> {
        let mut last_err = SynoFsError::Io("no attempts".into());
        for attempt in 0..3u8 {
            if attempt > 0 {
                debug!("retry {} for GET {}", attempt, url);
                tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
            }
            let resp = match self.http.get(url).query(params).send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = e.into();
                    continue;
                }
            };
            match resp.text().await {
                Ok(t) => return Ok(t),
                Err(e) => {
                    last_err = e.into();
                }
            }
        }
        Err(last_err)
    }

    /// Login and store the session ID.
    ///
    /// `otp_code` is the 6-digit TOTP code required when the account has 2-factor
    /// authentication enabled. Pass `None` if 2FA is not configured.
    pub async fn login(
        &self,
        user: &str,
        password: &str,
        otp_code: Option<&str>,
    ) -> Result<(), SynoFsError> {
        let url = format!("{}/auth.cgi", self.base_url);
        let mut params = vec![
            ("api", "SYNO.API.Auth"),
            ("version", "7"),
            ("method", "login"),
            ("account", user),
            ("passwd", password),
            ("session", "FileStation"),
            ("format", "sid"),
        ];
        if let Some(otp) = otp_code {
            params.push(("otp_code", otp));
        }
        let resp = self
            .http
            .get(&url)
            .query(&params)
            .send()
            .await?
            .json::<SynoResponse<AuthData>>()
            .await?;

        if resp.success {
            let sid = resp
                .data
                .ok_or_else(|| SynoFsError::Io("no auth data".into()))?
                .sid;
            debug!("Logged in, SID: {}...", &sid[..8.min(sid.len())]);
            *self.sid.write().unwrap() = Some(sid);
            if self.auto_relogin {
                *self.creds.write().unwrap() = Some(StoredCreds {
                    user: user.to_string(),
                    password: password.to_string(),
                });
            }
            Ok(())
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Re-authenticate using stashed credentials. Returns `NotSupported` if
    /// auto-relogin is off or no credentials are available (e.g. 2FA login).
    #[allow(dead_code)]
    async fn relogin(&self) -> Result<(), SynoFsError> {
        if !self.auto_relogin {
            return Err(SynoFsError::NotSupported);
        }
        let creds = self
            .creds
            .read()
            .unwrap()
            .clone()
            .ok_or(SynoFsError::NotSupported)?;
        warn!("SID expired, re-authenticating");
        self.login(&creds.user, &creds.password, None).await
    }

    /// True if this client was constructed with auto-relogin enabled.
    #[allow(dead_code)]
    pub fn auto_relogin_enabled(&self) -> bool {
        self.auto_relogin
    }

    /// Run `op` once. If it fails with `ApiError(119)` and auto-relogin is on,
    /// re-authenticate and run `op` exactly one more time. Any other error is
    /// returned untouched.
    ///
    /// If the re-login itself fails, the underlying error is wrapped in
    /// `SynoFsError::LoginFailed(...)` so callers can distinguish "the
    /// operation failed" from "we couldn't even re-authenticate to retry it."
    /// A persistent 119 (re-login succeeds but the retry still returns 119)
    /// surfaces as the second 119 untransformed.
    #[allow(dead_code)]
    pub async fn with_relogin_retry<F, Fut, T>(&self, mut op: F) -> Result<T, SynoFsError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, SynoFsError>>,
    {
        match op().await {
            Err(SynoFsError::ApiError(SID_NOT_FOUND)) if self.auto_relogin => {
                self.relogin()
                    .await
                    .map_err(|e| SynoFsError::LoginFailed(Box::new(e)))?;
                op().await
            }
            other => other,
        }
    }

    /// Logout and clear the session ID.
    pub async fn logout(&self) -> Result<(), SynoFsError> {
        let url = format!("{}/auth.cgi", self.base_url);
        let _ = self
            .http
            .get(&url)
            .query(&[
                ("api", "SYNO.API.Auth"),
                ("version", "7"),
                ("method", "logout"),
                ("session", "FileStation"),
                ("_sid", &self.sid()),
            ])
            .send()
            .await;
        *self.sid.write().unwrap() = None;
        Ok(())
    }

    /// List all FileStation shares the account can see.
    pub async fn list_shares(&self) -> Result<Vec<SynoFileInfo>, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        debug!("list_shares");
        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.List"),
                    ("version", "2"),
                    ("method", "list_share"),
                    ("additional", SHARE_ADDITIONAL_FIELDS),
                    ("limit", "500"),
                    ("offset", "0"),
                    ("_sid", &self.sid()),
                ],
            )
            .await?;

        let resp: SynoResponse<ListShareData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("list_shares parse error: {e}")))?;

        if resp.success {
            let shares = resp.data.map(|d| d.shares).unwrap_or_default();
            debug!("list_shares: {} shares returned", shares.len());
            Ok(shares)
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// List the contents of a directory.
    pub async fn list_dir(&self, folder_path: &str) -> Result<Vec<SynoFileInfo>, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        debug!("list_dir: {}", folder_path);
        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.List"),
                    ("version", "2"),
                    ("method", "list"),
                    ("folder_path", folder_path),
                    ("additional", ADDITIONAL_FIELDS),
                    ("limit", "5000"),
                    ("offset", "0"),
                    ("_sid", &self.sid()),
                ],
            )
            .await?;

        let resp: SynoResponse<ListData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("list_dir parse error: {e}")))?;

        if resp.success {
            Ok(resp.data.map(|d| d.files).unwrap_or_default())
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Get metadata for a single file or directory.
    pub async fn get_info(&self, path: &str) -> Result<SynoFileInfo, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[path]).unwrap();
        debug!("get_info: {}", path);
        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.List"),
                    ("version", "2"),
                    ("method", "getinfo"),
                    ("path", &path_json),
                    ("additional", ADDITIONAL_FIELDS),
                    ("_sid", &self.sid()),
                ],
            )
            .await?;

        debug!("get_info raw response: {}", text);

        let resp: SynoResponse<GetInfoData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("get_info parse error: {e}")))?;

        if resp.success {
            let mut files = resp.data.ok_or(SynoFsError::NotFound)?.files;
            let file = files.pop().ok_or(SynoFsError::NotFound)?;
            if let Some(code) = file.code {
                return Err(SynoFsError::ApiError(code));
            }
            Ok(file)
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Download a remote file atomically to `local_path`.
    ///
    /// Bytes are first written to `<local_path>.part`, fsynced, then renamed
    /// to `local_path`. The final file is therefore never observed in a
    /// partial state — either it's complete and correct, or it doesn't exist.
    /// If any step fails (network error, DSM JSON-error envelope, I/O error)
    /// the temporary file is removed and `local_path` is left untouched.
    ///
    /// This guards against the common DSM footgun of `200 OK` responses whose
    /// body is `{"success":false,"error":{"code":119}}` — the synology-api
    /// PyPI package opens its destination in `'wb'` first and silently leaves
    /// a 0-byte file in this scenario.
    #[allow(dead_code)] // unused by the FUSE binary today; consumed by python bindings.
    pub async fn download_to_path(
        &self,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<(), SynoFsError> {
        let bytes = self
            .with_relogin_retry(|| self.download(remote_path, 0, 0))
            .await?;

        let tmp = {
            let mut t = local_path.as_os_str().to_os_string();
            t.push(".part");
            std::path::PathBuf::from(t)
        };

        let write_result: std::io::Result<()> = (|| {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, local_path)
        })();

        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(SynoFsError::Io(format!(
                "download_to_path: write to {} failed: {e}",
                local_path.display()
            )));
        }
        Ok(())
    }

    /// Download file bytes, optionally with a byte range.
    ///
    /// Retries up to 2 times on transient connection errors (e.g. the NAS closing a
    /// keep-alive connection mid-stream while the response body is being read).
    ///
    /// DSM violates HTTP convention by returning `200 OK` with a JSON error
    /// envelope (`{"success":false,"error":{"code":119}}`) when the SID is
    /// invalid, instead of a 4xx. We detect that case via the `Content-Type`
    /// header and surface `ApiError(code)` rather than returning the JSON as
    /// file content. Without this, a SID-expired download would silently
    /// produce garbage data on disk.
    pub async fn download(
        &self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<Bytes, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[path]).unwrap();
        debug!("download: {} offset={} len={}", path, offset, length);

        let range_header = if length > 0 {
            Some(format!("bytes={}-{}", offset, offset + length - 1))
        } else {
            None
        };

        let max_attempts = self.max_transfer_attempts();
        let mut last_err = SynoFsError::Io("no attempts".into());

        for attempt in 0..max_attempts {
            if attempt > 0 {
                debug!("download retry {} for {} offset={}", attempt, path, offset);
            }

            // One attempt. The concurrency permit is held only for the duration
            // of the request+body read (this inner block); it is released before
            // any backoff so a sleeping-then-retrying request never occupies a
            // slot.
            let outcome: TransferOutcome = {
                let _slot = self.acquire_transfer_slot().await;

                let mut req = self.http.get(&url).query(&[
                    ("api", "SYNO.FileStation.Download"),
                    ("version", "2"),
                    ("method", "download"),
                    ("path", &path_json),
                    ("mode", "download"),
                    ("_sid", &self.sid()),
                ]);
                if let Some(ref range) = range_header {
                    req = req.header("Range", range.as_str());
                }

                match req.send().await {
                    Err(e) => TransferOutcome::Retry {
                        hard: false,
                        err: e.into(),
                    },
                    Ok(resp) => {
                        let status = resp.status();
                        // 416 Range Not Satisfiable = range starts past EOF;
                        // return empty (EOF signal).
                        if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
                            TransferOutcome::Done(Bytes::new())
                        } else if !status.is_success() {
                            let err = SynoFsError::Io(format!("download HTTP {}", status));
                            if http_status_is_transient(status) {
                                TransferOutcome::Retry { hard: false, err }
                            } else {
                                TransferOutcome::Fatal(err)
                            }
                        } else {
                            match resp.bytes().await {
                                Err(e) => TransferOutcome::Retry {
                                    hard: false,
                                    err: e.into(),
                                },
                                Ok(body) => classify_download_body(body),
                            }
                        }
                    }
                }
            };

            match outcome {
                TransferOutcome::Done(bytes) => return Ok(bytes),
                TransferOutcome::Fatal(e) => return Err(e),
                TransferOutcome::Retry { hard, err } => {
                    last_err = err;
                    if attempt + 1 < max_attempts {
                        self.backoff_before_retry(attempt, hard).await;
                    }
                }
            }
        }
        Err(last_err)
    }

    /// Upload file contents (replaces entire file).
    pub async fn upload(
        &self,
        folder_path: &str,
        filename: &str,
        data: Vec<u8>,
        overwrite: bool,
    ) -> Result<(), SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        debug!(
            "upload: {}/{} ({} bytes)",
            folder_path,
            filename,
            data.len()
        );

        // overwrite=true via the multipart API times out on some DSM versions.
        // Delete the existing file first so we can always upload with overwrite=false.
        if overwrite {
            let full_path = format!("{}/{}", folder_path.trim_end_matches('/'), filename);
            let _ = self.delete(&full_path).await; // ignore error — file may not exist yet

            // Synology Delete is async on modern DSM: poll get_info until the file is
            // gone (or inaccessible) before uploading, to avoid 418 AlreadyExists.
            for _ in 0..10u8 {
                match self.get_info(&full_path).await {
                    Ok(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                    Err(_) => break, // gone or inaccessible — safe to upload
                }
            }
        }

        let max_attempts = self.max_transfer_attempts();
        let mut last_err = SynoFsError::Io("no attempts".into());
        for attempt in 0..max_attempts {
            if attempt > 0 {
                debug!("upload retry {} for {}/{}", attempt, folder_path, filename);
            }

            let file_part = multipart::Part::bytes(data.clone())
                .file_name(filename.to_string())
                .mime_str("application/octet-stream")
                .map_err(|e| SynoFsError::Io(e.to_string()))?;

            let form = multipart::Form::new()
                .text("api", "SYNO.FileStation.Upload")
                .text("version", "3")
                .text("method", "upload")
                .text("path", folder_path.to_string())
                .text("create_parents", "true")
                .text("overwrite", "false")
                .part("file", file_part);

            // Hold a transfer slot only for the request+response read; drop it
            // before any backoff so a retrying upload doesn't hog a permit.
            let text = {
                let _slot = self.acquire_transfer_slot().await;
                match self
                    .http
                    .post(&url)
                    .query(&[("_sid", self.sid())])
                    .multipart(form)
                    .send()
                    .await
                {
                    Ok(r) => r.text().await.map_err(SynoFsError::from),
                    Err(e) => Err(e.into()),
                }
            };

            let text = match text {
                Ok(t) => t,
                Err(e) => {
                    last_err = e;
                    if attempt + 1 < max_attempts {
                        self.backoff_before_retry(attempt, false).await;
                    }
                    continue;
                }
            };

            debug!("upload raw response: {}", text);

            let parsed: SynoResponse<UploadData> = serde_json::from_str(&text)
                .map_err(|e| SynoFsError::Io(format!("upload parse error: {e}")))?;

            return if parsed.success {
                Ok(())
            } else {
                let code = parsed.error.map(|e| e.code).unwrap_or(0);
                Err(SynoFsError::ApiError(code))
            };
        }
        Err(last_err)
    }

    /// Delete a file or directory (recursive for directories).
    pub async fn delete(&self, path: &str) -> Result<(), SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[path]).unwrap();
        debug!("delete: {}", path);

        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.Delete"),
                    ("version", "2"),
                    ("method", "delete"),
                    ("path", &path_json),
                    ("recursive", "true"),
                    ("accurate_progress", "false"),
                    ("_sid", &self.sid()),
                ],
            )
            .await?;

        let resp: SynoResponse<serde_json::Value> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("delete parse error: {e}")))?;

        if resp.success {
            Ok(())
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Create a directory.
    pub async fn create_folder(
        &self,
        parent: &str,
        name: &str,
    ) -> Result<SynoFileInfo, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let parent_json = serde_json::to_string(&[parent]).unwrap();
        let name_json = serde_json::to_string(&[name]).unwrap();
        debug!("create_folder: {}/{}", parent, name);

        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.CreateFolder"),
                    ("version", "2"),
                    ("method", "create"),
                    ("folder_path", &parent_json),
                    ("name", &name_json),
                    ("additional", ADDITIONAL_FIELDS),
                    ("_sid", &self.sid()),
                ],
            )
            .await?;

        debug!("create_folder raw response: {}", text);

        let resp: SynoResponse<CreateFolderData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("create_folder parse error: {e}")))?;

        if resp.success {
            let mut folders = resp
                .data
                .ok_or(SynoFsError::Io("no folder data".into()))?
                .folders;
            folders
                .pop()
                .ok_or(SynoFsError::Io("empty folder list".into()))
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Rename a file or directory (same-directory rename only).
    pub async fn rename(
        &self,
        old_path: &str,
        new_name: &str,
    ) -> Result<SynoFileInfo, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[old_path]).unwrap();
        let name_json = serde_json::to_string(&[new_name]).unwrap();
        debug!("rename: {} -> {}", old_path, new_name);

        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.Rename"),
                    ("version", "2"),
                    ("method", "rename"),
                    ("path", &path_json),
                    ("name", &name_json),
                    ("additional", ADDITIONAL_FIELDS),
                    ("_sid", &self.sid()),
                ],
            )
            .await?;

        debug!("rename raw response: {}", text);

        let resp: SynoResponse<RenameData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("rename parse error: {e}")))?;

        if resp.success {
            let mut files = resp
                .data
                .ok_or(SynoFsError::Io("no rename data".into()))?
                .files;
            files.pop().ok_or(SynoFsError::Io("empty file list".into()))
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a client pointed at the given mock server.
    fn client_for(server: &MockServer) -> SynologyClient {
        let uri = server.uri(); // "http://127.0.0.1:PORT"
        let without_scheme = uri.trim_start_matches("http://");
        let (host, port_str) = without_scheme.rsplit_once(':').unwrap();
        let port: u16 = port_str.parse().unwrap();
        SynologyClient::new(host, port, false)
    }

    /// Build an auto-relogin client pointed at the given mock server.
    fn client_auto_for(server: &MockServer) -> SynologyClient {
        let uri = server.uri();
        let without_scheme = uri.trim_start_matches("http://");
        let (host, port_str) = without_scheme.rsplit_once(':').unwrap();
        let port: u16 = port_str.parse().unwrap();
        SynologyClient::with_auto_relogin(host, port, false)
    }

    // ── login ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn login_stores_sid_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "abc123def"}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        assert_eq!(client.sid(), "abc123def");
    }

    #[tokio::test]
    async fn login_returns_api_error_on_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 400}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.login("alice", "wrong", None).await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(400)));
    }

    #[tokio::test]
    async fn login_with_otp_includes_otp_param() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .and(query_param("otp_code", "123456"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "otp_sid_xyz"}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .login("alice", "secret", Some("123456"))
            .await
            .unwrap();
        assert_eq!(client.sid(), "otp_sid_xyz");
    }

    // ── logout ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn logout_clears_sid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "session_abc"}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        assert_eq!(client.sid(), "session_abc");
        client.logout().await.unwrap();
        assert_eq!(client.sid(), "");
    }

    // ── list_shares ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_shares_returns_shares() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list_share"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"shares": [
                    {"name": "photos", "path": "/photos", "isdir": true, "additional": null},
                    {"name": "docs",   "path": "/docs",   "isdir": true, "additional": null}
                ]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let shares = client.list_shares().await.unwrap();
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].name, "photos");
        assert_eq!(shares[1].name, "docs");
    }

    #[tokio::test]
    async fn list_shares_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list_share"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 408}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.list_shares().await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(408)));
    }

    // ── list_dir ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_dir_returns_files() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [
                    {"name": "file.txt", "path": "/share/file.txt", "isdir": false, "additional": null}
                ]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let files = client.list_dir("/share").await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "file.txt");
    }

    #[tokio::test]
    async fn list_dir_null_data_returns_empty_vec() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let files = client.list_dir("/empty").await.unwrap();
        assert!(files.is_empty());
    }

    // ── get_info ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_info_returns_file_metadata() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [{
                    "name": "notes.txt",
                    "path": "/share/notes.txt",
                    "isdir": false,
                    "additional": {"size": 512, "owner": null, "time": null, "perm": null}
                }]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let info = client.get_info("/share/notes.txt").await.unwrap();
        assert_eq!(info.name, "notes.txt");
        assert_eq!(info.additional.unwrap().size, Some(512));
    }

    #[tokio::test]
    async fn get_info_per_entry_error_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [{"code": 408, "path": "/share/missing"}]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.get_info("/share/missing").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(408)));
    }

    #[tokio::test]
    async fn get_info_envelope_error_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 119}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.get_info("/share/restricted").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(119)));
    }

    // ── download ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn download_returns_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello world".to_vec()))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let data = client.download("/share/file.txt", 0, 11).await.unwrap();
        assert_eq!(data.as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn download_416_returns_empty_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(416))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let data = client.download("/share/file.txt", 9999, 10).await.unwrap();
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn download_http_error_returns_io_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.download("/share/file.txt", 0, 10).await.unwrap_err();
        assert!(matches!(err, SynoFsError::Io(_)));
    }

    // ── upload ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn upload_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"blks": null}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .upload("/share", "test.txt", b"content".to_vec(), false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upload_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 1805}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client
            .upload("/share", "test.txt", b"data".to_vec(), false)
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(1805)));
    }

    #[tokio::test]
    async fn upload_with_overwrite_deletes_then_polls_then_uploads() {
        let server = MockServer::start().await;
        // DELETE call (GET method=delete)
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .mount(&server)
            .await;
        // Poll for file gone (GET method=getinfo) — return error so upload proceeds
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 414}
            })))
            .mount(&server)
            .await;
        // Actual upload (POST)
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"blks": null}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .upload("/share", "test.txt", b"new content".to_vec(), true)
            .await
            .unwrap();
    }

    // ── delete ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.delete("/share/file.txt").await.unwrap();
    }

    #[tokio::test]
    async fn delete_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 414}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.delete("/share/missing.txt").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(414)));
    }

    // ── create_folder ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_folder_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "create"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"folders": [
                    {"name": "newdir", "path": "/share/newdir", "isdir": true, "additional": null}
                ]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let info = client.create_folder("/share", "newdir").await.unwrap();
        assert_eq!(info.name, "newdir");
        assert!(info.isdir);
    }

    #[tokio::test]
    async fn create_folder_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "create"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 1101}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client
            .create_folder("/share", "existing")
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(1101)));
    }

    // ── rename ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rename_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "rename"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [
                    {"name": "new.txt", "path": "/share/new.txt", "isdir": false, "additional": null}
                ]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let info = client.rename("/share/old.txt", "new.txt").await.unwrap();
        assert_eq!(info.name, "new.txt");
    }

    #[tokio::test]
    async fn rename_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "rename"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 418}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client
            .rename("/share/old.txt", "existing.txt")
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(418)));
    }

    // ── retry behaviour ──────────────────────────────────────────────────────
    //
    // A VPN coming up mid-session silently kills existing TCP connections.
    // reqwest's pool happily hands out the dead connection, the request fails,
    // and without a retry the FUSE callback returns EIO to the user. The retry
    // helper re-issues the request — pool_idle_timeout(4s) gets us a fresh
    // connection, which routes correctly over the new VPN interface.
    //
    // wiremock can't simulate a connection-layer fault (it only models HTTP
    // responses), so these tests stand up a tiny tokio TcpListener that closes
    // the socket without responding to trigger a real reqwest::Error.

    /// Spawn a TCP server that drops the first `failures` connections, then
    /// answers the next one with `body` as a JSON HTTP/1.1 response.
    async fn flaky_json_server(
        failures: usize,
        body: &'static str,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            for _ in 0..failures {
                if let Ok((stream, _)) = listener.accept().await {
                    drop(stream); // close immediately, no HTTP response
                }
            }
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (port, handle)
    }

    #[tokio::test]
    async fn list_dir_recovers_after_transient_connection_drops() {
        // Simulates the VPN-flap scenario: first 2 connections die, 3rd succeeds.
        let body = r#"{"success":true,"data":{"files":[{"name":"hi.txt","path":"/share/hi.txt","isdir":false,"additional":null}]}}"#;
        let (port, handle) = flaky_json_server(2, body).await;

        let client = SynologyClient::new("127.0.0.1", port, false);
        let files = client.list_dir("/share").await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "hi.txt");
        handle.await.ok();
    }

    #[tokio::test]
    async fn list_dir_returns_io_error_when_all_retries_fail() {
        // 10 failures > 3 attempts — verifies the helper eventually gives up
        // with an Io error instead of hanging the FUSE callback forever.
        let (port, handle) = flaky_json_server(10, "").await;

        let client = SynologyClient::new("127.0.0.1", port, false);
        let err = client.list_dir("/share").await.unwrap_err();
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");
        handle.abort();
    }

    #[tokio::test]
    async fn list_dir_does_not_retry_on_api_error() {
        // API-level failures (success: false) must NOT be retried — they're
        // deterministic, and retrying would multiply the user's wait on a real
        // permission denial or rate-limit.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 408}
            })))
            .expect(1) // verified when MockServer is dropped
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.list_dir("/share").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(408)));
    }

    // ── auto-relogin & SID-expiry handling ───────────────────────────────────
    //
    // DSM expires session tokens after ~30 minutes of inactivity, returning
    // ApiError(119) ("SID not found"). Long-running scripts should recover
    // transparently. These tests pin down the contract:
    //   - default client (no auto_relogin): 119 surfaces unchanged
    //   - auto_relogin client: 119 triggers one re-login + one retry; if the
    //     retry succeeds the caller never sees 119; if the retry or re-login
    //     itself fails, the *latest* error is what surfaces

    #[tokio::test]
    async fn default_client_does_not_stash_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "abc"}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        assert!(!client.auto_relogin_enabled());
        // No stashed creds → relogin must refuse rather than silently no-op.
        let err = client.relogin().await.unwrap_err();
        assert!(matches!(err, SynoFsError::NotSupported));
    }

    #[tokio::test]
    async fn auto_relogin_client_stashes_credentials_on_login() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "first"}
            })))
            .mount(&server)
            .await;

        let client = client_auto_for(&server);
        assert!(client.auto_relogin_enabled());
        client.login("alice", "secret", None).await.unwrap();
        // relogin should succeed using stashed creds (server returns the same SID).
        client.relogin().await.unwrap();
    }

    #[tokio::test]
    async fn api_119_surfaces_when_auto_relogin_off() {
        // Pre-bug-fix behavior: a default client should still see 119 directly.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "s"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 119}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        let err = client
            .with_relogin_retry(|| client.get_info("/share/x"))
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(119)));
    }

    #[tokio::test]
    async fn api_119_triggers_transparent_relogin_and_retry_succeeds() {
        // Sequence: client logs in → operation returns 119 (SID expired) →
        // client transparently re-logs-in → operation retried → caller sees Ok.
        let server = MockServer::start().await;

        // Both login calls return the same fixed sid; server doesn't care
        // about sid value, only that the call sequence is right.
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .and(query_param("method", "login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "fresh_sid"}
            })))
            .expect(2) // initial login + one re-login
            .mount(&server)
            .await;

        // First getinfo call: 119. Second call: success.
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 119}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [
                    {"name": "x", "path": "/share/x", "isdir": false, "additional": null}
                ]}
            })))
            .mount(&server)
            .await;

        let client = client_auto_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        let info = client
            .with_relogin_retry(|| client.get_info("/share/x"))
            .await
            .unwrap();
        assert_eq!(info.name, "x");
        // MockServer drop verifies the .expect(2) on the login mock — both
        // initial login and re-login were observed.
    }

    #[tokio::test]
    async fn api_119_relogin_failure_surfaces_auth_error() {
        // Initial login OK; first op gets 119; re-login fails (e.g. password
        // changed server-side). Caller should see the re-login failure, NOT
        // the original 119, so they can act on the right cause.
        let server = MockServer::start().await;

        // First login: success. Second login (re-login): auth failure (400).
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .and(query_param("method", "login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "first"}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .and(query_param("method", "login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 400}
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 119}
            })))
            .mount(&server)
            .await;

        let client = client_auto_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        let err = client
            .with_relogin_retry(|| client.get_info("/share/x"))
            .await
            .unwrap_err();
        // The re-login failure is wrapped so callers can distinguish "the
        // operation failed" from "we couldn't even re-authenticate."
        match err {
            SynoFsError::LoginFailed(inner) => assert!(
                matches!(*inner, SynoFsError::ApiError(400)),
                "expected wrapped ApiError(400), got {inner:?}"
            ),
            other => panic!("expected LoginFailed(ApiError(400)), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn api_119_only_retries_once() {
        // If both the initial call AND the retry return 119, give up — don't
        // loop forever. The second 119 is what the caller sees.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .and(query_param("method", "login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "s"}
            })))
            .expect(2) // initial + 1 re-login, no more
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 119}
            })))
            .expect(2) // exactly 2 attempts, never 3
            .mount(&server)
            .await;

        let client = client_auto_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        let err = client
            .with_relogin_retry(|| client.get_info("/share/x"))
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(119)));
    }

    #[tokio::test]
    async fn non_119_errors_do_not_trigger_relogin() {
        // 408 (no permission) is deterministic — re-logging-in won't fix it.
        // Verify we don't re-auth on non-119 errors. The login mock has
        // .expect(1) and the test will fail on drop if we re-login.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .and(query_param("method", "login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "s"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 408}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_auto_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        let err = client
            .with_relogin_retry(|| client.get_info("/share/x"))
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(408)));
    }

    // ── download JSON-error envelope detection ───────────────────────────────
    //
    // The fishsense bug: DSM returns 200 OK with body
    // {"success":false,"error":{"code":119}} on a download when the SID is
    // expired. The synology-api PyPI lib treats this as success (because HTTP
    // is 200), opens the destination file with 'wb' (truncating), reads zero
    // file bytes, and silently corrupts the output. We must surface this as
    // ApiError(code).

    #[tokio::test]
    async fn download_returns_api_error_when_body_is_dsm_json_error_envelope() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json; charset=UTF-8")
                    .set_body_string(r#"{"success":false,"error":{"code":119}}"#),
            )
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.download("/share/file.bin", 0, 0).await.unwrap_err();
        assert!(
            matches!(err, SynoFsError::ApiError(119)),
            "expected ApiError(119), got {err:?}"
        );
    }

    #[tokio::test]
    async fn download_with_octet_stream_content_type_returns_bytes_not_parsed() {
        // Sanity-check that real binary downloads aren't accidentally caught
        // by the JSON-envelope detection. The body happens to start with `{`
        // but Content-Type is binary, so we should pass it through.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/octet-stream")
                    .set_body_bytes(b"{not really json}".to_vec()),
            )
            .mount(&server)
            .await;

        let client = client_for(&server);
        let bytes = client.download("/share/x", 0, 0).await.unwrap();
        assert_eq!(bytes.as_ref(), b"{not really json}");
    }

    // ── atomic download_to_path ──────────────────────────────────────────────
    //
    // download_to_path must guarantee that the destination file is either
    // (a) absent, or (b) complete and correct — never a 0-byte stub or a
    // partial download. Implementation detail: write to "<path>.part", fsync,
    // rename. The fishsense regression is the central case here.

    fn unique_tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("synofs-test-{pid}-{nanos}-{name}"));
        p
    }

    #[tokio::test]
    async fn download_to_path_writes_atomically_then_renames() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/octet-stream")
                    .set_body_bytes(b"hello atomic world".to_vec()),
            )
            .mount(&server)
            .await;

        let client = client_for(&server);
        let dest = unique_tmp_path("happy.bin");
        let part = {
            let mut p = dest.as_os_str().to_os_string();
            p.push(".part");
            std::path::PathBuf::from(p)
        };

        client.download_to_path("/share/file", &dest).await.unwrap();

        let on_disk = std::fs::read(&dest).unwrap();
        assert_eq!(on_disk, b"hello atomic world");
        assert!(!part.exists(), "tmp file should be gone after rename");

        std::fs::remove_file(&dest).ok();
    }

    #[tokio::test]
    async fn download_to_path_does_not_create_final_file_on_dsm_json_error() {
        // **The fishsense regression test.** DSM replies 200 OK with a JSON
        // error envelope; the destination must NOT exist on disk afterward
        // (no 0-byte stub), and neither must the .part tmp file.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"success":false,"error":{"code":119}}"#),
            )
            .mount(&server)
            .await;

        let client = client_for(&server); // no auto-relogin — 119 surfaces
        let dest = unique_tmp_path("regression.bin");
        let part = {
            let mut p = dest.as_os_str().to_os_string();
            p.push(".part");
            std::path::PathBuf::from(p)
        };

        let err = client
            .download_to_path("/share/missing", &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(119)));
        assert!(
            !dest.exists(),
            "destination must not exist after failed download (no zero-byte stub)"
        );
        assert!(!part.exists(), ".part tmp file must be cleaned up");
    }

    #[tokio::test]
    async fn download_to_path_with_auto_relogin_recovers_from_119() {
        // End-to-end fishsense fix: SID expires mid-script, auto-relogin
        // kicks in, retry succeeds, file lands on disk correctly.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .and(query_param("method", "login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "fresh"}
            })))
            .mount(&server)
            .await;

        // First download: 119. Second: real bytes.
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"success":false,"error":{"code":119}}"#),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/octet-stream")
                    .set_body_bytes(b"recovered payload".to_vec()),
            )
            .mount(&server)
            .await;

        let client = client_auto_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        let dest = unique_tmp_path("recovered.bin");
        client.download_to_path("/share/x", &dest).await.unwrap();

        let on_disk = std::fs::read(&dest).unwrap();
        assert_eq!(on_disk, b"recovered payload");
        std::fs::remove_file(&dest).ok();
    }

    #[tokio::test]
    async fn download_to_path_cleans_tmp_when_rename_target_is_unwritable() {
        // Force a rename failure by pointing at a path under a directory
        // that doesn't exist. The .part tmp won't even be created (parent
        // dir missing), so we should get an Io error and no leftover state.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/octet-stream")
                    .set_body_bytes(b"data".to_vec()),
            )
            .mount(&server)
            .await;

        let client = client_for(&server);
        let bogus_dir = unique_tmp_path("nonexistent-parent-dir");
        let dest = bogus_dir.join("file.bin");

        let err = client
            .download_to_path("/share/x", &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::Io(_)));
        assert!(!dest.exists());
    }

    // ── throttle: concurrency cap, backoff, error classification, retry bound ──
    //
    // The NAS incident: parallel FileStation Download calls saturated the shared
    // synoscgi CGI backend, and an inner retry storm re-fetched the same files
    // 200-250×. The throttle is the fix — a small global concurrency semaphore,
    // a rate-limit belt, jittered exponential backoff on transient/degraded
    // responses (HTTP 502/503/504, 407, DSM 402 busy), fail-fast on permanent
    // errors (missing file / no permission), and a hard per-file attempt cap so
    // the outer scheduler (e.g. Temporal) owns re-scheduling instead of an
    // unbounded inner loop.

    /// A throttle tuned for fast tests: tiny backoff so retry tests don't sleep
    /// for real seconds.
    fn fast_throttle(max_concurrency: usize, max_attempts: u32) -> ThrottleConfig {
        ThrottleConfig {
            max_concurrency,
            min_interval: Duration::from_millis(0),
            max_attempts,
            backoff_base: Duration::from_millis(1),
            backoff_max: Duration::from_millis(5),
        }
    }

    fn client_throttled_for(server: &MockServer, cfg: ThrottleConfig) -> SynologyClient {
        let uri = server.uri();
        let without_scheme = uri.trim_start_matches("http://");
        let (host, port_str) = without_scheme.rsplit_once(':').unwrap();
        let port: u16 = port_str.parse().unwrap();
        SynologyClient::new(host, port, false).with_throttle(cfg)
    }

    #[tokio::test]
    async fn download_retries_http_502_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(502))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"payload".to_vec()))
            .mount(&server)
            .await;

        let client = client_throttled_for(&server, fast_throttle(4, 5));
        let bytes = client.download("/share/f", 0, 0).await.unwrap();
        assert_eq!(bytes.as_ref(), b"payload");
    }

    #[tokio::test]
    async fn download_retries_http_407_then_succeeds() {
        // 407 during the incident was the backend fail-closing — back off and
        // retry, don't hammer through it.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(407))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".to_vec()))
            .mount(&server)
            .await;

        let client = client_throttled_for(&server, fast_throttle(4, 5));
        let bytes = client.download("/share/f", 0, 0).await.unwrap();
        assert_eq!(bytes.as_ref(), b"ok");
    }

    #[tokio::test]
    async fn download_402_busy_backs_off_and_retries() {
        // DSM 402 (system busy) arrives as a 200-OK JSON envelope. It is
        // transient — back off (harder) and retry rather than fail fast.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"success":false,"error":{"code":402}}"#),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/octet-stream")
                    .set_body_bytes(b"after-busy".to_vec()),
            )
            .mount(&server)
            .await;

        let client = client_throttled_for(&server, fast_throttle(4, 5));
        let bytes = client.download("/share/f", 0, 0).await.unwrap();
        assert_eq!(bytes.as_ref(), b"after-busy");
    }

    #[tokio::test]
    async fn download_missing_file_fails_fast_without_retry() {
        // A permanent error (DSM 415, no such file/folder) must NOT be retried —
        // retrying wastes the backend's attention exactly like a 502 storm.
        // .expect(1) fails on MockServer drop if we attempt it more than once.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"success":false,"error":{"code":415}}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = client_throttled_for(&server, fast_throttle(4, 5));
        let err = client.download("/share/missing", 0, 0).await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(415)), "got {err:?}");
    }

    #[tokio::test]
    async fn download_bounded_by_max_attempts() {
        // Persistent transient failure must give up after max_attempts — no
        // unbounded inner loop. .expect(3) pins the exact attempt count.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(502))
            .expect(3)
            .mount(&server)
            .await;

        let client = client_throttled_for(&server, fast_throttle(4, 3));
        let err = client.download("/share/f", 0, 0).await.unwrap_err();
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn download_concurrency_capped_by_semaphore() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Raw TCP server that records the peak number of simultaneously
        // in-flight requests. Each connection holds its slot for 50 ms so
        // parallel downloads overlap if the semaphore lets them.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cur = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let cur_s = cur.clone();
        let peak_s = peak.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let cur = cur_s.clone();
                let peak = peak_s.clone();
                tokio::spawn(async move {
                    let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let body = b"OKOKOK";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                    let _ = stream.shutdown().await;
                    cur.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        let client = Arc::new(
            SynologyClient::new("127.0.0.1", port, false).with_throttle(fast_throttle(2, 3)),
        );
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let c = client.clone();
            tasks.push(tokio::spawn(
                async move { c.download("/share/x", 0, 6).await },
            ));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        let observed = peak.load(Ordering::SeqCst);
        assert!(observed <= 2, "peak concurrency {observed} exceeded cap 2");
        assert!(observed >= 2, "expected the cap to actually be reached");
        handle.abort();
    }

    #[tokio::test]
    async fn download_rate_gate_spaces_out_requests() {
        // Even with plenty of concurrency, the min-interval belt keeps the
        // request rate against synoscgi modest. 4 requests spaced 80 ms apart
        // means the batch cannot finish faster than ~3 intervals.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"z".to_vec()))
            .mount(&server)
            .await;

        let cfg = ThrottleConfig {
            max_concurrency: 8,
            min_interval: Duration::from_millis(80),
            max_attempts: 1,
            backoff_base: Duration::from_millis(1),
            backoff_max: Duration::from_millis(1),
        };
        let client = std::sync::Arc::new(client_throttled_for(&server, cfg));

        let start = std::time::Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let c = client.clone();
            tasks.push(tokio::spawn(
                async move { c.download("/share/x", 0, 0).await },
            ));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(150),
            "rate gate did not space requests: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn unthrottled_client_download_unaffected() {
        // The FUSE/CLI path constructs the client without a throttle: behavior
        // is exactly as before (no cap, no added delay, plain success).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"plain".to_vec()))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let bytes = client.download("/share/f", 0, 0).await.unwrap();
        assert_eq!(bytes.as_ref(), b"plain");
    }
}
