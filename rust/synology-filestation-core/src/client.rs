use bytes::Bytes;
use reqwest::{multipart, Client};
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Semaphore, SemaphorePermit};
use tracing::{debug, error, warn};

use crate::error::{dsm_code_to_category, ErrorCategory, SynoFsError};
use crate::transport::{
    BreakerConfig, CircuitBreaker, ReadTransport, StreamReadTransport, StreamWriteTransport,
    WriteTransport,
};
use crate::types::{
    AuthData, CreateFolderData, GetInfoData, ListData, ListShareData, Md5StartData, Md5StatusData,
    RenameData, SynoFileInfo, SynoResponse, UploadData, ADDITIONAL_FIELDS, SHARE_ADDITIONAL_FIELDS,
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
#[derive(Clone)]
#[allow(dead_code)]
struct StoredCreds {
    user: String,
    password: String,
}

/// Hand-written so the stashed password cannot reach a log through a stray
/// `{:?}`. A derived Debug would print it in full, and this struct exists
/// precisely to hold a password for the lifetime of the session.
impl std::fmt::Debug for StoredCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCreds")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
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

/// How the session id is carried on an authenticated request.
///
/// DSM accepts it either as a `_sid` query parameter or as an `id` cookie. They
/// are equivalent to the server and very different everywhere else: a query
/// parameter is written verbatim into the NAS's own nginx access log, into any
/// proxy's log in between, and into the `Display` of every `reqwest` transport
/// error — which this client then logs, returns across the FFI, and raises as a
/// Python exception. A cookie appears in none of those.
///
/// So the cookie is preferred, and the query parameter is the fallback for a
/// DSM that will not take it.
const SESSION_AUTH_COOKIE: u8 = 0;
const SESSION_AUTH_QUERY: u8 = 1;
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

/// One injected backend plus the [`CircuitBreaker`] tracking its health. The
/// breaker is a `std::sync::Mutex` (quick, non-async state mutation, never held
/// across an `.await`).
struct TransportEntry<T: ?Sized> {
    transport: Arc<T>,
    breaker: StdMutex<CircuitBreaker>,
}

impl<T: ?Sized> TransportEntry<T> {
    fn new(transport: Arc<T>) -> Self {
        Self {
            transport,
            breaker: StdMutex::new(CircuitBreaker::new(BreakerConfig::default())),
        }
    }
}

/// Bytes per slice on the chunked upload path — the same 10 MiB DSM's own File
/// Station uploader uses (`chunksize` in `FileUploader.js`).
///
/// DSM only slices above `MAX_POST_FILESIZE` (4 GiB − 4096), because its
/// concern is the POST limit. Ours is memory: `http_upload` holds the whole
/// file in a `Vec<u8>`, so we slice anything that exceeds one slice.
pub const DEFAULT_SLICE_SIZE: usize = 10 * 1024 * 1024;

/// Entries requested per `list` / `list_share` page.
///
/// DSM caps what one response may carry, so a directory larger than this needs
/// several requests. Kept modest rather than maximal: a page is parsed whole, so
/// this trades one extra round trip on very large directories for a bounded
/// per-response allocation.
pub const LIST_PAGE_SIZE: usize = 1000;

/// Ceiling on pages fetched for a single listing, so a server that reports an
/// unreachable `total` (or keeps handing back full pages) cannot spin us
/// forever. At [`LIST_PAGE_SIZE`] this covers 10M entries in one directory.
const LIST_MAX_PAGES: usize = 10_000;

/// Upload progress sink: `(bytes_done, bytes_total)`, called once per slice.
/// Borrowed rather than boxed so callers can pass a plain closure reference.
pub type ProgressSink<'a> = &'a (dyn Fn(u64, u64) + Send + Sync);

/// How long a metadata or download request may take to produce response headers
/// (and, on the response body, how long it may go without delivering a chunk).
/// Uploads deliberately do not use it — see [`build_http_transfer`].
const METADATA_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Deadline policy for a single upload request: `grace + bytes / floor_bps`.
///
/// An upload cannot use a flat timeout — the payload spans four orders of
/// magnitude (a text file to a 10 MiB slice) and the link spans three (LAN to
/// a congested VPN). A rate floor scales the allowance with the bytes actually
/// in flight, so a big slice on a slow link gets the minutes it needs while a
/// genuinely wedged connection still fails instead of parking a FUSE callback
/// forever.
#[derive(Clone, Copy, Debug)]
struct UploadDeadline {
    /// Flat allowance on top of the transfer time, covering connect, TLS
    /// handshake and DSM writing the slice out before it answers.
    grace: Duration,
    /// Slowest upload throughput we still treat as progress rather than a
    /// stall. Set well below any usable link: the point is to catch a dead
    /// connection, not to enforce a service level.
    floor_bps: u64,
}

impl Default for UploadDeadline {
    fn default() -> Self {
        Self {
            grace: Duration::from_secs(60),
            // 32 KiB/s — a 10 MiB slice gets ~6 minutes.
            floor_bps: 32 * 1024,
        }
    }
}

impl UploadDeadline {
    fn for_bytes(&self, bytes: u64) -> Duration {
        self.grace + Duration::from_secs(bytes / self.floor_bps.max(1))
    }
}

/// How long to let a just-written file settle before a size disagreement is
/// treated as corruption rather than a listing that has not caught up.
const VERIFY_SETTLE_DELAY: Duration = Duration::from_millis(500);

/// How often the `SYNO.FileStation.MD5` task is polled — the same 1 s File
/// Station's own properties dialog uses.
const MD5_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Ceiling on waiting for a hash. DSM reads the whole file to produce one, so
/// this is generous; it exists so a task that never finishes cannot park a FUSE
/// `flush` indefinitely.
const MD5_MAX_WAIT: Duration = Duration::from_secs(15 * 60);

/// Why one slice of a chunked upload failed, and what that implies for
/// resending it.
enum SliceError {
    /// The server gave a definitive answer. Resending cannot change it.
    Fatal(SynoFsError),
    /// Worth another attempt. `may_have_landed` says whether the server might
    /// already hold these bytes — if it does, a resend appends them twice and
    /// the finished file has to be verified. `hard` doubles the backoff (DSM
    /// asking for a pause).
    Retryable {
        err: SynoFsError,
        may_have_landed: bool,
        hard: bool,
    },
}

/// MD5 of a local file, streamed in 1 MiB reads so a multi-GB upload is not
/// re-buffered to hash it. Runs on the blocking pool: hashing 6 GB is seconds
/// of solid CPU, which is not something to do on a runtime worker.
async fn md5_of_file(path: &Path) -> Result<String, SynoFsError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use md5::{Digest, Md5};
        use std::io::Read;

        let mut f = std::fs::File::open(&path)
            .map_err(|e| SynoFsError::Io(format!("md5: open {} failed: {e}", path.display())))?;
        let mut hasher = Md5::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = f.read(&mut buf).map_err(|e| {
                SynoFsError::Io(format!("md5: read {} failed: {e}", path.display()))
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    })
    .await
    .map_err(|e| SynoFsError::Io(format!("md5: hashing task failed: {e}")))?
}

pub struct SynologyClient {
    http: Client,
    /// Client for upload request bodies. Same connection policy as `http` minus
    /// the read timeout, which would otherwise cap how long a body may take to
    /// push — see [`build_http_transfer`].
    http_transfer: Client,
    /// How long a single upload request may take, derived from its size.
    upload_deadline: UploadDeadline,
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
    /// True when TLS certificate verification has been turned off via
    /// [`SynologyClient::with_insecure_tls`]. Tracked separately from the
    /// `reqwest::Client` (which does not expose its own settings) so consumers
    /// can tell the user which mode they are connecting in.
    insecure_tls: bool,
    /// Whether the session id travels as a cookie or as a `_sid` query
    /// parameter. Settled by a probe immediately after login.
    session_auth: std::sync::atomic::AtomicU8,
    /// Injected read backends, tried in order before the HTTP Download API.
    /// Empty (the default) = HTTP only, i.e. exactly today's behavior.
    read_transports: Vec<TransportEntry<dyn ReadTransport>>,
    /// Injected write backends, tried in order before the HTTP Upload API.
    write_transports: Vec<TransportEntry<dyn WriteTransport>>,
    /// Injected streaming write backends, tried in order by `upload_from_path`
    /// before falling back to reading the file into memory + HTTP upload.
    stream_write_transports: Vec<TransportEntry<dyn StreamWriteTransport>>,
    /// Injected streaming read backends, tried in order by `download_to_path`
    /// before falling back to the buffering HTTP download.
    stream_read_transports: Vec<TransportEntry<dyn StreamReadTransport>>,
    /// Bytes per slice for the chunked upload path. A file larger than this is
    /// uploaded slice-by-slice so it is never held in memory whole; anything
    /// smaller takes the one-shot path. Default [`DEFAULT_SLICE_SIZE`].
    slice_size: usize,
}

impl std::fmt::Debug for SynologyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynologyClient")
            .field("base_url", &self.base_url)
            .field("auto_relogin", &self.auto_relogin)
            .field("insecure_tls", &self.insecure_tls)
            .field("throttled", &self.throttle.is_some())
            .field("read_transports", &self.read_transports.len())
            .field("write_transports", &self.write_transports.len())
            .field(
                "stream_write_transports",
                &self.stream_write_transports.len(),
            )
            .field("stream_read_transports", &self.stream_read_transports.len())
            .finish_non_exhaustive()
    }
}

/// Install the ring `CryptoProvider` as the process default exactly once.
///
/// reqwest 0.13 is built with `rustls-no-provider`, so rustls has no compiled-in
/// provider and needs one installed before the first TLS `ClientConfig` is built.
/// We use ring (not aws-lc-rs) to keep the build free of cmake/NASM. `install_default`
/// errors if a provider is already set — by another crate or a second client — which
/// is exactly the idempotent outcome we want, so the result is intentionally ignored.
fn install_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl SynologyClient {
    pub fn new(host: &str, port: u16, https: bool) -> Self {
        install_crypto_provider();
        let scheme = if https { "https" } else { "http" };
        let base_url = format!("{}://{}:{}/webapi", scheme, host, port);
        Self {
            http: build_http(false),
            http_transfer: build_http_transfer(false),
            upload_deadline: UploadDeadline::default(),
            base_url,
            sid: RwLock::new(None),
            auto_relogin: false,
            creds: RwLock::new(None),
            throttle: None,
            insecure_tls: false,
            session_auth: std::sync::atomic::AtomicU8::new(SESSION_AUTH_COOKIE),
            read_transports: Vec::new(),
            write_transports: Vec::new(),
            stream_write_transports: Vec::new(),
            stream_read_transports: Vec::new(),
            slice_size: DEFAULT_SLICE_SIZE,
        }
    }

    /// Accept any TLS certificate, including self-signed and expired ones, and
    /// ignore hostname mismatches.
    ///
    /// This turns HTTPS into encryption-without-authentication: anything able to
    /// intercept the connection can present its own certificate and read the
    /// password in the login exchange. It exists because a self-signed
    /// certificate is the out-of-the-box state for a DSM appliance, and is
    /// surfaced to users as an explicit opt-in (`--insecure` on the CLI, a
    /// checkbox in the GUI, `verify_ssl=False` in the Python bindings) rather
    /// than being the silent default it used to be.
    ///
    /// Prefer installing the NAS's certificate in the system trust store.
    pub fn with_insecure_tls(mut self) -> Self {
        self.http = build_http(true);
        self.http_transfer = build_http_transfer(true);
        self.insecure_tls = true;
        self
    }

    /// Shrink the metadata read timeout so a test can prove uploads are not
    /// governed by it without waiting out the real 30 s.
    #[cfg(test)]
    fn with_read_timeout_for_test(mut self, d: Duration) -> Self {
        self.http = build_client(self.insecure_tls, Some(d));
        self
    }

    /// Shrink the per-upload deadline so a test can watch it fire.
    #[cfg(test)]
    fn with_upload_deadline_for_test(mut self, grace: Duration, floor_bps: u64) -> Self {
        self.upload_deadline = UploadDeadline { grace, floor_bps };
        self
    }

    /// Whether TLS certificate verification has been disabled on this client.
    /// Consumers use it to tell the user which mode they are connecting in.
    pub fn insecure_tls(&self) -> bool {
        self.insecure_tls
    }
}

/// Build the metadata/download HTTP client — everything except upload request
/// bodies, which get [`build_http_transfer`] instead.
fn build_http(accept_invalid_certs: bool) -> Client {
    build_client(accept_invalid_certs, Some(METADATA_READ_TIMEOUT))
}

/// Build the client used for upload request bodies: the same connection policy,
/// but with **no** `read_timeout`.
///
/// reqwest's read timeout is not the idle timer the name suggests. It is a
/// `sleep` armed when the request is created and polled alongside the pending
/// request, so it caps the whole span from "request started" to "response
/// headers arrived" — the time spent writing the request body included. On a
/// 30 s cap, any upload whose body takes longer than 30 s to push fails with
/// `operation timed out`, which on a slow link is every large file: 10 MiB
/// needs more than 30 s below ~350 KB/s. Uploads are bounded per request by
/// [`UploadDeadline`] instead, which knows how many bytes are in flight.
fn build_http_transfer(accept_invalid_certs: bool) -> Client {
    build_client(accept_invalid_certs, None)
}

/// Build an HTTP client. `accept_invalid_certs` and `read_timeout` are the only
/// knobs that vary; everything else is the timeout/keepalive policy the whole
/// crate depends on, so it lives in one place rather than being repeated per
/// constructor.
fn build_client(accept_invalid_certs: bool, read_timeout: Option<Duration>) -> Client {
    let builder = Client::builder()
        .danger_accept_invalid_certs(accept_invalid_certs)
        // Drop idle connections after 4 s so we don't reuse connections the NAS
        // has already closed on its side (~7 s keep-alive on most DSM versions).
        .pool_idle_timeout(Duration::from_secs(4))
        // Fail fast if the NAS is unreachable rather than waiting for the OS-level
        // TCP timeout (~75 s on macOS, ETIMEDOUT / os error 60).
        .connect_timeout(Duration::from_secs(10))
        // Send TCP keepalive probes so stalled mid-transfer connections are
        // detected in seconds rather than waiting for the full OS TCP timeout
        // (~75 s on macOS, ETIMEDOUT / os error 60).
        .tcp_keepalive(Duration::from_secs(10));
    // Bound how long we'll wait for a response. Without this, a silently-dead
    // connection (e.g. routes changed when a VPN comes up mid-session) hangs
    // the FUSE callback indefinitely — the user sees their file manager freeze
    // with no error. Requests that carry a large body opt out (see
    // `build_http_transfer`) because this cap covers the body write too.
    let builder = match read_timeout {
        Some(d) => builder.read_timeout(d),
        None => builder,
    };
    builder.build().expect("failed to build HTTP client")
}

impl SynologyClient {
    /// Inject a [`ReadTransport`] backend (e.g. SMB). `download` will prefer it
    /// over the HTTP Download API when its circuit breaker is closed, falling
    /// back to HTTP (and any later backends) on transport failures. Call more
    /// than once to register several backends; they are tried in the order
    /// added, with HTTP last.
    ///
    /// Read/write call sites never change — this is the only place a consumer
    /// opts a backend in.
    pub fn with_read_transport(mut self, transport: Arc<dyn ReadTransport>) -> Self {
        self.read_transports.push(TransportEntry::new(transport));
        self
    }

    /// Inject a [`WriteTransport`] backend. `upload` will prefer it over the
    /// HTTP Upload API when healthy, falling back to HTTP on transport failures.
    /// The backend's `write` must be atomic so fallback is safe.
    pub fn with_write_transport(mut self, transport: Arc<dyn WriteTransport>) -> Self {
        self.write_transports.push(TransportEntry::new(transport));
        self
    }

    /// Inject a [`StreamWriteTransport`] backend. `upload_from_path` will stream
    /// the local file straight to it when healthy, falling back to reading the
    /// file into memory + HTTP upload on transport failures.
    pub fn with_stream_write_transport(mut self, transport: Arc<dyn StreamWriteTransport>) -> Self {
        self.stream_write_transports
            .push(TransportEntry::new(transport));
        self
    }

    /// Inject a [`StreamReadTransport`] backend. `download_to_path` will stream
    /// straight to disk through it when healthy, falling back to the buffering
    /// HTTP download on transport failures.
    pub fn with_stream_read_transport(mut self, transport: Arc<dyn StreamReadTransport>) -> Self {
        self.stream_read_transports
            .push(TransportEntry::new(transport));
        self
    }

    /// Override the slice size used by the chunked upload path (default
    /// [`DEFAULT_SLICE_SIZE`]). A file larger than this is uploaded slice by
    /// slice; anything smaller takes the one-shot path. Mostly useful for tests
    /// and for tuning against a slow link.
    pub fn with_slice_size(mut self, bytes: usize) -> Self {
        self.slice_size = bytes.max(1);
        self
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

    /// Attach the session id to a request in whichever way this DSM accepts.
    ///
    /// Every authenticated call goes through here rather than pushing `_sid`
    /// into its own parameter list, so there is one place that decides how the
    /// token travels — and one place to audit.
    fn attach_session(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let sid = self.sid();
        if sid.is_empty() {
            return req;
        }
        if self.session_auth.load(std::sync::atomic::Ordering::Relaxed) == SESSION_AUTH_COOKIE {
            req.header(reqwest::header::COOKIE, format!("id={sid}"))
        } else {
            req.query(&[("_sid", sid.as_str())])
        }
    }

    /// Settle how the session id travels, once, straight after login.
    ///
    /// The cookie is a claim about somebody else's server, so it is checked
    /// rather than assumed: one cheap authenticated request in cookie mode, and
    /// if DSM answers 119 the client spends the rest of the session on the query
    /// parameter it used to use.
    ///
    /// Running this at login is the whole point of the design. A 119 is
    /// ambiguous in general — "the cookie was refused" and "the session expired"
    /// are the same code — but a session issued moments ago has not expired, so
    /// here the answer is unambiguous. Deciding it from the first ordinary call
    /// instead would misread an expired session as a rejected cookie and quietly
    /// start putting the id back into URLs.
    ///
    /// Only a definitive 119 triggers the fallback. A transport failure says
    /// nothing about whether the cookie is accepted — the network is simply
    /// down, and the next real call reports that on its own.
    async fn probe_session_transport(&self) {
        use std::sync::atomic::Ordering;

        self.session_auth
            .store(SESSION_AUTH_COOKIE, Ordering::Relaxed);

        let url = format!("{}/entry.cgi", self.base_url);
        let req = self.attach_session(self.http.get(&url).query(&[
            ("api", "SYNO.FileStation.List"),
            ("version", "2"),
            ("method", "list_share"),
            ("limit", "1"),
            ("offset", "0"),
        ]));

        let rejected = match req.send().await {
            Ok(resp) => match resp.text().await {
                Ok(body) => serde_json::from_str::<SynoResponse<serde_json::Value>>(&body)
                    .ok()
                    .filter(|envelope| !envelope.success)
                    .and_then(|envelope| envelope.error)
                    .is_some_and(|e| e.code == SID_NOT_FOUND),
                Err(_) => false,
            },
            Err(_) => false,
        };

        if rejected {
            warn!(
                "this DSM did not accept the session cookie; falling back to the _sid \
                 query parameter. The session id will appear in the NAS's access log."
            );
            self.session_auth
                .store(SESSION_AUTH_QUERY, Ordering::Relaxed);
        } else {
            debug!("session id will travel as a cookie");
        }
    }

    /// True when the session id is being kept out of request URLs.
    pub fn session_in_cookie(&self) -> bool {
        self.session_auth.load(std::sync::atomic::Ordering::Relaxed) == SESSION_AUTH_COOKIE
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
                debug!(
                    "retry {} for GET {}",
                    attempt,
                    crate::redact::redact_secrets(url)
                );
                tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
            }
            let resp = match self
                .attach_session(self.http.get(url).query(params))
                .send()
                .await
            {
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
    ///
    /// Sent as a form-encoded **POST**. It used to be a GET with
    /// `passwd=<plaintext>` in the query string, which put the account password
    /// into DSM's own nginx access log — and into any proxy's log between here
    /// and the NAS — on every single login. Request bodies are not logged that
    /// way. DSM's `auth.cgi` accepts either verb; this is the same exchange, it
    /// just stops writing the password to disk on the way past.
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
            .post(&url)
            .form(&params)
            .send()
            .await?
            .json::<SynoResponse<AuthData>>()
            .await?;

        if resp.success {
            let sid = resp
                .data
                .ok_or_else(|| SynoFsError::Io("no auth data".into()))?
                .sid;
            // Deliberately not logged, not even a prefix: the session id is a
            // bearer token, and a log line is exactly where it must not be.
            debug!("Logged in ({} byte session id)", sid.len());
            *self.sid.write().unwrap() = Some(sid);
            // Settle how the token travels before any real call uses it, while
            // the session is new enough that a 119 can only mean one thing.
            self.probe_session_transport().await;
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
            .attach_session(self.http.get(&url).query(&[
                ("api", "SYNO.API.Auth"),
                ("version", "7"),
                ("method", "logout"),
                ("session", "FileStation"),
            ]))
            .send()
            .await;
        *self.sid.write().unwrap() = None;
        Ok(())
    }

    /// Fetch a `SYNO.FileStation.List` listing in full, following pagination.
    ///
    /// A single request only ever returns one page, so asking once and keeping
    /// whatever came back silently truncates any directory bigger than the
    /// limit — and a filesystem that omits files is worse than one that errors.
    /// This keeps requesting at increasing offsets until the server says it is
    /// done, which it signals either by reporting a `total` we have reached or
    /// by handing back a partial (or empty) page.
    async fn list_paged<T, F>(
        &self,
        method: &str,
        extra_params: &[(&str, &str)],
        additional: &str,
        label: &str,
        unpack: F,
    ) -> Result<Vec<SynoFileInfo>, SynoFsError>
    where
        T: serde::de::DeserializeOwned,
        F: Fn(T) -> (Vec<SynoFileInfo>, Option<u64>),
    {
        let url = format!("{}/entry.cgi", self.base_url);
        let limit = LIST_PAGE_SIZE.to_string();
        let mut collected: Vec<SynoFileInfo> = Vec::new();

        for _ in 0..LIST_MAX_PAGES {
            let offset = collected.len().to_string();
            let mut params: Vec<(&str, &str)> = vec![
                ("api", "SYNO.FileStation.List"),
                ("version", "2"),
                ("method", method),
            ];
            params.extend_from_slice(extra_params);
            params.push(("additional", additional));
            params.push(("limit", &limit));
            params.push(("offset", &offset));

            let text = self.get_text_retried(&url, &params).await?;
            let resp: SynoResponse<T> = serde_json::from_str(&text)
                .map_err(|e| SynoFsError::Io(format!("{label} parse error: {e}")))?;
            if !resp.success {
                let code = resp.error.map(|e| e.code).unwrap_or(0);
                return Err(SynoFsError::ApiError(code));
            }

            let (page, total) = match resp.data {
                Some(d) => unpack(d),
                None => (Vec::new(), None),
            };
            let page_len = page.len();
            collected.extend(page);

            let done = page_len == 0
                || page_len < LIST_PAGE_SIZE
                || total.is_some_and(|t| collected.len() as u64 >= t);
            if done {
                debug!("{label}: {} entries", collected.len());
                return Ok(collected);
            }
        }

        // Only reachable from a server that keeps handing back full pages
        // without ever satisfying its own `total`. Return what we have rather
        // than looping, but say so — a short listing must never look normal.
        warn!(
            "{label}: stopped at the {LIST_MAX_PAGES}-page cap with {} entries; listing may be incomplete",
            collected.len()
        );
        Ok(collected)
    }

    /// List all FileStation shares the account can see.
    pub async fn list_shares(&self) -> Result<Vec<SynoFileInfo>, SynoFsError> {
        debug!("list_shares");
        self.list_paged::<ListShareData, _>(
            "list_share",
            &[],
            SHARE_ADDITIONAL_FIELDS,
            "list_shares",
            |d| (d.shares, d.total),
        )
        .await
    }

    /// List the contents of a directory.
    pub async fn list_dir(&self, folder_path: &str) -> Result<Vec<SynoFileInfo>, SynoFsError> {
        debug!("list_dir: {}", folder_path);
        self.list_paged::<ListData, _>(
            "list",
            &[("folder_path", folder_path)],
            ADDITIONAL_FIELDS,
            "list_dir",
            |d| (d.files, d.total),
        )
        .await
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

    /// Download a remote file atomically to `local_path`, preferring a
    /// [`StreamReadTransport`] backend (SMB) so a large file streams straight to
    /// disk with no in-memory copy.
    ///
    /// The destination is never observed partial — either complete or absent.
    /// On a transport failure the backend's breaker trips and we fall back to
    /// the buffering HTTP download; a definitive error (not-found / permission)
    /// propagates. With no stream backend injected this is exactly the HTTP
    /// download — today's behavior.
    #[allow(dead_code)] // unused by the FUSE binary today; consumed by python bindings.
    pub async fn download_to_path(
        &self,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<(), SynoFsError> {
        for entry in &self.stream_read_transports {
            let allowed = entry.breaker.lock().unwrap().allows(Instant::now());
            if !allowed {
                continue;
            }
            match entry.transport.read_to_path(remote_path, local_path).await {
                Ok(()) => {
                    entry.breaker.lock().unwrap().on_success();
                    return Ok(());
                }
                Err(e) if e.category() == ErrorCategory::Transport => {
                    warn!("stream read backend failed (transient), falling back: {e}");
                    entry.breaker.lock().unwrap().on_failure(Instant::now());
                    continue;
                }
                Err(e) => {
                    entry.breaker.lock().unwrap().on_success();
                    return Err(e);
                }
            }
        }
        self.http_download_to_path(remote_path, local_path).await
    }

    /// HTTP download-to-file: buffer the bytes, then write atomically
    /// (`<local_path>.part`, fsync, rename). Used when no stream backend is
    /// injected, and as the fallback when one trips its breaker.
    ///
    /// Guards against the DSM footgun of `200 OK` responses whose body is
    /// `{"success":false,"error":{"code":119}}` — the synology-api PyPI package
    /// opens its destination in `'wb'` first and silently leaves a 0-byte file.
    async fn http_download_to_path(
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

    /// Read file bytes, preferring any injected [`ReadTransport`] backend (SMB,
    /// …) over the HTTP Download API.
    ///
    /// Backends are tried in registration order; on a transport failure
    /// (`category() == Transport`) the backend's circuit breaker trips and we
    /// fall back to the next backend, ending at the HTTP path. A definitive
    /// error (not-found / permission) from a backend propagates unchanged — the
    /// backend answered, so re-asking HTTP the same question is pointless.
    ///
    /// With no backends injected this is exactly the HTTP download — today's
    /// behavior, unchanged.
    pub async fn download(
        &self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<Bytes, SynoFsError> {
        for entry in &self.read_transports {
            // Lock only to read/update breaker state — never held across await.
            let allowed = entry.breaker.lock().unwrap().allows(Instant::now());
            if !allowed {
                continue;
            }
            match entry.transport.read(path, offset, length).await {
                Ok(bytes) => {
                    entry.breaker.lock().unwrap().on_success();
                    return Ok(bytes);
                }
                Err(e) if e.category() == ErrorCategory::Transport => {
                    warn!("read backend failed (transient), falling back: {e}");
                    entry.breaker.lock().unwrap().on_failure(Instant::now());
                    continue;
                }
                Err(e) => {
                    // Reachable backend, definitive answer — trust it, propagate.
                    entry.breaker.lock().unwrap().on_success();
                    return Err(e);
                }
            }
        }
        self.http_download(path, offset, length).await
    }

    /// The HTTP FileStation Download implementation: throttle, transient retry,
    /// and DSM JSON-envelope detection. Used directly when no read backend is
    /// injected, and as the fallback when a backend trips its breaker.
    ///
    /// DSM violates HTTP convention by returning `200 OK` with a JSON error
    /// envelope (`{"success":false,"error":{"code":119}}`) when the SID is
    /// invalid, instead of a 4xx. We detect that case via the response body and
    /// surface `ApiError(code)` rather than returning the JSON as file content.
    async fn http_download(
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

                let mut req = self.attach_session(self.http.get(&url).query(&[
                    ("api", "SYNO.FileStation.Download"),
                    ("version", "2"),
                    ("method", "download"),
                    ("path", &path_json),
                    ("mode", "download"),
                ]));
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

    /// Write a whole file, preferring any injected [`WriteTransport`] backend
    /// (SMB, …) over the HTTP Upload API.
    ///
    /// Same selection + circuit-breaker semantics as [`download`](Self::download).
    /// A backend's `write` is atomic (old-or-nothing), so falling back to HTTP
    /// after a failed attempt can't collide with a half-written file. With no
    /// backends injected this is exactly the HTTP upload.
    pub async fn upload(
        &self,
        folder_path: &str,
        filename: &str,
        data: Vec<u8>,
        overwrite: bool,
    ) -> Result<(), SynoFsError> {
        // Only route *replacing* writes through a write backend. A backend's
        // `write` unconditionally replaces the file, so it can't honor
        // `overwrite=false`'s "fail if the file already exists" contract —
        // those go straight to the HTTP path, which does.
        if overwrite && !self.write_transports.is_empty() {
            let full_path = format!("{}/{}", folder_path.trim_end_matches('/'), filename);
            for entry in &self.write_transports {
                let allowed = entry.breaker.lock().unwrap().allows(Instant::now());
                if !allowed {
                    continue;
                }
                match entry.transport.write(&full_path, &data).await {
                    Ok(()) => {
                        entry.breaker.lock().unwrap().on_success();
                        return Ok(());
                    }
                    Err(e) if e.category() == ErrorCategory::Transport => {
                        warn!("write backend failed (transient), falling back: {e}");
                        entry.breaker.lock().unwrap().on_failure(Instant::now());
                        continue;
                    }
                    Err(e) => {
                        entry.breaker.lock().unwrap().on_success();
                        return Err(e);
                    }
                }
            }
        }
        self.http_upload(folder_path, filename, data, overwrite, None)
            .await
    }

    /// Stream a local file to the NAS, preferring a [`StreamWriteTransport`]
    /// backend (SMB) so a large file is never buffered in memory.
    ///
    /// Same selection + circuit-breaker + `overwrite` semantics as
    /// [`upload`](Self::upload). On fallback (no stream backend, or a transient
    /// failure) the file is read into memory and sent over HTTP — so the memory
    /// win applies to the streaming path, and correctness holds either way.
    pub async fn upload_from_path(
        &self,
        local: &Path,
        folder_path: &str,
        filename: &str,
        overwrite: bool,
    ) -> Result<(), SynoFsError> {
        self.upload_from_path_with_progress(local, folder_path, filename, overwrite, None)
            .await
    }

    /// [`upload_from_path`](Self::upload_from_path) with a progress sink called
    /// once per slice with cumulative bytes. Slice boundaries are internal to
    /// this crate, so a caller that wants a moving progress bar (the GUI, via
    /// the FFI) can only learn about them here.
    pub async fn upload_from_path_with_progress(
        &self,
        local: &Path,
        folder_path: &str,
        filename: &str,
        overwrite: bool,
        progress: Option<ProgressSink<'_>>,
    ) -> Result<(), SynoFsError> {
        if overwrite && !self.stream_write_transports.is_empty() {
            let full_path = format!("{}/{}", folder_path.trim_end_matches('/'), filename);
            for entry in &self.stream_write_transports {
                let allowed = entry.breaker.lock().unwrap().allows(Instant::now());
                if !allowed {
                    continue;
                }
                match entry.transport.write_from_path(&full_path, local).await {
                    Ok(()) => {
                        entry.breaker.lock().unwrap().on_success();
                        return Ok(());
                    }
                    Err(e) if e.category() == ErrorCategory::Transport => {
                        warn!("stream write backend failed (transient), falling back: {e}");
                        entry.breaker.lock().unwrap().on_failure(Instant::now());
                        continue;
                    }
                    Err(e) => {
                        entry.breaker.lock().unwrap().on_success();
                        return Err(e);
                    }
                }
            }
        }
        // Fallback: HTTP. A file bigger than one slice goes down the chunked
        // path so it is never resident in memory whole; smaller files keep the
        // existing one-shot behavior.
        let len = tokio::fs::metadata(local)
            .await
            .map_err(|e| {
                SynoFsError::Io(format!(
                    "upload_from_path: stat {} failed: {e}",
                    local.display()
                ))
            })?
            .len();
        if len > self.slice_size as u64 {
            return self
                .http_slice_upload(local, folder_path, filename, len, overwrite, progress)
                .await;
        }
        let data = tokio::fs::read(local).await.map_err(|e| {
            SynoFsError::Io(format!(
                "upload_from_path: read {} failed: {e}",
                local.display()
            ))
        })?;
        self.http_upload(
            folder_path,
            filename,
            data,
            overwrite,
            local_mtime_ms(local).await,
        )
        .await?;
        // One-shot: the only boundary we can report is the end of the file.
        if let Some(p) = progress {
            p(len, len);
        }
        Ok(())
    }

    /// Chunked ("slice") upload — the path DSM's own File Station uploader uses
    /// for large files, reimplemented from a capture of it plus its JS source.
    ///
    /// Each slice is one POST carrying the same body fields; the chunking rides
    /// in headers. The server hands back a `tmpfile` handle on the first slice,
    /// which every later slice echoes as `X-TMP-FILE` to append to the same
    /// partial file. The final slice sets `X-FILE-CHUNK-END: true` and its
    /// response is the result — there is no separate finalize call.
    ///
    /// Memory is bounded by one slice, in contrast to [`Self::http_upload`],
    /// which holds the whole file (and clones it per retry attempt).
    ///
    /// A failed slice is resent (bounded by [`Self::max_transfer_attempts`])
    /// rather than costing the whole file. DSM has no resume — it appends each
    /// slice blindly and never reports how much of the partial it holds — so a
    /// resend after the body may already have arrived can append the same bytes
    /// twice. That is why every completed upload is checked against what landed
    /// (see [`Self::verify_upload`]); a slice we cannot vouch for is never
    /// reported as a successful write.
    async fn http_slice_upload(
        &self,
        local: &Path,
        folder_path: &str,
        filename: &str,
        total: u64,
        overwrite: bool,
        progress: Option<ProgressSink<'_>>,
    ) -> Result<(), SynoFsError> {
        use tokio::io::AsyncReadExt;

        let url = format!("{}/entry.cgi", self.base_url);
        let slice_size = self.slice_size;
        let slices = total.div_ceil(slice_size as u64).max(1);
        debug!(
            "slice upload: {}/{} ({} bytes, {} slices of {})",
            folder_path, filename, total, slices, slice_size
        );

        if overwrite {
            self.clear_for_overwrite(folder_path, filename).await;
        }

        let mtime_ms = local_mtime_ms(local).await;

        let mut file = tokio::fs::File::open(local).await.map_err(|e| {
            SynoFsError::Io(format!(
                "slice upload: open {} failed: {e}",
                local.display()
            ))
        })?;
        let mut buf = vec![0u8; slice_size];
        let mut tmpfile: Option<String> = None;
        // Set when a resend might have appended a slice the server already
        // held. Only then is the finished file worth hashing.
        let mut unverified_resend = false;
        let max_attempts = self.max_transfer_attempts();

        for index in 0..slices {
            let want = std::cmp::min(slice_size as u64, total - index * slice_size as u64) as usize;
            file.read_exact(&mut buf[..want]).await.map_err(|e| {
                SynoFsError::Io(format!("slice upload: read slice {index} failed: {e}"))
            })?;
            let last = index + 1 == slices;

            let mut attempt = 0u32;
            let parsed = loop {
                let outcome = self
                    .send_slice(
                        &url,
                        folder_path,
                        filename,
                        &buf[..want],
                        total,
                        last,
                        tmpfile.as_deref(),
                        mtime_ms.as_deref(),
                    )
                    .await;
                match outcome {
                    Ok(parsed) => break parsed,
                    Err(SliceError::Fatal(e)) => return Err(e),
                    Err(SliceError::Retryable {
                        err,
                        may_have_landed,
                        hard,
                    }) => {
                        attempt += 1;
                        if attempt >= max_attempts {
                            return Err(err);
                        }
                        // Resending the *first* slice cannot double anything:
                        // with no tmpfile handle it opens a fresh partial file,
                        // and the abandoned one is the server's to reap. From
                        // the second slice on, the server may already hold what
                        // we are about to send again.
                        if may_have_landed && tmpfile.is_some() {
                            unverified_resend = true;
                        }
                        warn!(
                            "slice upload: slice {index} attempt {attempt} failed, resending: {err}"
                        );
                        self.backoff_before_retry(attempt - 1, hard).await;
                    }
                }
            };

            if let Some(p) = progress {
                p(index * slice_size as u64 + want as u64, total);
            }

            if !last {
                // Without a handle there is nothing for the next slice to append
                // to; DSM's own client treats this as fatal rather than retrying.
                tmpfile = match parsed
                    .data
                    .and_then(|d| d.tmpfile)
                    .filter(|t| !t.is_empty())
                {
                    Some(t) => Some(t),
                    None => {
                        return Err(SynoFsError::Io(format!(
                            "slice upload: server returned no tmpfile after slice {index}"
                        )))
                    }
                };
            }
        }

        let full_path = format!("{}/{}", folder_path.trim_end_matches('/'), filename);
        self.verify_upload(&full_path, local, total, unverified_resend)
            .await
    }

    /// Send one slice and classify what came back.
    ///
    /// The classification that matters is `may_have_landed`: whether the server
    /// could already hold these bytes. Only a failure in the connect/TLS phase
    /// proves it does not.
    #[allow(clippy::too_many_arguments)]
    async fn send_slice(
        &self,
        url: &str,
        folder_path: &str,
        filename: &str,
        chunk: &[u8],
        total: u64,
        last: bool,
        tmpfile: Option<&str>,
        mtime_ms: Option<&str>,
    ) -> Result<SynoResponse<UploadData>, SliceError> {
        let file_part = multipart::Part::bytes(chunk.to_vec())
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| SliceError::Fatal(SynoFsError::Io(e.to_string())))?;
        let mut form = multipart::Form::new()
            .text("overwrite", "false")
            .text("create_parents", "true")
            .text("path", folder_path.to_string());
        if let Some(ms) = mtime_ms {
            form = form.text("mtime", ms.to_string());
        }
        let form = form.part("file", file_part);

        let mut req = self
            .attach_session(self.http_transfer.post(url).query(&[
                ("api", "SYNO.FileStation.Upload"),
                ("method", "upload"),
                ("version", "2"),
            ]))
            // Sized to this slice, not to the file: each slice is its own
            // request, so a 6 GB upload is a long series of ~6-minute deadlines
            // rather than one open-ended wait.
            .timeout(self.upload_deadline.for_bytes(chunk.len() as u64))
            .header("X-TYPE-NAME", "SLICEUPLOAD")
            .header("X-FILE-SIZE", total.to_string())
            .header("X-FILE-CHUNK-END", if last { "true" } else { "false" });
        if let Some(t) = tmpfile {
            req = req.header("X-TMP-FILE", t.to_string());
        }

        let text = {
            let _slot = self.acquire_transfer_slot().await;
            let resp = match req.multipart(form).send().await {
                Ok(r) => r,
                Err(e) => {
                    // A connect/TLS failure is the one case where the body
                    // provably never left this machine. A timeout, a reset
                    // mid-body or a lost response all leave the question open.
                    let may_have_landed = !e.is_connect();
                    return Err(SliceError::Retryable {
                        err: SynoFsError::from(e),
                        may_have_landed,
                        hard: false,
                    });
                }
            };
            let status = resp.status();
            if !status.is_success() {
                let err = SynoFsError::Io(format!("slice upload HTTP {status}"));
                return Err(if http_status_is_transient(status) {
                    SliceError::Retryable {
                        err,
                        may_have_landed: true,
                        hard: false,
                    }
                } else {
                    SliceError::Fatal(err)
                });
            }
            match resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    return Err(SliceError::Retryable {
                        err: SynoFsError::from(e),
                        may_have_landed: true,
                        hard: false,
                    })
                }
            }
        };

        let parsed: SynoResponse<UploadData> = serde_json::from_str(&text).map_err(|e| {
            SliceError::Fatal(SynoFsError::Io(format!("slice upload parse error: {e}")))
        })?;
        if !parsed.success {
            let code = parsed.error.map(|e| e.code).unwrap_or(0);
            // 402 is the appliance asking for a pause, not a verdict on the
            // request — back off harder and try the slice again.
            return Err(if dsm_code_to_category(code) == ErrorCategory::Busy {
                SliceError::Retryable {
                    err: SynoFsError::ApiError(code),
                    may_have_landed: true,
                    hard: true,
                }
            } else {
                SliceError::Fatal(SynoFsError::ApiError(code))
            });
        }
        Ok(parsed)
    }

    /// Check that what landed on the NAS is what we sent, and refuse to report
    /// success otherwise.
    ///
    /// Two levels, because they cost very different amounts:
    ///
    /// * **Size** — one metadata call, run after every sliced upload. A doubled
    ///   slice the server kept shows up here immediately.
    /// * **MD5** — only when a resend could have doubled a slice, because it
    ///   makes DSM read the whole file back (minutes, and disk the appliance
    ///   would rather spend elsewhere). It is the only check that catches a
    ///   doubled slice if DSM trims the partial back to `X-FILE-SIZE`.
    ///
    /// A check that cannot *run* — no size in the listing, `SYNO.FileStation.MD5`
    /// missing or refused — is logged and the upload accepted: the write itself
    /// succeeded and there is no evidence against it. Only positive evidence of
    /// a mismatch fails the upload, and then the file is removed rather than
    /// left for someone to find later.
    async fn verify_upload(
        &self,
        full_path: &str,
        local: &Path,
        total: u64,
        hash_it: bool,
    ) -> Result<(), SynoFsError> {
        if let Some(size) = self.landed_size(full_path).await {
            if size != total {
                // The listing can lag a write DSM has just accepted — the same
                // lag `clear_for_overwrite` polls through. Confirm before
                // acting: a false positive here deletes a good upload.
                tokio::time::sleep(VERIFY_SETTLE_DELAY).await;
                if let Some(size) = self.landed_size(full_path).await {
                    if size != total {
                        return self
                            .reject_upload(
                                full_path,
                                format!("landed as {size} bytes, expected {total}"),
                            )
                            .await;
                    }
                }
            }
        }

        if !hash_it {
            return Ok(());
        }

        let remote = match self.md5(full_path).await {
            Ok(m) => m,
            Err(e) => {
                warn!("upload verify: MD5 of {full_path} unavailable ({e}), accepting as-is");
                return Ok(());
            }
        };
        let local_md5 = md5_of_file(local).await?;
        if !remote.eq_ignore_ascii_case(&local_md5) {
            return self
                .reject_upload(full_path, format!("md5 {remote} != {local_md5}"))
                .await;
        }
        debug!("upload verify: {full_path} matches after a resend");
        Ok(())
    }

    /// The size the NAS reports for `full_path`, or `None` when it cannot say —
    /// an unreadable listing is not evidence against an upload, so the caller
    /// treats it as "unverified" rather than "wrong".
    async fn landed_size(&self, full_path: &str) -> Option<u64> {
        match self.get_info(full_path).await {
            Ok(info) => match info.additional.and_then(|a| a.size) {
                Some(size) => Some(size),
                None => {
                    warn!("upload verify: no size reported for {full_path}, accepting as-is");
                    None
                }
            },
            Err(e) => {
                warn!("upload verify: getinfo {full_path} failed ({e}), accepting as-is");
                None
            }
        }
    }

    /// Remove a file whose contents we cannot vouch for, then report why.
    async fn reject_upload(&self, full_path: &str, why: String) -> Result<(), SynoFsError> {
        let msg = format!("upload verification failed for {full_path}: {why}");
        error!("{msg}");
        if let Err(e) = self.delete(full_path).await {
            warn!("could not remove unverified upload {full_path}: {e}");
        }
        Err(SynoFsError::Io(msg))
    }

    /// Have DSM hash a file it holds, via `SYNO.FileStation.MD5`.
    ///
    /// Two steps, as File Station's own properties dialog does it: `start`
    /// hands back a task id, `status` is polled (it polls at 1 s) until
    /// `finished`. Bounded by [`MD5_MAX_WAIT`] so a task that never finishes
    /// cannot park the caller — for the FUSE backend, that caller is a `flush`.
    pub async fn md5(&self, path: &str) -> Result<String, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.MD5"),
                    ("version", "2"),
                    ("method", "start"),
                    ("file_path", path),
                ],
            )
            .await?;
        let parsed: SynoResponse<Md5StartData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("md5 start parse error: {e}")))?;
        if !parsed.success {
            return Err(SynoFsError::ApiError(
                parsed.error.map(|e| e.code).unwrap_or(0),
            ));
        }
        let taskid = parsed
            .data
            .map(|d| d.taskid)
            .ok_or_else(|| SynoFsError::Io("md5 start returned no taskid".into()))?;

        let deadline = Instant::now() + MD5_MAX_WAIT;
        loop {
            let text = self
                .get_text_retried(
                    &url,
                    &[
                        ("api", "SYNO.FileStation.MD5"),
                        ("version", "2"),
                        ("method", "status"),
                        ("taskid", &taskid),
                    ],
                )
                .await?;
            let parsed: SynoResponse<Md5StatusData> = serde_json::from_str(&text)
                .map_err(|e| SynoFsError::Io(format!("md5 status parse error: {e}")))?;
            if !parsed.success {
                return Err(SynoFsError::ApiError(
                    parsed.error.map(|e| e.code).unwrap_or(0),
                ));
            }
            if let Some(data) = parsed.data {
                if data.finished {
                    return data.md5.filter(|m| !m.is_empty()).ok_or_else(|| {
                        SynoFsError::Io("md5 task finished without a digest".into())
                    });
                }
            }
            if Instant::now() >= deadline {
                return Err(SynoFsError::Io(format!(
                    "md5 of {path} did not finish within {}s",
                    MD5_MAX_WAIT.as_secs()
                )));
            }
            tokio::time::sleep(MD5_POLL_INTERVAL).await;
        }
    }

    /// Delete a file that is in the way of an upload, then wait for it to
    /// actually disappear. Shared by the one-shot and slice upload paths:
    /// `overwrite=true` on the multipart API times out on some DSM versions, so
    /// both always upload with `overwrite=false` onto cleared ground. Delete is
    /// async on modern DSM, hence the poll — otherwise the upload races it and
    /// fails 418 AlreadyExists.
    async fn clear_for_overwrite(&self, folder_path: &str, filename: &str) {
        let full_path = format!("{}/{}", folder_path.trim_end_matches('/'), filename);
        let _ = self.delete(&full_path).await; // ignore error — file may not exist yet
        for _ in 0..10u8 {
            match self.get_info(&full_path).await {
                Ok(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(_) => break, // gone or inaccessible — safe to upload
            }
        }
    }

    /// The HTTP FileStation Upload implementation. Used directly when no write
    /// backend is injected, and as the fallback when a backend trips its breaker.
    async fn http_upload(
        &self,
        folder_path: &str,
        filename: &str,
        data: Vec<u8>,
        overwrite: bool,
        // Local modification time in ms, when the caller has a file to take it
        // from. DSM stores it verbatim; without it the NAS stamps upload time.
        mtime_ms: Option<String>,
    ) -> Result<(), SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        debug!(
            "upload: {}/{} ({} bytes)",
            folder_path,
            filename,
            data.len()
        );

        let max_attempts = self.max_transfer_attempts();
        let mut last_err = SynoFsError::Io("no attempts".into());
        for attempt in 0..max_attempts {
            if attempt > 0 {
                debug!("upload retry {} for {}/{}", attempt, folder_path, filename);
            }

            // Re-clear on *every* attempt, not once up front. Both upload paths
            // always POST with `overwrite=false` (DSM's multipart overwrite
            // times out on some versions), so an attempt only succeeds onto
            // cleared ground. A previous attempt whose response was lost may
            // well have landed the file — retrying without re-clearing would
            // then get 418 and report a write that *succeeded* as
            // AlreadyExists. Re-clearing is also what makes retrying an upload
            // safe at all.
            if overwrite {
                self.clear_for_overwrite(folder_path, filename).await;
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
                .text("size", data.len().to_string())
                .text("overwrite", "false")
                .part("file", file_part);
            let form = match &mtime_ms {
                Some(ms) => form.text("mtime", ms.clone()),
                None => form,
            };

            // Hold a transfer slot only for the request+response read; drop it
            // before any backoff so a retrying upload doesn't hog a permit.
            // `Ok(text)` = a 2xx body to parse; `Err(e)` = retry this attempt.
            // A non-transient HTTP status returns immediately: the server gave
            // a definitive refusal, and resending the same request cannot help.
            let text = {
                let _slot = self.acquire_transfer_slot().await;
                match self
                    .attach_session(self.http_transfer.post(&url))
                    .timeout(self.upload_deadline.for_bytes(data.len() as u64))
                    .multipart(form)
                    .send()
                    .await
                {
                    Err(e) => Err(SynoFsError::from(e)),
                    Ok(r) => {
                        let status = r.status();
                        if status.is_success() {
                            r.text().await.map_err(SynoFsError::from)
                        } else {
                            let err = SynoFsError::Io(format!("upload HTTP {}", status));
                            if http_status_is_transient(status) {
                                Err(err)
                            } else {
                                return Err(err);
                            }
                        }
                    }
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

/// A local file's modification time in milliseconds since the epoch, as DSM's
/// upload API expects it. `None` when the filesystem can't report one — the
/// upload still proceeds, it just lands with the NAS's own timestamp.
async fn local_mtime_ms(path: &Path) -> Option<String> {
    tokio::fs::metadata(path)
        .await
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
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

    // ── TLS crypto provider ────────────────────────────────────────────────────

    /// reqwest 0.13 is built with `rustls-no-provider`, so rustls ships no
    /// compiled-in crypto provider. `SynologyClient::new` must install one (ring)
    /// as the process default, otherwise the first HTTPS handshake to the NAS
    /// panics/fails. The wiremock tests only speak HTTP and would not catch this,
    /// so pin it directly: after constructing an HTTPS client a default provider
    /// must be present.
    #[test]
    fn https_client_installs_default_crypto_provider() {
        let _client = SynologyClient::new("nas.example.invalid", 5001, true);
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "SynologyClient::new must install a default rustls CryptoProvider"
        );
    }

    // ── secret leakage ───────────────────────────────────────────────────────

    /// Regression: reqwest embeds the full request URL, query string included,
    /// in the Display of a transport error. Every FileStation call carried the
    /// session id as `_sid`, so one connection failure published a live bearer
    /// token into the CLI's stderr, the GUI's log pane and the message of every
    /// Python exception. Nothing leaving this client may carry it.
    #[tokio::test]
    async fn a_transport_error_never_carries_the_session_id() {
        // Port 1 has nothing listening, so the request fails at connect — the
        // path that bakes the request URL into the error message.
        let client = SynologyClient::new("127.0.0.1", 1, false);
        *client.sid.write().unwrap() = Some("SUPERSECRETSID".to_string());

        let err = client.list_dir("/share").await.unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("entry.cgi"),
            "precondition: the error should carry the URL, else this proves \
             nothing: {message}"
        );
        assert!(
            !message.contains("SUPERSECRETSID"),
            "session id leaked into a transport error: {message}"
        );
    }

    /// The stashed password must not be one stray `{:?}` away from a log line.
    ///
    /// The literal is deliberately shaped like a placeholder rather than like a
    /// password: a realistic-looking one here trips secret scanners on every
    /// pull request, and a security check that cries wolf is one people learn
    /// to click past.
    #[test]
    fn debug_formatting_stored_creds_hides_the_password() {
        let creds = StoredCreds {
            user: "alice".into(),
            password: "placeholder-not-a-real-password".into(),
        };
        let rendered = format!("{creds:?}");
        assert!(
            !rendered.contains("placeholder-not-a-real-password"),
            "{rendered}"
        );
        assert!(rendered.contains("alice"), "{rendered}");
    }

    // ── how the session id travels ───────────────────────────────────────────

    /// Mount the share listing the post-login probe asks for.
    async fn mount_probe_ok(server: &MockServer) {
        Mock::given(method("GET"))
            .and(query_param("method", "list_share"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"success": true, "data": {"total": 0, "shares": []}}),
            ))
            .mount(server)
            .await;
    }

    fn empty_list() -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({"success": true, "data": {"total": 0, "files": []}}))
    }

    /// Regression: the session id rode in the query string of every call, which
    /// puts a live bearer token in the NAS's own access log, in any proxy's log
    /// in between, and in the text of every transport error. It travels as a
    /// cookie now, and no request URL may contain it.
    #[tokio::test]
    async fn the_session_id_never_appears_in_a_request_url() {
        let server = MockServer::start().await;
        mount_auth(
            &server,
            serde_json::json!({"success": true, "data": {"sid": "SUPERSECRETSID"}}),
        )
        .await;
        mount_probe_ok(&server).await;
        Mock::given(method("GET"))
            .and(query_param("method", "list"))
            .respond_with(empty_list())
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        client.list_dir("/share").await.unwrap();
        client.logout().await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert!(requests.len() >= 4, "login + probe + list + logout");
        for req in &requests {
            assert!(
                !req.url.as_str().contains("SUPERSECRETSID"),
                "session id in a request URL: {}",
                req.url
            );
            assert!(
                !req.url.as_str().contains("_sid"),
                "_sid parameter still present: {}",
                req.url
            );
        }
    }

    /// ...and it does still reach the server, just in a header.
    #[tokio::test]
    async fn the_session_id_travels_as_a_cookie() {
        let server = MockServer::start().await;
        mount_auth(
            &server,
            serde_json::json!({"success": true, "data": {"sid": "SUPERSECRETSID"}}),
        )
        .await;
        mount_probe_ok(&server).await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        assert!(client.session_in_cookie());

        let requests = server.received_requests().await.unwrap();
        let probe = requests
            .iter()
            .find(|r| r.url.query().is_some_and(|q| q.contains("list_share")))
            .expect("the probe request");
        assert_eq!(
            probe.headers.get("cookie").unwrap().to_str().unwrap(),
            "id=SUPERSECRETSID"
        );
    }

    /// The cookie is a claim about a server we cannot test against here, so it
    /// is verified rather than assumed. A DSM that answers 119 to the probe
    /// sends the client back to the query parameter — degraded, but working,
    /// which is the right way round for an unverifiable assumption.
    #[tokio::test]
    async fn a_dsm_that_rejects_the_cookie_falls_back_to_the_query_parameter() {
        let server = MockServer::start().await;
        mount_auth(
            &server,
            serde_json::json!({"success": true, "data": {"sid": "SUPERSECRETSID"}}),
        )
        .await;
        Mock::given(method("GET"))
            .and(query_param("method", "list_share"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"success": false, "error": {"code": 119}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("method", "list"))
            .respond_with(empty_list())
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        assert!(
            !client.session_in_cookie(),
            "a 119 to the probe must switch the client to query auth"
        );

        client.list_dir("/share").await.unwrap();
        let requests = server.received_requests().await.unwrap();
        let list = requests
            .iter()
            .rfind(|r| r.url.query().is_some_and(|q| q.contains("method=list&")))
            .expect("the list request");
        assert!(
            list.url.as_str().contains("_sid=SUPERSECRETSID"),
            "the fallback must still authenticate: {}",
            list.url
        );
    }

    /// A probe that cannot reach the NAS says nothing about whether the cookie
    /// is accepted — the network is simply down. Downgrading on that would
    /// permanently degrade a session over an unrelated blip.
    #[tokio::test]
    async fn a_probe_that_cannot_reach_the_nas_does_not_downgrade_the_session() {
        let server = MockServer::start().await;
        mount_auth(
            &server,
            serde_json::json!({"success": true, "data": {"sid": "s"}}),
        )
        .await;
        // No probe route: wiremock answers 404 with an empty body — a failure,
        // but not a 119.
        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();

        assert!(
            client.session_in_cookie(),
            "only a definitive 119 should downgrade the session"
        );
    }
    // ── TLS verification ─────────────────────────────────────────────────────

    /// A one-shot HTTPS listener presenting a self-signed certificate for
    /// `localhost` — i.e. exactly the NAS setup that made someone reach for
    /// `danger_accept_invalid_certs` in the first place. Answers any request
    /// with a successful login envelope, so the only thing that can fail a test
    /// against it is the TLS handshake.
    ///
    /// Hand-rolled because wiremock speaks plain HTTP; the response is a canned
    /// HTTP/1.1 message rather than a real server.
    async fn self_signed_https_server() -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        install_crypto_provider();

        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = issued.cert.der().clone();
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return; // handshake refused by the client — the point of the test
                    };
                    let mut buf = [0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let body = r#"{"success":true,"data":{"sid":"tls_ok"}}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        port
    }

    /// Regression: the client called `danger_accept_invalid_certs(true)`
    /// unconditionally, so `https` bought encryption against a passive observer
    /// and nothing else — any machine able to intercept the connection could
    /// present its own certificate and read the password. Verification is now
    /// on by default.
    #[tokio::test]
    async fn https_rejects_a_self_signed_certificate_by_default() {
        let port = self_signed_https_server().await;
        let client = SynologyClient::new("localhost", port, true);

        let err = client
            .login("alice", "secret", None)
            .await
            .expect_err("an unverifiable certificate must not be silently accepted");

        assert!(
            matches!(err, SynoFsError::Io(_)),
            "expected a transport/TLS failure, got {err:?}"
        );
    }

    /// The escape hatch has to actually work: a self-signed NAS certificate is
    /// the normal case for this appliance, and `--insecure` is what those users
    /// are told to pass.
    #[tokio::test]
    async fn with_insecure_tls_accepts_a_self_signed_certificate() {
        let port = self_signed_https_server().await;
        let client = SynologyClient::new("localhost", port, true).with_insecure_tls();

        client
            .login("alice", "secret", None)
            .await
            .expect("--insecure must accept a self-signed certificate");
        assert_eq!(client.sid(), "tls_ok");
    }

    /// The CLI and GUI turn a rejected certificate into "…re-run with
    /// --insecure", which only works if the error is recognisable as a TLS
    /// failure. Pin `is_tls_error` against a real handshake so it tracks the
    /// string rustls actually produces.
    #[tokio::test]
    async fn a_rejected_certificate_is_recognisable_as_a_tls_failure() {
        let port = self_signed_https_server().await;
        let err = SynologyClient::new("localhost", port, true)
            .login("alice", "secret", None)
            .await
            .unwrap_err();

        assert!(
            err.is_tls_error(),
            "a rejected certificate must be recognisable so the user can be \
             pointed at --insecure; got: {err}"
        );
    }

    /// The flag is inspectable so the CLI/GUI/bindings can report which mode
    /// they are in, and so a future change cannot silently invert the default.
    #[test]
    fn tls_verification_is_on_unless_explicitly_disabled() {
        let strict = SynologyClient::new("nas.example.invalid", 5001, true);
        assert!(!strict.insecure_tls());
        assert!(strict.with_insecure_tls().insecure_tls());
    }

    // ── login ────────────────────────────────────────────────────────────────

    /// Mount an auth.cgi handler and return the login response body it serves.
    async fn mount_auth(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn login_stores_sid_on_success() {
        let server = MockServer::start().await;
        mount_auth(
            &server,
            serde_json::json!({"success": true, "data": {"sid": "abc123def"}}),
        )
        .await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        assert_eq!(client.sid(), "abc123def");
    }

    #[tokio::test]
    async fn login_returns_api_error_on_failure() {
        let server = MockServer::start().await;
        mount_auth(
            &server,
            serde_json::json!({"success": false, "error": {"code": 400}}),
        )
        .await;

        let client = client_for(&server);
        let err = client.login("alice", "wrong", None).await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(400)));
    }

    #[tokio::test]
    async fn login_with_otp_sends_the_otp_code() {
        let server = MockServer::start().await;
        mount_auth(
            &server,
            serde_json::json!({"success": true, "data": {"sid": "otp_sid_xyz"}}),
        )
        .await;

        let client = client_for(&server);
        client
            .login("alice", "secret", Some("123456"))
            .await
            .unwrap();
        assert_eq!(client.sid(), "otp_sid_xyz");

        let reqs = server.received_requests().await.unwrap();
        let body = String::from_utf8_lossy(&reqs[0].body);
        assert!(
            body.contains("otp_code=123456"),
            "otp missing from body: {body}"
        );
    }

    /// Regression: login was a GET carrying `passwd=<plaintext>` in the query
    /// string. Query strings are written to DSM's own nginx access log and to
    /// any proxy in between, so every login left the account password sitting
    /// in plaintext on disk in at least one place. Credentials belong in the
    /// request body.
    #[tokio::test]
    async fn login_never_puts_credentials_in_the_url() {
        let server = MockServer::start().await;
        mount_auth(
            &server,
            serde_json::json!({"success": true, "data": {"sid": "s"}}),
        )
        .await;

        let client = client_for(&server);
        client
            .login("alice", "placeholder-not-a-real-password", Some("998877"))
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let req = &reqs[0];
        let url = req.url.as_str();
        assert!(
            !url.contains("placeholder-not-a-real-password"),
            "password leaked into the URL: {url}"
        );
        assert!(!url.contains("passwd"), "passwd param in the URL: {url}");
        assert!(!url.contains("998877"), "otp leaked into the URL: {url}");
        assert!(!url.contains("alice"), "account leaked into the URL: {url}");

        // ...and it really did travel, just in the body.
        let body = String::from_utf8_lossy(&req.body);
        assert!(
            body.contains("placeholder-not-a-real-password"),
            "password missing from the body: {body}"
        );
    }

    // ── logout ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn logout_clears_sid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
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

    // ── list pagination ──────────────────────────────────────────────────────

    /// Build a `list`/`list_share` page: `count` synthetic entries plus the
    /// server-reported `total` for the whole directory.
    fn page_body(
        key: &str,
        prefix: &str,
        start: usize,
        count: usize,
        total: usize,
    ) -> serde_json::Value {
        let entries: Vec<serde_json::Value> = (start..start + count)
            .map(|i| {
                serde_json::json!({
                    "name": format!("f{i}"),
                    "path": format!("{prefix}/f{i}"),
                    "isdir": false,
                    "additional": null
                })
            })
            .collect();
        serde_json::json!({
            "success": true,
            "data": { "total": total, "offset": start, key: entries }
        })
    }

    /// Regression: `list_dir` sent a single request with a hardcoded limit and
    /// `offset=0`, then returned whatever came back. A directory with more
    /// entries than one page was silently listed short — through FUSE that
    /// presents as files that simply do not exist. Every page must be fetched.
    #[tokio::test]
    async fn list_dir_pages_until_the_server_total_is_reached() {
        let server = MockServer::start().await;
        let page = LIST_PAGE_SIZE;
        let total = page + 37;

        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .and(query_param("offset", "0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(page_body("files", "/share", 0, page, total)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .and(query_param("offset", page.to_string().as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(page_body("files", "/share", page, 37, total)),
            )
            .mount(&server)
            .await;

        let client = client_for(&server);
        let files = client.list_dir("/share").await.unwrap();
        assert_eq!(files.len(), total, "every page must be collected");
        assert_eq!(files[0].name, "f0");
        assert_eq!(files[total - 1].name, format!("f{}", total - 1));
    }

    /// Same defect on the share listing, which had an even smaller cap (500).
    #[tokio::test]
    async fn list_shares_pages_until_the_server_total_is_reached() {
        let server = MockServer::start().await;
        let page = LIST_PAGE_SIZE;
        let total = page + 5;

        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list_share"))
            .and(query_param("offset", "0"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(page_body("shares", "", 0, page, total)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list_share"))
            .and(query_param("offset", page.to_string().as_str()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(page_body("shares", "", page, 5, total)),
            )
            .mount(&server)
            .await;

        let client = client_for(&server);
        let shares = client.list_shares().await.unwrap();
        assert_eq!(shares.len(), total);
    }

    /// A directory that fits in one page must still cost exactly one request —
    /// paging must not add a speculative second round trip to every listing.
    #[tokio::test]
    async fn list_dir_stops_after_a_short_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(page_body("files", "/share", 0, 3, 3)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = client_for(&server);
        let files = client.list_dir("/share").await.unwrap();
        assert_eq!(files.len(), 3);
        // `expect(1)` is asserted when the server drops at end of scope.
    }

    /// A server that reports a `total` it never delivers (or keeps returning
    /// full pages forever) must not spin the client indefinitely: paging stops
    /// as soon as a page comes back empty.
    #[tokio::test]
    async fn list_dir_stops_when_a_page_comes_back_empty() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page_body(
                "files",
                "/share",
                0,
                LIST_PAGE_SIZE,
                999_999,
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .and(query_param("offset", LIST_PAGE_SIZE.to_string().as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"total": 999_999, "files": []}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let files = client.list_dir("/share").await.unwrap();
        assert_eq!(files.len(), LIST_PAGE_SIZE);
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

    /// Regression: `clear_for_overwrite` used to run *once*, before the retry
    /// loop. An overwrite that had to be retried therefore re-POSTed with
    /// `overwrite=false` onto ground that was no longer clear — if the first
    /// attempt actually landed on the NAS before the response was lost, DSM
    /// answered 418 and a write that had *succeeded* was reported as
    /// AlreadyExists. Each attempt must start from cleared ground.
    #[tokio::test]
    async fn overwrite_upload_reclears_the_destination_before_each_retry() {
        let server = MockServer::start().await;

        // The delete must happen once per upload attempt, not once per call.
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "delete"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"success": true})),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"success": false, "error": {"code": 414}})),
            )
            .mount(&server)
            .await;

        // First attempt: the backend is degraded (the shape that leaves a write
        // possibly-applied but unacknowledged). Second attempt: fine.
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"success": true, "data": {"blks": null}})),
            )
            .with_priority(2)
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .upload("/share", "test.txt", b"new content".to_vec(), true)
            .await
            .expect("a retried overwrite must succeed, not report AlreadyExists");
        // `expect(2)` on the delete mock is asserted when the server drops.
    }

    /// The retry above is only safe because each attempt re-clears; it must not
    /// widen into retrying a *definitive* refusal. A 400 is the server telling
    /// us the request itself is wrong — resending it cannot help.
    #[tokio::test]
    async fn upload_does_not_retry_a_permanent_http_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client
            .upload("/share", "test.txt", b"data".to_vec(), false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SynoFsError::Io(ref m) if m.contains("400")),
            "expected a permanent HTTP error, got {err:?}"
        );
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
        Mock::given(method("POST"))
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
        Mock::given(method("POST"))
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
        Mock::given(method("POST"))
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
        Mock::given(method("POST"))
            .and(path("/webapi/auth.cgi"))
            .and(body_string_contains("method=login"))
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
        Mock::given(method("POST"))
            .and(path("/webapi/auth.cgi"))
            .and(body_string_contains("method=login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "first"}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/auth.cgi"))
            .and(body_string_contains("method=login"))
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
        Mock::given(method("POST"))
            .and(path("/webapi/auth.cgi"))
            .and(body_string_contains("method=login"))
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
        Mock::given(method("POST"))
            .and(path("/webapi/auth.cgi"))
            .and(body_string_contains("method=login"))
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

        Mock::given(method("POST"))
            .and(path("/webapi/auth.cgi"))
            .and(body_string_contains("method=login"))
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

    // ── read/write backend selection + fallback ──────────────────────────────
    //
    // Dependency-inversion: a backend (SMB today) is injected and preferred over
    // HTTP, with a per-backend circuit breaker. These pin the selection contract
    // with a configurable fake backend so no real SMB server is needed.

    use std::sync::atomic::{AtomicUsize, Ordering};

    enum Behave {
        Ok(&'static [u8]),
        Transient, // category Transport → fall back
        NotFound,  // definitive → propagate, no fallback
    }

    struct FakeBackend {
        behave: Behave,
        calls: AtomicUsize,
    }

    impl FakeBackend {
        fn new(behave: Behave) -> Arc<Self> {
            Arc::new(Self {
                behave,
                calls: AtomicUsize::new(0),
            })
        }
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
        fn outcome_bytes(&self) -> Result<Bytes, SynoFsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.behave {
                Behave::Ok(b) => Ok(Bytes::from_static(b)),
                Behave::Transient => Err(SynoFsError::Io("backend down".into())),
                Behave::NotFound => Err(SynoFsError::NotFound),
            }
        }
        fn outcome_unit(&self) -> Result<(), SynoFsError> {
            self.outcome_bytes().map(|_| ())
        }
    }

    #[async_trait::async_trait]
    impl ReadTransport for FakeBackend {
        async fn read(&self, _p: &str, _o: u64, _l: u64) -> Result<Bytes, SynoFsError> {
            self.outcome_bytes()
        }
    }

    #[async_trait::async_trait]
    impl WriteTransport for FakeBackend {
        async fn write(&self, _p: &str, _d: &[u8]) -> Result<(), SynoFsError> {
            self.outcome_unit()
        }
    }

    #[async_trait::async_trait]
    impl StreamWriteTransport for FakeBackend {
        async fn write_from_path(&self, _p: &str, _local: &Path) -> Result<(), SynoFsError> {
            self.outcome_unit()
        }
    }

    #[async_trait::async_trait]
    impl StreamReadTransport for FakeBackend {
        async fn read_to_path(&self, _remote: &str, local: &Path) -> Result<(), SynoFsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.behave {
                // A real backend writes the destination; do the same so tests
                // can assert on the file it produced.
                Behave::Ok(b) => {
                    std::fs::write(local, b).map_err(|e| SynoFsError::Io(e.to_string()))?;
                    Ok(())
                }
                Behave::Transient => Err(SynoFsError::Io("backend down".into())),
                Behave::NotFound => Err(SynoFsError::NotFound),
            }
        }
    }

    /// A client pointed at a dead address (no HTTP server) — proves a call is
    /// served by the backend without ever touching HTTP.
    fn offline_client() -> SynologyClient {
        SynologyClient::new("127.0.0.1", 1, false)
    }

    #[tokio::test]
    async fn download_prefers_healthy_backend_and_skips_http() {
        let backend = FakeBackend::new(Behave::Ok(b"from-smb"));
        let client = offline_client().with_read_transport(backend.clone());
        // No HTTP server exists; if this returns, the backend served it.
        let bytes = client.download("/share/f", 0, 0).await.unwrap();
        assert_eq!(bytes.as_ref(), b"from-smb");
        assert_eq!(backend.call_count(), 1);
    }

    #[tokio::test]
    async fn download_propagates_definitive_backend_error_without_http() {
        let backend = FakeBackend::new(Behave::NotFound);
        let client = offline_client().with_read_transport(backend.clone());
        let err = client.download("/share/missing", 0, 0).await.unwrap_err();
        assert!(matches!(err, SynoFsError::NotFound));
        assert_eq!(backend.call_count(), 1, "definitive error must not retry");
    }

    #[tokio::test]
    async fn download_falls_back_to_http_on_transient_backend_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"from-http".to_vec()))
            .mount(&server)
            .await;

        let backend = FakeBackend::new(Behave::Transient);
        let client = client_for(&server).with_read_transport(backend.clone());
        let bytes = client.download("/share/f", 0, 0).await.unwrap();
        assert_eq!(bytes.as_ref(), b"from-http", "fell back to HTTP");
        assert_eq!(backend.call_count(), 1);
    }

    #[tokio::test]
    async fn breaker_opens_and_stops_probing_a_failing_backend() {
        // Default breaker threshold is 2. A persistently-transient backend
        // should be tried on the first two downloads, then skipped entirely
        // while HTTP keeps serving.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"http".to_vec()))
            .mount(&server)
            .await;

        let backend = FakeBackend::new(Behave::Transient);
        let client = client_for(&server).with_read_transport(backend.clone());

        for _ in 0..5 {
            assert_eq!(
                client.download("/share/f", 0, 0).await.unwrap().as_ref(),
                b"http"
            );
        }
        // Tried twice (to reach the threshold), then the open breaker skips it.
        assert_eq!(backend.call_count(), 2, "breaker should stop probing");
    }

    #[tokio::test]
    async fn upload_prefers_backend_then_falls_back_on_transient() {
        // Healthy write backend serves a replacing upload with no HTTP server.
        let ok_backend = FakeBackend::new(Behave::Ok(b""));
        let client = offline_client().with_write_transport(ok_backend.clone());
        client
            .upload("/share", "f.bin", b"data".to_vec(), true)
            .await
            .unwrap();
        assert_eq!(ok_backend.call_count(), 1);

        // Transient write failure falls back to the HTTP upload.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"blks": null}
            })))
            .mount(&server)
            .await;
        let bad_backend = FakeBackend::new(Behave::Transient);
        let client = client_for(&server).with_write_transport(bad_backend.clone());
        client
            .upload("/share", "f.bin", b"data".to_vec(), true)
            .await
            .unwrap();
        assert_eq!(
            bad_backend.call_count(),
            1,
            "attempted before HTTP fallback"
        );
    }

    #[tokio::test]
    async fn upload_overwrite_false_bypasses_write_backend() {
        // A backend's write always replaces, so it can't honor overwrite=false's
        // "fail if the file exists" contract — that write must go to HTTP, not
        // silently clobber an existing file over SMB.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"blks": null}
            })))
            .mount(&server)
            .await;
        let backend = FakeBackend::new(Behave::Ok(b""));
        let client = client_for(&server).with_write_transport(backend.clone());
        client
            .upload("/share", "f.bin", b"data".to_vec(), false)
            .await
            .unwrap();
        assert_eq!(
            backend.call_count(),
            0,
            "overwrite=false must skip the replacing write backend"
        );
    }

    // ── streaming upload (upload_from_path) selection ────────────────────────

    fn write_scratch_file(bytes: &[u8]) -> std::path::PathBuf {
        let p = unique_tmp_path("stream-upload-src.bin");
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[tokio::test]
    async fn upload_from_path_prefers_stream_backend_and_skips_http() {
        let src = write_scratch_file(b"streamed payload");
        let backend = FakeBackend::new(Behave::Ok(b""));
        let client = offline_client().with_stream_write_transport(backend.clone());
        client
            .upload_from_path(&src, "/share", "f.bin", true)
            .await
            .unwrap();
        assert_eq!(backend.call_count(), 1);
        std::fs::remove_file(&src).ok();
    }

    #[tokio::test]
    async fn upload_from_path_falls_back_to_http_on_transient() {
        let src = write_scratch_file(b"streamed payload");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"blks": null}
            })))
            .mount(&server)
            .await;
        let backend = FakeBackend::new(Behave::Transient);
        let client = client_for(&server).with_stream_write_transport(backend.clone());
        client
            .upload_from_path(&src, "/share", "f.bin", true)
            .await
            .unwrap();
        assert_eq!(backend.call_count(), 1, "attempted before HTTP fallback");
        std::fs::remove_file(&src).ok();
    }

    #[tokio::test]
    async fn upload_from_path_overwrite_false_bypasses_stream_backend() {
        let src = write_scratch_file(b"streamed payload");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"blks": null}
            })))
            .mount(&server)
            .await;
        let backend = FakeBackend::new(Behave::Ok(b""));
        let client = client_for(&server).with_stream_write_transport(backend.clone());
        client
            .upload_from_path(&src, "/share", "f.bin", false)
            .await
            .unwrap();
        assert_eq!(
            backend.call_count(),
            0,
            "overwrite=false must skip the streaming backend"
        );
        std::fs::remove_file(&src).ok();
    }

    // ── streaming download (download_to_path) selection ──────────────────────

    #[tokio::test]
    async fn download_to_path_prefers_stream_backend_and_skips_http() {
        let backend = FakeBackend::new(Behave::Ok(b"streamed to disk"));
        let client = offline_client().with_stream_read_transport(backend.clone());
        let dest = unique_tmp_path("stream-dl.bin");
        client.download_to_path("/share/f", &dest).await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"streamed to disk");
        assert_eq!(backend.call_count(), 1);
        std::fs::remove_file(&dest).ok();
    }

    #[tokio::test]
    async fn download_to_path_falls_back_to_http_on_transient() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"from-http".to_vec()))
            .mount(&server)
            .await;
        let backend = FakeBackend::new(Behave::Transient);
        let client = client_for(&server).with_stream_read_transport(backend.clone());
        let dest = unique_tmp_path("stream-dl-fallback.bin");
        client.download_to_path("/share/f", &dest).await.unwrap();
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"from-http",
            "fell back to HTTP"
        );
        assert_eq!(backend.call_count(), 1);
        std::fs::remove_file(&dest).ok();
    }

    #[tokio::test]
    async fn download_to_path_propagates_definitive_backend_error() {
        let backend = FakeBackend::new(Behave::NotFound);
        let client = offline_client().with_stream_read_transport(backend.clone());
        let dest = unique_tmp_path("stream-dl-missing.bin");
        let err = client
            .download_to_path("/share/missing", &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::NotFound));
        assert_eq!(backend.call_count(), 1);
        assert!(!dest.exists(), "definitive failure leaves no file");
    }

    // ── slice upload ─────────────────────────────────────────────────────────
    //
    // Mirrors what the DSM 7 File Station web UI does for large files (mined
    // from a browser capture of a 4.9 GB upload): one POST per slice, with the
    // chunking carried in request headers rather than the multipart body. Every
    // slice repeats the same body fields; the server ties them together by tmpfile.
    //
    //   X-TYPE-NAME: SLICEUPLOAD
    //   X-FILE-SIZE: <total bytes>
    //   X-FILE-CHUNK-END: false   (true on the final slice)
    //   X-TMP-FILE: <tmpfile>     (echoed from the previous response, slice 2+)
    //
    // Confirmed against DSM's own uploader (FileUploader_T9JY.js): the final
    // data slice carries X-FILE-CHUNK-END: true and its response is the result --
    // there is no separate finalize request. Slices are tied together by echoing
    // the response's `tmpfile` back as X-TMP-FILE; a non-final response without
    // one is fatal. DSM slices only above 4 GiB; we slice above one slice, because
    // our motive is bounded memory rather than its POST limit.

    /// Write `len` bytes to a scratch file and return its path.
    fn scratch_file(name: &str, len: usize) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("syno-slice-{}-{name}", std::process::id()));
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, data).unwrap();
        path
    }

    fn header_of(req: &wiremock::Request, name: &str) -> Option<String> {
        req.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn slice_upload_splits_file_and_marks_final_slice() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"blSkip": false, "progress": 1, "tmpfile": "slice.1.0.9224"}
            })))
            .mount(&server)
            .await;

        let local = scratch_file("split.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .unwrap();

        // POSTs only: a completed sliced upload also GETs the file back to
        // check what landed.
        let reqs = slice_posts(&server).await;
        assert_eq!(reqs.len(), 3, "2500 bytes at 1024/slice is 3 slices");
        for r in &reqs {
            assert_eq!(header_of(r, "X-TYPE-NAME").as_deref(), Some("SLICEUPLOAD"));
            assert_eq!(header_of(r, "X-FILE-SIZE").as_deref(), Some("2500"));
        }
        let ends: Vec<_> = reqs
            .iter()
            .map(|r| header_of(r, "X-FILE-CHUNK-END").unwrap())
            .collect();
        assert_eq!(ends, vec!["false", "false", "true"]);

        // Slice 1 opens the upload; every later slice echoes the tmpfile the
        // server handed back, which is what ties them to one partial file.
        let tmps: Vec<_> = reqs.iter().map(|r| header_of(r, "X-TMP-FILE")).collect();
        assert_eq!(
            tmps,
            vec![
                None,
                Some("slice.1.0.9224".to_string()),
                Some("slice.1.0.9224".to_string())
            ]
        );
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_skipped_for_file_that_fits_one_slice() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"blks": null}
            })))
            .mount(&server)
            .await;

        let local = scratch_file("small.bin", 500);
        let client = client_for(&server).with_slice_size(1024);
        client
            .upload_from_path(&local, "/share", "small.bin", false)
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1, "one-shot upload for a file under one slice");
        assert!(
            header_of(&reqs[0], "X-TYPE-NAME").is_none(),
            "no slice headers on the one-shot path"
        );
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_stops_at_the_failing_slice() {
        // A DSM error code is a verdict, not a blip: the slice is not resent,
        // and the remaining slices are not sent either. (Transport failures are
        // resent — see `slice_upload_resends_a_failed_slice_on_the_same_tmpfile`.)
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false, "error": {"code": 1805}
            })))
            .mount(&server)
            .await;

        let local = scratch_file("fail.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        let err = client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .unwrap_err();

        assert!(matches!(err, SynoFsError::ApiError(1805)));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "first slice fails, remaining slices are not sent"
        );
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_aborts_when_tmpfile_missing() {
        // DSM's own client treats a non-final response with no tmpfile as fatal:
        // without it the next slice has nothing to append to.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"blSkip": false, "progress": 1}
            })))
            .mount(&server)
            .await;

        let local = scratch_file("notmp.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        let err = client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .unwrap_err();

        assert!(matches!(err, SynoFsError::Io(_)));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "no tmpfile to continue with, so no second slice"
        );
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn upload_preserves_mtime_and_sends_size() {
        // Proven against the NAS in a browser capture: File Station sends the
        // local mtime in ms and the server stores it (the listing came back with
        // mtime = the value sent, crtime = upload time). Without it every
        // uploaded file is stamped with the upload time instead.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"blks": null}
            })))
            .mount(&server)
            .await;

        let local = scratch_file("mtime.bin", 300);
        let client = client_for(&server);
        client
            .upload_from_path(&local, "/share", "mtime.bin", false)
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body = String::from_utf8_lossy(&reqs[0].body).to_string();
        assert!(body.contains("name=\"size\""), "one-shot upload sends size");
        assert!(
            body.contains("name=\"mtime\""),
            "one-shot upload sends mtime"
        );
        let sent_ms: u128 = body
            .split("name=\"mtime\"")
            .nth(1)
            .unwrap()
            .trim_start_matches("\r\n\r\n")
            .lines()
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let want_ms = std::fs::metadata(&local)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        assert_eq!(
            sent_ms, want_ms,
            "mtime is the local file's, in milliseconds"
        );
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_reports_progress_per_slice() {
        // The FFI can't observe slice boundaries itself (they live inside the
        // core loop), so the GUI's upload bar depends on this callback.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"blSkip": false, "tmpfile": "slice.1.0.9224"}
            })))
            .mount(&server)
            .await;

        let local = scratch_file("progress.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        client
            .upload_from_path_with_progress(
                &local,
                "/share",
                "big.bin",
                false,
                Some(&move |done, total| sink.lock().unwrap().push((done, total))),
            )
            .await
            .unwrap();

        assert_eq!(
            *seen.lock().unwrap(),
            vec![(1024, 2500), (2048, 2500), (2500, 2500)],
            "cumulative bytes after each slice"
        );
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_sends_create_parents_like_the_one_shot_path() {
        // Both paths are reached through the same public API, so a large file
        // must not lose directory auto-creation that a small one gets.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"blSkip": false, "tmpfile": "slice.1.0.9224"}
            })))
            .mount(&server)
            .await;

        let local = scratch_file("parents.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        client
            .upload_from_path(&local, "/share/new/dir", "big.bin", false)
            .await
            .unwrap();

        for req in slice_posts(&server).await {
            let body = String::from_utf8_lossy(&req.body).to_string();
            assert!(
                body.contains("name=\"create_parents\""),
                "every slice carries create_parents"
            );
            // Deliberately absent: DSM's own uploader sends `size` only on the
            // one-shot path and puts the total in X-FILE-SIZE when slicing.
            assert!(
                !body.contains("name=\"size\""),
                "the slice path uses the X-FILE-SIZE header, not a size field"
            );
        }
        std::fs::remove_file(&local).ok();
    }

    // ── upload deadlines ─────────────────────────────────────────────────────
    //
    // reqwest's `read_timeout` is not the idle timer its name suggests: it is
    // armed when the request is created and polled alongside the pending
    // request, so it caps the whole span from "request started" to "response
    // headers arrived" — including writing the request body. A 30 s cap
    // therefore aborts any upload whose body takes longer than 30 s to push,
    // which on a slow link is every large file; the caller sees "operation
    // timed out" (EIO on the FUSE mount) with nothing actually wrong. Uploads
    // get their own client with no read timeout, bounded per request by a
    // size-derived deadline instead.

    #[tokio::test]
    async fn one_shot_upload_outlives_the_metadata_read_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(400))
                    .set_body_json(serde_json::json!({"success": true, "data": {}})),
            )
            .mount(&server)
            .await;

        let local = scratch_file("slow-oneshot.bin", 500);
        let client = client_for(&server)
            .with_slice_size(1024)
            .with_read_timeout_for_test(Duration::from_millis(100));
        client
            .upload_from_path(&local, "/share", "slow.bin", false)
            .await
            .expect("a slow upload is not a dead one");
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_outlives_the_metadata_read_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(400))
                    .set_body_json(serde_json::json!({
                        "success": true,
                        "data": {"blSkip": false, "tmpfile": "slice.1.0.9224"}
                    })),
            )
            .mount(&server)
            .await;

        let local = scratch_file("slow-slice.bin", 2500);
        let client = client_for(&server)
            .with_slice_size(1024)
            .with_read_timeout_for_test(Duration::from_millis(100));
        client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .expect("every slice gets the same reprieve");

        assert_eq!(slice_posts(&server).await.len(), 3);
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn upload_is_still_bounded_by_its_own_deadline() {
        // Dropping the read timeout must not mean "hang forever": a server that
        // takes the body and then goes silent still has to fail, or the FUSE
        // callback that called flush never returns.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(30))
                    .set_body_json(serde_json::json!({"success": true, "data": {}})),
            )
            .mount(&server)
            .await;

        let local = scratch_file("hung.bin", 500);
        let client = client_for(&server)
            .with_slice_size(1024)
            .with_upload_deadline_for_test(Duration::from_millis(150), u64::MAX);
        let started = std::time::Instant::now();
        let err = client
            .upload_from_path(&local, "/share", "hung.bin", false)
            .await
            .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the deadline fired, not the mock's own delay: {err}"
        );
        std::fs::remove_file(&local).ok();
    }

    #[test]
    fn upload_deadline_scales_with_the_payload() {
        let policy = UploadDeadline::default();
        // A 10 MiB slice on a link crawling at the assumed floor still fits.
        let slice = policy.for_bytes(DEFAULT_SLICE_SIZE as u64);
        assert!(
            slice >= Duration::from_secs(5 * 60),
            "10 MiB at the floor rate needs minutes, got {slice:?}"
        );
        // A bigger payload gets proportionally longer, rather than one fixed cap
        // that is either too tight for slow links or useless on fast ones.
        assert!(policy.for_bytes(DEFAULT_SLICE_SIZE as u64 * 4) > slice);
        // An empty body still gets the grace period, never a zero deadline.
        assert_eq!(policy.for_bytes(0), policy.grace);
    }

    // ── slice upload: retry, and the verification that makes it safe ──────────
    //
    // DSM offers no resume. The server appends each slice to its tmpfile and
    // never reports how many bytes it holds — `FileUploader_T9JY.js` computes
    // every offset client-side and, on any error, gives up on the whole file.
    // So a resent slice is exact only when the request never reached the
    // server; if the body went out and the answer was lost, resending may
    // append the same 10 MiB twice.
    //
    // We resend anyway, because the alternative is discarding a multi-GB
    // upload over one blip, and we make it safe by checking what actually
    // landed: the size always, plus a server-side MD5 (SYNO.FileStation.MD5
    // v2 — the API File Station's own properties dialog calls) whenever a
    // resend could have doubled a slice. A retry on the *first* slice can't
    // double anything: without a tmpfile handle the resend opens a fresh
    // partial, so it skips the hash.

    /// md5 of `scratch_file(_, 2500)`'s byte pattern, from `md5sum` rather than
    /// from our own hasher, so the test can disagree with the implementation.
    const SCRATCH_2500_MD5: &str = "babbd9d63dca99cb8d4cc054ba70829d";

    fn slice_ok() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"blSkip": false, "tmpfile": "slice.1.0.9224"}
        }))
    }

    /// Answer `getinfo` for the uploaded file with `size` bytes.
    async fn mount_getinfo_size(server: &MockServer, size: u64) {
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [{
                    "name": "big.bin",
                    "path": "/share/big.bin",
                    "isdir": false,
                    "additional": {"size": size, "owner": null, "time": null, "perm": null}
                }]}
            })))
            .mount(server)
            .await;
    }

    /// Answer the two-step MD5 task API with `digest`.
    async fn mount_md5(server: &MockServer, digest: &str) {
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("api", "SYNO.FileStation.MD5"))
            .and(query_param("method", "start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"taskid": "md5-1"}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("api", "SYNO.FileStation.MD5"))
            .and(query_param("method", "status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"finished": true, "md5": digest}
            })))
            .mount(server)
            .await;
    }

    /// Upload POSTs only — the verification traffic is GETs.
    async fn slice_posts(server: &MockServer) -> Vec<wiremock::Request> {
        server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .collect()
    }

    async fn md5_calls(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| {
                r.url
                    .query()
                    .is_some_and(|q| q.contains("SYNO.FileStation.MD5"))
            })
            .count()
    }

    #[tokio::test]
    async fn slice_upload_resends_a_failed_slice_on_the_same_tmpfile() {
        let server = MockServer::start().await;
        // Slice 1 goes out, slice 2 gets a 503, then everything succeeds.
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .mount(&server)
            .await;
        mount_getinfo_size(&server, 2500).await;
        mount_md5(&server, SCRATCH_2500_MD5).await;

        let local = scratch_file("retry.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .expect("a blip on one slice does not cost the file");

        let posts = slice_posts(&server).await;
        assert_eq!(posts.len(), 4, "3 slices plus one resend");
        // The resend continues the same partial file rather than starting over.
        let tmps: Vec<_> = posts.iter().map(|r| header_of(r, "X-TMP-FILE")).collect();
        assert_eq!(tmps[1], tmps[2], "the resend targets the same tmpfile");
        assert_eq!(
            header_of(&posts[3], "X-FILE-CHUNK-END").as_deref(),
            Some("true"),
            "the upload still terminates on the final slice"
        );
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_hashes_the_result_after_a_resend_that_could_have_doubled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .mount(&server)
            .await;
        mount_getinfo_size(&server, 2500).await;
        mount_md5(&server, SCRATCH_2500_MD5).await;

        let local = scratch_file("hashed.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .unwrap();

        assert!(
            md5_calls(&server).await >= 2,
            "a risky resend is verified by start + status"
        );
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_skips_the_hash_when_nothing_could_have_doubled() {
        // The happy path pays for one getinfo, never for a NAS-side hash of a
        // multi-GB file.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .mount(&server)
            .await;
        mount_getinfo_size(&server, 2500).await;
        mount_md5(&server, SCRATCH_2500_MD5).await;

        let local = scratch_file("clean.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .unwrap();

        assert_eq!(md5_calls(&server).await, 0, "no resend, no hash");
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn resending_the_first_slice_needs_no_hash() {
        // Slice 1 has no tmpfile to append to, so its resend opens a fresh
        // partial file. Nothing can be doubled, and the orphaned partial is the
        // server's to reap.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .mount(&server)
            .await;
        mount_getinfo_size(&server, 2500).await;
        mount_md5(&server, SCRATCH_2500_MD5).await;

        let local = scratch_file("firstfail.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .unwrap();

        let posts = slice_posts(&server).await;
        assert_eq!(posts.len(), 4, "3 slices plus the first slice's resend");
        assert!(
            header_of(&posts[1], "X-TMP-FILE").is_none(),
            "the resend of slice 1 opens a new partial rather than continuing one"
        );
        assert_eq!(md5_calls(&server).await, 0, "nothing could have doubled");
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_fails_when_the_landed_size_is_wrong() {
        // The cheap half of the safety net: a doubled slice that DSM kept makes
        // the file too big, and no hash is needed to see it.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .mount(&server)
            .await;
        mount_getinfo_size(&server, 3524).await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .mount(&server)
            .await;

        let local = scratch_file("wrongsize.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        let err = client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");

        let deleted = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.query().is_some_and(|q| q.contains("method=delete")));
        assert!(deleted, "a file we cannot vouch for is not left behind");
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_fails_when_the_server_hash_disagrees() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .mount(&server)
            .await;
        // Right size, wrong content — exactly what a doubled slice looks like
        // if DSM trims the partial back to X-FILE-SIZE.
        mount_getinfo_size(&server, 2500).await;
        mount_md5(&server, "00000000000000000000000000000000").await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .mount(&server)
            .await;

        let local = scratch_file("badhash.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        let err = client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");

        let deleted = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.query().is_some_and(|q| q.contains("method=delete")));
        assert!(
            deleted,
            "the corrupt file is removed, not reported as success"
        );
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_accepts_a_result_it_cannot_verify() {
        // MD5 is a DSM feature that can be missing or refused. The upload
        // itself succeeded and there is no evidence of harm, so an unverifiable
        // result is accepted with a warning rather than turned into a failure —
        // the documented residual risk of resending a slice.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .mount(&server)
            .await;
        mount_getinfo_size(&server, 2500).await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("api", "SYNO.FileStation.MD5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false, "error": {"code": 119}
            })))
            .mount(&server)
            .await;

        let local = scratch_file("noverify.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .expect("an unverifiable upload is not a failed one");
        std::fs::remove_file(&local).ok();
    }

    #[tokio::test]
    async fn slice_upload_gives_up_after_the_attempt_bound() {
        // Bounded, per the outer-retry contract: this client never spins on a
        // slice forever.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let local = scratch_file("hopeless.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        let err = client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");
        assert_eq!(
            slice_posts(&server).await.len(),
            3,
            "one slice, three attempts, then the error surfaces"
        );
        std::fs::remove_file(&local).ok();
    }

    // ── SYNO.FileStation.MD5 ─────────────────────────────────────────────────

    #[tokio::test]
    async fn md5_polls_the_task_until_it_finishes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"taskid": "md5-7"}
            })))
            .mount(&server)
            .await;
        // DSM reads the file to answer, so the first status call says "not yet".
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"finished": false}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"finished": true, "md5": "d41d8cd98f00b204e9800998ecf8427e"}
            })))
            .mount(&server)
            .await;

        let digest = client_for(&server).md5("/share/big.bin").await.unwrap();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

        let taskids: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter_map(|r| {
                r.url
                    .query_pairs()
                    .find(|(k, _)| k == "taskid")
                    .map(|(_, v)| v.to_string())
            })
            .collect();
        assert_eq!(
            taskids,
            vec!["md5-7", "md5-7"],
            "both polls carry the task id start handed back"
        );
    }

    #[tokio::test]
    async fn md5_surfaces_an_api_error_rather_than_polling_forever() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false, "error": {"code": 400}
            })))
            .mount(&server)
            .await;

        let err = client_for(&server).md5("/share/big.bin").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(400)), "got {err:?}");
    }

    #[tokio::test]
    async fn slice_upload_tolerates_a_size_that_settles() {
        // The listing can lag a write DSM has just accepted — the same lag
        // `clear_for_overwrite` polls through. A disagreement is confirmed
        // before it costs the file, because the alternative is deleting a
        // perfectly good upload.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(slice_ok())
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [{
                    "name": "big.bin", "path": "/share/big.bin", "isdir": false,
                    "additional": {"size": 1024, "owner": null, "time": null, "perm": null}
                }]}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount_getinfo_size(&server, 2500).await;

        let local = scratch_file("settles.bin", 2500);
        let client = client_for(&server).with_slice_size(1024);
        client
            .upload_from_path(&local, "/share", "big.bin", false)
            .await
            .expect("a listing that catches up is not a corrupt upload");

        let deleted = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.query().is_some_and(|q| q.contains("method=delete")));
        assert!(!deleted, "a good upload is never deleted");
        std::fs::remove_file(&local).ok();
    }
}
