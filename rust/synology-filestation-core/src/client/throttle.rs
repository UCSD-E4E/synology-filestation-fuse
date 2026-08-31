//! The opt-in throttle that keeps this client from saturating `synoscgi`.

use super::*;

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
pub(super) struct Throttle {
    sem: Semaphore,
    min_interval: Duration,
    /// Earliest instant the next transfer request may start (rate-limit belt).
    next_earliest: Mutex<Instant>,
    max_attempts: u32,
    backoff_base: Duration,
    backoff_max: Duration,
}

/// Outcome of a single transfer attempt, deciding what the retry loop does next.
pub(super) enum TransferOutcome {
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
pub(super) fn http_status_is_transient(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 502 | 503 | 504 | 407)
}

/// Classify a successful (HTTP 200) download body. DSM violates HTTP convention
/// by returning `200 OK` with a JSON error envelope
/// (`{"success":false,"error":{"code":N}}`) instead of a 4xx. Small bodies that
/// plausibly *look* like an envelope are probed; real binary content passes
/// through untouched.
pub(super) fn classify_download_body(body: Bytes) -> TransferOutcome {
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
pub(super) fn full_jitter(cap: Duration) -> Duration {
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

impl SynologyClient {
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
    pub(super) fn max_transfer_attempts(&self) -> u32 {
        self.throttle.as_ref().map(|t| t.max_attempts).unwrap_or(3)
    }

    /// Reserve a transfer slot: apply the rate-limit belt, then acquire a
    /// concurrency permit. Returns `None` when unthrottled (the caller runs as
    /// before). The permit releases when the returned guard is dropped, so
    /// callers must hold it only for the request+body read and drop it before
    /// backing off.
    pub(super) async fn acquire_transfer_slot(&self) -> Option<SemaphorePermit<'_>> {
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
    pub(super) async fn backoff_before_retry(&self, attempt: u32, hard: bool) {
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
}
