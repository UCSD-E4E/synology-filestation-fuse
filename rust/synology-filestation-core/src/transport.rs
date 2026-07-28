//! Pluggable read/write **backends** and the health tracking that lets
//! [`SynologyClient`](crate::SynologyClient) prefer them over the HTTP
//! FileStation API — while transparently falling back to HTTP when a backend is
//! unavailable.
//!
//! The motivation is the NAS-saturation incident: the HTTP Download/Upload API
//! is proxied through the shared `synoscgi` backend, so a bulk transfer load can
//! take the appliance down. An alternative transport (SMB today; NFS, S3, or a
//! cache tomorrow) that talks to a *different* service relieves it. Backends
//! plug in by **dependency inversion**: they implement [`ReadTransport`] /
//! [`WriteTransport`] here, and consumers inject them at construction — the
//! read/write call sites (`download`/`upload`) never change, and this crate
//! never depends on any backend's protocol library.
//!
//! ## Error contract (the integration seam)
//!
//! An implementor maps its failures onto [`SynoFsError`] so the selection layer
//! can distinguish, via [`SynoFsError::category`]:
//!
//! * **transient** (connection lost / timeout / transport) → `Transport` — the
//!   selection layer trips this backend's [`CircuitBreaker`] and falls back;
//! * **definitive** (not-found / permission / …) → propagate unchanged; the
//!   backend is healthy and gave a real answer, so falling back would just ask
//!   the same NAS the same question.
//!
//! ## Write contract
//!
//! [`WriteTransport::write`] MUST be **atomic**: on success the whole file is
//! replaced; on failure the target is left untouched (old-or-nothing, never a
//! partial). That is what makes fallback *safe* — a failed primary write can't
//! leave a half-file for the HTTP path (or another backend) to collide with.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::SynoFsError;

/// A read backend serving file bytes as an alternative to the HTTP Download API.
#[async_trait]
pub trait ReadTransport: Send + Sync {
    /// Read `length` bytes at `offset`; `length == 0` reads the whole file
    /// (mirroring [`SynologyClient::download`](crate::SynologyClient::download)).
    async fn read(&self, path: &str, offset: u64, length: u64) -> Result<Bytes, SynoFsError>;
}

/// A write backend replacing a whole file, as an alternative to the HTTP Upload
/// API. Implementations MUST be atomic — see the [module docs](self#write-contract).
#[async_trait]
pub trait WriteTransport: Send + Sync {
    /// Atomically replace the file at `path` with `data`.
    async fn write(&self, path: &str, data: &[u8]) -> Result<(), SynoFsError>;
}

/// Tuning for a backend's [`CircuitBreaker`].
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// Consecutive transport failures that trip the breaker open.
    pub failure_threshold: u32,
    /// How long the breaker stays open before allowing a single re-probe.
    pub cooldown: Duration,
}

impl Default for BreakerConfig {
    /// Open after 2 consecutive transport failures; re-probe after 30 s. Sized
    /// so that walking off the SMB network trips the backend quickly (so we
    /// don't pay its connect timeout on every file) yet recovers on its own
    /// once we're back.
    fn default() -> Self {
        Self {
            failure_threshold: 2,
            cooldown: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum State {
    /// Backend is trusted — attempts are allowed.
    Closed,
    /// Backend is failing — attempts are skipped until `opened_at + cooldown`.
    Open { opened_at: Instant },
    /// Cooldown elapsed — one trial attempt is out; further attempts wait for
    /// its verdict.
    HalfOpen,
}

/// Per-backend health tracker. Skips a failing backend (so we don't pay its
/// connect timeout on every operation) and periodically re-probes to recover.
///
/// Time is passed in explicitly (`now: Instant`) rather than read from the clock
/// so the state machine is deterministically testable.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    state: State,
    consecutive_failures: u32,
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            state: State::Closed,
            consecutive_failures: 0,
        }
    }

    /// Whether a backend attempt is allowed at `now`. When the cooldown has
    /// elapsed this transitions `Open → HalfOpen` and allows exactly one trial.
    pub fn allows(&mut self, now: Instant) -> bool {
        match self.state {
            State::Closed => true,
            State::Open { opened_at } => {
                if now.duration_since(opened_at) >= self.config.cooldown {
                    self.state = State::HalfOpen;
                    true
                } else {
                    false
                }
            }
            State::HalfOpen => false,
        }
    }

    /// Record a healthy response (bytes, or a definitive error the backend
    /// answered): the backend is trusted again.
    pub fn on_success(&mut self) {
        self.state = State::Closed;
        self.consecutive_failures = 0;
    }

    /// Record a transport failure. A half-open trial that fails re-opens the
    /// breaker immediately; otherwise failures accumulate toward the threshold.
    pub fn on_failure(&mut self, now: Instant) {
        match self.state {
            State::HalfOpen => {
                self.state = State::Open { opened_at: now };
            }
            _ => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= self.config.failure_threshold {
                    self.state = State::Open { opened_at: now };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(BreakerConfig {
            failure_threshold: 2,
            cooldown: Duration::from_secs(30),
        })
    }

    #[test]
    fn starts_closed_and_allows() {
        let mut b = breaker();
        assert!(b.allows(Instant::now()));
    }

    #[test]
    fn opens_only_after_threshold_consecutive_failures() {
        let t = Instant::now();
        let mut b = breaker();
        b.on_failure(t);
        assert!(b.allows(t), "1 failure < threshold(2): still closed");
        b.on_failure(t);
        assert!(!b.allows(t), "2 failures: open, attempts skipped");
    }

    #[test]
    fn success_resets_the_failure_count() {
        let t = Instant::now();
        let mut b = breaker();
        b.on_failure(t);
        b.on_success(); // reachable again
        b.on_failure(t);
        assert!(
            b.allows(t),
            "count reset, so a lone later failure stays closed"
        );
    }

    #[test]
    fn stays_open_during_cooldown_then_half_opens_for_one_probe() {
        let t = Instant::now();
        let mut b = breaker();
        b.on_failure(t);
        b.on_failure(t); // open at t
        assert!(!b.allows(t + Duration::from_secs(10)), "still cooling");
        assert!(!b.allows(t + Duration::from_secs(29)), "still cooling");
        assert!(
            b.allows(t + Duration::from_secs(30)),
            "cooldown elapsed → half-open, one probe allowed"
        );
        assert!(
            !b.allows(t + Duration::from_secs(30)),
            "half-open: only a single trial is in flight"
        );
    }

    #[test]
    fn half_open_success_closes() {
        let t = Instant::now();
        let mut b = breaker();
        b.on_failure(t);
        b.on_failure(t);
        assert!(b.allows(t + Duration::from_secs(30))); // half-open probe
        b.on_success();
        assert!(b.allows(t + Duration::from_secs(31)), "closed again");
    }

    #[test]
    fn half_open_failure_reopens_for_another_cooldown() {
        let t = Instant::now();
        let mut b = breaker();
        b.on_failure(t);
        b.on_failure(t);
        let probe = t + Duration::from_secs(30);
        assert!(b.allows(probe)); // half-open probe
        b.on_failure(probe); // probe failed → reopen at `probe`
        assert!(!b.allows(probe + Duration::from_secs(10)), "cooling again");
        assert!(
            b.allows(probe + Duration::from_secs(30)),
            "half-opens again after another full cooldown"
        );
    }
}
