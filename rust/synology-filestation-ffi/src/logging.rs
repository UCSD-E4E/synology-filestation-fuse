//! Bridge from the crate's `tracing` events to a C callback.
//!
//! The GUI installs a callback via `syno_set_log_callback`; we lazily install a
//! `tracing_subscriber::fmt` subscriber whose writer formats each event line
//! and hands it to whatever callback is currently registered. Installing the
//! subscriber is one-shot (a global default can only be set once), but the
//! callback target behind it can be swapped or cleared at any time.

use std::ffi::{c_void, CString};
use std::io::{self, Write};
use std::os::raw::c_char;
use std::sync::{Mutex, Once, OnceLock};

use tracing_subscriber::{fmt, prelude::*, reload, EnvFilter, Registry};

/// C callback signature: `(level, line, user_data)`. `level` mirrors the
/// `tracing::Level` ordering (1=ERROR … 5=TRACE); `line` is a NUL-terminated
/// UTF-8 string valid only for the duration of the call.
pub type LogCb = extern "C" fn(level: i32, line: *const c_char, user_data: *mut c_void);

/// A registered callback plus its opaque user-data pointer. The pointers are
/// only ever called/observed; we never deref `user_data` ourselves. The C#
/// side guarantees both stay valid until it clears the callback.
struct Sink {
    cb: LogCb,
    user_data: usize,
}

// SAFETY: the callback is a plain function pointer and `user_data` is treated
// as an opaque token; the foreign caller owns its lifetime and thread-safety.
unsafe impl Send for Sink {}

static SINK: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();
static INIT: Once = Once::new();
/// Handle to the reloadable level filter, so `set_level` can change verbosity
/// after the subscriber is installed.
static RELOAD: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

fn sink() -> &'static Mutex<Option<Sink>> {
    SINK.get_or_init(|| Mutex::new(None))
}

/// The crates whose `debug!` a person asking for debug actually wants.
///
/// Everything else in the process — TLS, HTTP, the userspace TCP stack — is
/// somebody else's diagnostic, and at debug it arrives faster than a log pane
/// can render.
const OURS: [&str; 6] = [
    "synology_filestation_core",
    "synology_filestation_fuse",
    "synology_filestation_ffi",
    "synology_filestation_connect",
    "synology_filestation_openvpn",
    "synology_filestation_smb",
];

/// The filter expression a requested level means.
///
/// A bare level is global, which is the whole bug: "debug" used to mean debug
/// for every crate linked into the process. The verbose levels are therefore
/// scoped to this workspace's crates, and everything else is left at `info` —
/// left, not lowered, so a dependency's warning still arrives.
///
/// Anything that already looks like a filter expression is passed through
/// untouched, matching what the CLI's `--log-level` accepts. Scoping the
/// levels would otherwise remove the only way to ask a dependency a question.
fn directives(level: &str) -> String {
    let asked = level.trim();
    if asked.contains('=') || asked.contains(',') {
        return asked.to_string();
    }
    let verbose = match asked.to_ascii_lowercase().as_str() {
        "error" => return "error".to_string(),
        "warn" => return "warn".to_string(),
        "debug" => "debug",
        "trace" => "trace",
        // `info` and anything unrecognised. Unrecognised is deliberately the
        // same as the default rather than an error: this arrives from a
        // settings file, and a typo there should not silence the log.
        _ => return "info".to_string(),
    };
    let mut out = String::from("info");
    for target in OURS {
        out.push(',');
        out.push_str(target);
        out.push('=');
        out.push_str(verbose);
    }
    out
}

/// Change the active log verbosity. No-op until the subscriber is installed
/// (the GUI registers a callback at startup, before any connect).
pub fn set_level(level: &str) {
    if let Some(handle) = RELOAD.get() {
        if let Ok(filter) = EnvFilter::try_new(directives(level)) {
            let _ = handle.reload(filter);
        }
    }
}

/// Register (or, with `cb == None`, clear) the log callback, installing the
/// tracing subscriber on first use.
///
/// # Safety
/// `cb`/`user_data` must remain valid until a subsequent call clears them.
pub unsafe fn set_callback(cb: Option<LogCb>, user_data: *mut c_void) {
    {
        let mut guard = sink().lock().unwrap();
        *guard = cb.map(|cb| Sink {
            cb,
            user_data: user_data as usize,
        });
    }
    INIT.call_once(|| {
        // INFO by default, reloadable via `set_level` so the GUI's log-level
        // control actually takes effect. Build the reload handle first so it is
        // available even if `try_init` later loses the global-default race.
        let (filter, handle) = reload::Layer::new(EnvFilter::new("info"));
        let _ = RELOAD.set(handle);
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_ansi(false).with_writer(|| CallbackWriter))
            .try_init();
    });
}

/// A `Write` sink that buffers a line and dispatches complete lines to the
/// registered callback. Lines are level-tagged best-effort by scanning the
/// formatted prefix.
struct CallbackWriter;

impl Write for CallbackWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        for line in text.split_inclusive('\n') {
            let trimmed = line.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                continue;
            }
            dispatch(trimmed);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn level_of(line: &str) -> i32 {
    // The fmt layer prints "<timestamp> <LEVEL> <target>: <message>". The level
    // is the first whitespace-delimited token that exactly equals a level name;
    // returning on the first exact match means message text containing the word
    // "ERROR"/"DEBUG" (which comes after the level) can't misclassify the line.
    for tok in line.split_whitespace() {
        match tok {
            "ERROR" => return 1,
            "WARN" => return 2,
            "INFO" => return 3,
            "DEBUG" => return 4,
            "TRACE" => return 5,
            _ => {}
        }
    }
    3 // default to INFO if no level token is found
}

fn dispatch(line: &str) {
    // Copy the callback + user_data out while holding the lock, then release it
    // *before* calling into foreign code. Calling under the lock risks a
    // deadlock if the callback re-enters logging or tries to swap/clear itself.
    let target = {
        let guard = match sink().lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        guard.as_ref().map(|s| (s.cb, s.user_data))
    };
    if let Some((cb, user_data)) = target {
        if let Ok(c) = CString::new(line) {
            cb(level_of(line), c.as_ptr(), user_data as *mut c_void);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the level was applied as a bare `LevelFilter`, which is
    /// global. Asking for "debug" therefore turned on debug for *every* crate
    /// in the process — rustls, hyper, reqwest, and, once a tunnel is up, the
    /// userspace TCP stack packet by packet. Our own crates emit almost no
    /// `debug!` at all, so nearly all of that volume was somebody else's, and
    /// it arrived through a C callback into a GUI that appends to a string per
    /// line. The log pane stopped being readable and the window stopped
    /// responding, which is a poor reward for asking a question.
    #[test]
    fn debug_does_not_turn_on_the_whole_dependency_tree() {
        let filter = directives("debug");

        assert!(
            filter.starts_with("info"),
            "everything else stays where it was, got {filter}"
        );
        assert!(
            filter.contains("synology_filestation_connect=debug"),
            "and ours go verbose, got {filter}"
        );
        assert!(
            filter.contains("synology_filestation_openvpn=debug"),
            "the tunnel is the thing being diagnosed, got {filter}"
        );
    }

    #[test]
    fn trace_scopes_the_same_way() {
        let filter = directives("trace");

        assert!(filter.starts_with("info"), "got {filter}");
        assert!(
            filter.contains("synology_filestation_openvpn=trace"),
            "got {filter}"
        );
    }

    /// The quiet levels were never the problem, and rewriting them would hide
    /// a dependency's warning — which is the one third-party message anybody
    /// wants.
    #[test]
    fn a_quiet_level_stays_global() {
        assert_eq!(directives("info"), "info");
        assert_eq!(directives("warn"), "warn");
        assert_eq!(directives("error"), "error");
    }

    #[test]
    fn an_unknown_level_is_info_rather_than_silence() {
        assert_eq!(directives("shout"), "info");
        assert_eq!(directives(""), "info");
    }

    /// An escape hatch, matching what the CLI already accepts: anything that
    /// looks like a filter expression is one, and is passed through untouched.
    /// Without it, scoping the levels would take away the only way to ask a
    /// dependency a question.
    #[test]
    fn an_explicit_filter_expression_is_left_alone() {
        let asked = "warn,synology_filestation_openvpn=trace,rustls=debug";

        assert_eq!(directives(asked), asked);
        assert_eq!(directives("hyper=debug"), "hyper=debug");
    }

    /// A directive string that does not parse would leave the subscriber on
    /// whatever it had, silently ignoring the setting.
    #[test]
    fn every_level_produces_something_that_parses() {
        for level in ["error", "warn", "info", "debug", "trace", "nonsense"] {
            assert!(
                tracing_subscriber::EnvFilter::try_new(directives(level)).is_ok(),
                "{level} produced an unparseable filter"
            );
        }
    }
}
