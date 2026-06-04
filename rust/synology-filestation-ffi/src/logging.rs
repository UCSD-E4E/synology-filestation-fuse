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

use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, reload, Registry};

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
static RELOAD: OnceLock<reload::Handle<LevelFilter, Registry>> = OnceLock::new();

fn sink() -> &'static Mutex<Option<Sink>> {
    SINK.get_or_init(|| Mutex::new(None))
}

fn parse_level(level: &str) -> LevelFilter {
    match level.trim().to_ascii_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => LevelFilter::INFO,
    }
}

/// Change the active log verbosity. No-op until the subscriber is installed
/// (the GUI registers a callback at startup, before any connect).
pub fn set_level(level: &str) {
    if let Some(handle) = RELOAD.get() {
        let _ = handle.reload(parse_level(level));
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
        let (filter, handle) = reload::Layer::new(LevelFilter::INFO);
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
