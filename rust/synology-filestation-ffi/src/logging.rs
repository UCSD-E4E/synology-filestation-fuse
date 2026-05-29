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

fn sink() -> &'static Mutex<Option<Sink>> {
    SINK.get_or_init(|| Mutex::new(None))
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
        // INFO-and-above by default; the GUI doesn't need DEBUG/TRACE spam in
        // its log pane. (We avoid the `env-filter` feature to keep the cdylib
        // lean — a static max level is all the GUI needs.)
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(|| CallbackWriter)
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
    // The fmt layer prints e.g. "...  INFO synology...: message".
    if line.contains("ERROR") {
        1
    } else if line.contains(" WARN") {
        2
    } else if line.contains(" INFO") {
        3
    } else if line.contains("DEBUG") {
        4
    } else {
        5
    }
}

fn dispatch(line: &str) {
    let guard = match sink().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if let Some(s) = guard.as_ref() {
        if let Ok(c) = CString::new(line) {
            (s.cb)(level_of(line), c.as_ptr(), s.user_data as *mut c_void);
        }
    }
}
