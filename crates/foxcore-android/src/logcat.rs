//! Send core diagnostics to logcat at `warn` and above.
//!
//! Release builds also compile lower levels out. Warn/error records are a privacy
//! surface and must never contain traffic tuples, hostnames, or secrets.

use std::ffi::CString;

/// Android log priority values from `<android/log.h>`.
const ANDROID_LOG_WARN: libc::c_int = 5;
const ANDROID_LOG_ERROR: libc::c_int = 6;

/// Tag distinguishing core records from the app's `FoxholeDiag` records.
const TAG: &str = "FoxCore";

unsafe extern "C" {
    /// `liblog` writer declared directly to avoid another supply-chain dependency.
    fn __android_log_write(
        prio: libc::c_int,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> libc::c_int;
}

struct LogcatLogger;

impl log::Log for LogcatLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let priority = match record.level() {
            log::Level::Error => ANDROID_LOG_ERROR,
            _ => ANDROID_LOG_WARN,
        };
        // Drop interior-NUL messages instead of presenting a truncated diagnostic.
        let Ok(tag) = CString::new(TAG) else { return };
        let Ok(text) = CString::new(record.args().to_string()) else {
            return;
        };
        // SAFETY: both pointers are NUL-terminated and outlive the call, which
        // copies what it needs before returning.
        unsafe {
            __android_log_write(priority, tag.as_ptr(), text.as_ptr());
        }
    }

    fn flush(&self) {}
}

static LOGGER: LogcatLogger = LogcatLogger;

/// Install the process logger idempotently.
pub(crate) fn install() {
    let _ = log::set_logger(&LOGGER);
    // Apply the privacy ceiling even if another logger was installed first.
    log::set_max_level(log::LevelFilter::Warn);
}
