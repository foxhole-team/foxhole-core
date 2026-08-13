//! Send the core's own `log` records to logcat, at `warn` and above only.
//!
//! # Why this did not exist, and why it has to
//!
//! `foxcore-tun` has 61 `log::` call sites, one of which is the documented
//! answer to a whole class of silent failures: a persistent tun read error used
//! to stop packets arriving forever while every counter the app can see still
//! read healthy, and the fix was to count it and say so. It was never said. The
//! `log` facade discards every record when no logger is installed, and none
//! ever was — so the core shipped 61 diagnostics that could not be read, on a
//! device, by anyone, including their author.
//!
//! # Why only warn and above
//!
//! Because of what the other records contain. Forty-nine of the sixty-one are
//! `debug` or `trace`, and they interpolate `NetworkTuple` — the source and
//! destination address and port of the user's traffic — once per packet or per
//! session. Installing a logger without a ceiling would turn a privacy VPN into
//! something that writes its user's connection list to a system log.
//!
//! The ceiling is enforced twice, deliberately. `log`'s `release_max_level_warn`
//! feature compiles `debug` and `trace` out of the release artifact entirely, so
//! the records do not exist to be leaked; [`install`] then also sets the runtime
//! filter, which covers debug builds and anything the feature resolution might
//! change underneath us. One of those alone is a promise; both is a property.
//!
//! Records at `warn` and above no longer carry addresses either — see
//! `ipstack::redacted`, which replaced the tuple with a per-process salted hash
//! so two lines about one flow still match each other and nothing else.

use std::ffi::CString;

/// Android log priority values from `<android/log.h>`.
const ANDROID_LOG_WARN: libc::c_int = 5;
const ANDROID_LOG_ERROR: libc::c_int = 6;

/// The tag every record from the core carries.
///
/// Distinct from the app's own `FoxholeDiag` so a reader can tell which side of
/// the JNI boundary a line came from without parsing it.
const TAG: &str = "FoxCore";

unsafe extern "C" {
    /// `liblog`'s writer. Declared rather than pulled in through a crate: the
    /// whole point of this module is a few lines of diagnostics, and a logging
    /// dependency would be a larger addition to a supply chain that is part of
    /// this product's threat model than the thing it delivers.
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
        // A record whose text cannot be represented as a C string is dropped
        // rather than truncated at the NUL: a diagnostic that silently loses its
        // tail is worse than a missing one, because it still looks complete.
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

/// Install the logger once for the process.
///
/// Idempotent and infallible by design: this is called from every entry point
/// that can be the first one, and a second call returning an error is not a
/// reason to fail a start. If some other logger got there first — a test
/// harness, a host binary — it keeps the field and this does nothing.
pub(crate) fn install() {
    let _ = log::set_logger(&LOGGER);
    // Set unconditionally rather than only on success: if another logger is
    // already installed, the ceiling still has to apply to it, because the
    // records this crate is worried about come from `foxcore-tun` either way.
    log::set_max_level(log::LevelFilter::Warn);
}
