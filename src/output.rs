//! Centralized stdout sink for user-facing output.
//!
//! All user-visible stdout writes in this binary go through `out!` /
//! `outln!`. This lets us forbid `clippy::print_stdout` everywhere except
//! this module — making it impossible to accidentally bypass a future
//! `--quiet` flag, JSON-output mode, or test capture.
//!
//! On a broken pipe (e.g. `acme-client-rs ... | head`) the process exits
//! cleanly with code 0. This is a deliberate policy choice — closing the
//! reader is normal in shell pipelines, not an error — and differs from the
//! POSIX SIGPIPE default (exit 128+13=141), which Rust suppresses on stdout
//! anyway. Other write failures are also silently swallowed (writing to
//! stdout that cannot be written to has no useful recovery path for a CLI).
//!
//! Use `tracing::{warn, error}` for stderr — this module is stdout-only.

#![allow(clippy::print_stdout)]

use std::sync::atomic::{AtomicBool, Ordering};

/// Process-global suppression flag for all user-facing stdout.
///
/// Set once from `--silent` after the CLI/config merge. When true, every
/// `out!`/`outln!` write is dropped at the sink, so `--silent` cannot be
/// defeated by a call site that forgets a per-message guard — including JSON
/// result output. stderr (`tracing`) is unaffected.
static SILENT: AtomicBool = AtomicBool::new(false);

/// Enable/disable global stdout suppression. Call once after merging config.
pub(crate) fn set_silent(silent: bool) {
    SILENT.store(silent, Ordering::Relaxed);
}

#[must_use]
pub(crate) fn is_silent() -> bool {
    SILENT.load(Ordering::Relaxed)
}

/// Internal helper: write to stdout, exit(0) on broken pipe, ignore other errors.
#[doc(hidden)]
pub(crate) fn __write_or_exit(args: std::fmt::Arguments<'_>, newline: bool) {
    use std::io::Write as _;
    if is_silent() {
        return;
    }
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    let res = if newline {
        writeln!(h, "{args}")
    } else {
        write!(h, "{args}")
    };
    if let Err(e) = res
        && e.kind() == std::io::ErrorKind::BrokenPipe
    {
        std::process::exit(0);
    }
}

/// Writes a line to stdout unless `--silent` is active; exits 0 when stdout
/// is a closed pipe (e.g. piped to `head`).
#[macro_export]
macro_rules! outln {
    () => {{
        $crate::output::__write_or_exit(::std::format_args!(""), true);
    }};
    ($($arg:tt)*) => {{
        $crate::output::__write_or_exit(::std::format_args!($($arg)*), true);
    }};
}

/// Same as [`outln!`] without the trailing newline.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {{
        $crate::output::__write_or_exit(::std::format_args!($($arg)*), false);
    }};
}

#[cfg(test)]
mod tests {
    use super::{is_silent, set_silent};

    #[test]
    fn m7_set_silent_toggles_global_suppression() {
        set_silent(true);
        assert!(is_silent());
        set_silent(false);
        assert!(!is_silent());
    }
}
