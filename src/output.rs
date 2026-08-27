//! Centralized stdout sink for user-facing output.
//!
//! All user-visible stdout writes in this binary go through `out!` /
//! `outln!`. This lets us forbid `clippy::print_stdout` everywhere except
//! this module — making it impossible to accidentally bypass a future
//! `--quiet` flag, JSON-output mode, or test capture.
//!
//! On a broken pipe (e.g. `acme-client-rs ... | head`) the sink latches a
//! process-global "stdout is dead" flag and every later `out!`/`outln!`
//! becomes a no-op. The ACME flow then runs to completion through its normal
//! success/error paths, so in-flight challenge state is still torn down and
//! the exit status still reflects what actually happened. This replaces an
//! earlier `exit(0)`, which skipped cleanup and reported success for an
//! issuance that never finished. Other write failures are silently swallowed
//! (writing to stdout that cannot be written to has no useful recovery path
//! for a CLI).
//!
//! Use `tracing::{warn, error}` for stderr — this module is stdout-only.

#![allow(clippy::print_stdout)]

#[cfg(test)]
use std::future::Future;
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

/// Latched once stdout returns `BrokenPipe`. Every later write is dropped at
/// the sink instead of retried, and `main` consults it to decide whether a
/// successful run still lost a result the caller explicitly asked for.
static STDOUT_DEAD: AtomicBool = AtomicBool::new(false);

/// `true` once a write has failed with `BrokenPipe` — the reader is gone.
#[must_use]
pub(crate) fn stdout_dead() -> bool {
    STDOUT_DEAD.load(Ordering::Relaxed)
}

/// Internal helper: write to stdout, latching `STDOUT_DEAD` on a broken pipe
/// and ignoring every other error.
///
/// In debug builds this asserts the rendered text is terminal-safe, so a sink
/// that forgets to scrub CA-supplied bytes fails loudly in tests. Under `cfg(test)`
/// a thread-local capture buffer, when installed, receives the text instead of
/// stdout. Release builds outside tests take neither path.
#[doc(hidden)]
pub(crate) fn __write(args: std::fmt::Arguments<'_>, newline: bool) {
    if is_silent() || stdout_dead() {
        return;
    }

    #[cfg(not(any(debug_assertions, test)))]
    write_args(args, newline);

    #[cfg(any(debug_assertions, test))]
    {
        // Rendered once and reused: `Display` impls may have side effects, so
        // formatting twice would not be semantics-preserving.
        let rendered = args.to_string();

        #[cfg(debug_assertions)]
        debug_assert!(
            crate::sanitize::is_terminal_safe(&rendered),
            "terminal-unsafe bytes reached the stdout sink; scrub untrusted \
             text at its source (see crate::sanitize)"
        );

        // Early return, never fall through: a captured write must not also
        // reach the real stdout.
        #[cfg(test)]
        if capture::push(&rendered, newline) {
            return;
        }

        write_rendered(&rendered, newline);
    }
}

#[cfg(any(debug_assertions, test))]
fn write_rendered(rendered: &str, newline: bool) {
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    latch_broken_pipe(if newline {
        writeln!(h, "{rendered}")
    } else {
        write!(h, "{rendered}")
    });
}

#[cfg(not(any(debug_assertions, test)))]
fn write_args(args: std::fmt::Arguments<'_>, newline: bool) {
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    latch_broken_pipe(if newline {
        writeln!(h, "{args}")
    } else {
        write!(h, "{args}")
    });
}

fn latch_broken_pipe(res: std::io::Result<()>) {
    if let Err(e) = res
        && e.kind() == std::io::ErrorKind::BrokenPipe
    {
        STDOUT_DEAD.store(true, Ordering::Relaxed);
    }
}

/// Thread-local redirection of `out!` / `outln!` for tests.
///
/// Thread-local rather than process-global because cargo runs tests on parallel
/// threads and a shared buffer would interleave. The consequence is that output
/// emitted from a `tokio::spawn`ed task is **not** captured — only work driven
/// directly on the calling thread.
#[cfg(test)]
mod capture {
    use std::cell::RefCell;

    thread_local! {
        static BUFFER: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    pub(super) fn install() {
        BUFFER.with(|b| *b.borrow_mut() = Some(String::new()));
    }

    pub(super) fn take() -> String {
        BUFFER.with(|b| b.borrow_mut().take().unwrap_or_default())
    }

    /// Appends when a buffer is installed; reports whether it consumed the write.
    pub(super) fn push(rendered: &str, newline: bool) -> bool {
        BUFFER.with(|b| {
            let mut slot = b.borrow_mut();
            let Some(buf) = slot.as_mut() else {
                return false;
            };
            buf.push_str(rendered);
            if newline {
                buf.push('\n');
            }
            true
        })
    }
}

/// Run `body`, returning its value alongside everything it printed.
#[cfg(test)]
pub(crate) fn capture<T>(body: impl FnOnce() -> T) -> (T, String) {
    capture::install();
    let value = body();
    (value, capture::take())
}

/// Async counterpart of [`capture`].
///
/// `#[tokio::test]` already runs inside a runtime, so a nested `block_on` is
/// not an option; the future is awaited directly on the capturing thread.
#[cfg(test)]
pub(crate) async fn capture_async<F, Fut, T>(body: F) -> (T, String)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    capture::install();
    let value = body().await;
    (value, capture::take())
}

/// Writes a line to stdout unless `--silent` is active or stdout is a closed
/// pipe (e.g. piped to `head`).
#[macro_export]
macro_rules! outln {
    () => {{
        $crate::output::__write(::std::format_args!(""), true);
    }};
    ($($arg:tt)*) => {{
        $crate::output::__write(::std::format_args!($($arg)*), true);
    }};
}

/// Same as [`outln!`] without the trailing newline.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {{
        $crate::output::__write(::std::format_args!($($arg)*), false);
    }};
}

#[cfg(test)]
mod tests {
    use super::{STDOUT_DEAD, is_silent, set_silent, stdout_dead};
    use std::sync::atomic::Ordering;

    #[test]
    fn m7_set_silent_toggles_global_suppression() {
        set_silent(true);
        assert!(is_silent());
        set_silent(false);
        assert!(!is_silent());
    }

    #[test]
    fn w1_stdout_dead_latch_suppresses_writes_without_exiting() {
        assert!(!stdout_dead());
        STDOUT_DEAD.store(true, Ordering::Relaxed);
        assert!(stdout_dead());
        // The whole point of the latch: reaching a write after a broken pipe
        // must return normally instead of terminating the process, so the
        // ACME flow keeps running and its cleanup paths still execute.
        super::__write(format_args!("dropped"), true);
        STDOUT_DEAD.store(false, Ordering::Relaxed);
        assert!(!stdout_dead());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "terminal-unsafe bytes reached the stdout sink")]
    fn e1_guard_rejects_unscrubbed_terminal_escapes() {
        set_silent(false);
        STDOUT_DEAD.store(false, Ordering::Relaxed);
        super::__write(format_args!("\u{1b}[2Jhostile\r"), true);
    }

    #[test]
    fn e1_guard_accepts_legitimate_multiline_and_crlf_output() {
        set_silent(true);
        super::__write(format_args!("plain\nlines\twith tabs"), true);
        super::__write(format_args!("crlf\r\npem\r\n"), false);
        set_silent(false);
    }
}
