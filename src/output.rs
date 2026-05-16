//! Centralized stdout sink for user-facing output.
//!
//! All user-visible stdout writes in this binary go through `out!` /
//! `outln!`. This lets us forbid `clippy::print_stdout` everywhere except
//! this module — making it impossible to accidentally bypass a future
//! `--quiet` flag, JSON-output mode, or test capture.
//!
//! Behavior is intentionally identical to `print!` / `println!`: writes
//! go to `std::io::stdout()`, panicking on failure (matching the standard
//! macros' behavior — a broken pipe is the only realistic failure mode
//! and the standard macros also panic on it under `-Z print-on-broken-pipe`
//! or when the SIGPIPE default is suppressed).
//!
//! Use `eprintln!` directly for stderr (logging goes through `tracing`
//! anyway; this module is stdout-only).

#![allow(clippy::print_stdout)]

#[macro_export]
macro_rules! outln {
    () => {{
        use std::io::Write as _;
        let stdout = std::io::stdout();
        let mut h = stdout.lock();
        writeln!(h).expect("stdout write failed");
    }};
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let stdout = std::io::stdout();
        let mut h = stdout.lock();
        writeln!(h, $($arg)*).expect("stdout write failed");
    }};
}

#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let stdout = std::io::stdout();
        let mut h = stdout.lock();
        write!(h, $($arg)*).expect("stdout write failed");
    }};
}
