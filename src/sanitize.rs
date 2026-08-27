//! Rendering guard for untrusted, CA-supplied text.
//!
//! Everything an ACME server sends us is attacker-controlled from this client's
//! point of view: a compromised or hostile CA (or anything that can MITM a
//! misconfigured `--insecure` deployment) chooses the bytes in `detail` fields,
//! profile descriptions, `explanationURL`, and unknown enum variants. Those
//! strings end up on an operator's terminal, frequently inside a `sudo` cron
//! job whose output is piped into a log.
//!
//! Raw control bytes there are not cosmetic. `CR` overwrites the line that was
//! just printed, `ESC [` drives the terminal's escape parser, and an unbounded
//! field turns one HTTP response into megabytes of log. This module is the single
//! place that neutralises all three.
//!
//! Two modes, because the safe answer differs by context:
//!
//! - [`untrusted_inline`] — for a value rendered *inside* one line
//!   (`  {name}: {description}`). Newlines and tabs are scrubbed too, so a CA
//!   cannot forge extra output lines or fake column alignment.
//! - [`untrusted_block`] — for a raw HTTP body rendered as its own block. `\n`
//!   and `\t` survive because the body legitimately is multi-line; everything
//!   else is scrubbed.
//!
//! Both cap their output. Neither is a substitute for validating a value that has
//! a grammar — where a grammar exists (`DnsName`, `ChallengeToken`,
//! `validate_issuer_domain_name`) the value is rejected at the parse boundary
//! instead, and never reaches this module.

use std::fmt::Write as _;

/// Maximum number of characters (for [`untrusted_inline`]) or bytes (for
/// [`untrusted_block`]) rendered from an untrusted value before truncation.
pub(crate) const MAX_UNTRUSTED_TEXT: usize = 1024;

/// Stand-in for a character that must not reach the terminal verbatim.
const REPLACEMENT: char = '·';

/// Whether `\n` and `\t` are meaningful in the destination context.
///
/// An enum rather than a `bool` parameter so the two call sites read as
/// `Whitespace::Preserve` / `Whitespace::Scrub` instead of `true` / `false`
/// (`RUST_GUIDELINES` §3).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Whitespace {
    /// Keep `\n` / `\t` — the destination renders a multi-line block.
    Preserve,
    /// Scrub `\n` / `\t` as well — the destination is a single line.
    Scrub,
}

/// `true` for characters that can steer a terminal rather than print on it.
///
/// [`char::is_control`] is Unicode category `Cc`, which covers **both** C0
/// (`U+0000`–`U+001F`, `U+007F`) and C1 (`U+0080`–`U+009F`). C1 matters: `U+009B`
/// is a single-character CSI introducer, so screening only the C0 range would
/// leave a working escape-sequence path open. `U+2028` / `U+2029` are added
/// because they are line/paragraph separators that some terminals and most log
/// viewers honour.
fn steers_terminal(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

fn scrub_char(c: char, whitespace: Whitespace) -> char {
    if whitespace == Whitespace::Preserve && matches!(c, '\n' | '\t') {
        return c;
    }
    if steers_terminal(c) { REPLACEMENT } else { c }
}

fn append_truncation_note(out: &mut String, total_bytes: usize) {
    // Deliberately ignores the `fmt::Result`: writing to a `String` is
    // infallible, and this runs on an error-reporting path that must not
    // itself fail.
    let _ = write!(out, "… [truncated, {total_bytes} bytes total]");
}

/// Scrub every terminal-steering character (including `\n` and `\t`) and cap the
/// result at [`MAX_UNTRUSTED_TEXT`] characters.
///
/// Use for any untrusted value rendered inside a single output line. Capping is
/// by `char`, not byte, so the result is never a split UTF-8 sequence.
pub(crate) fn untrusted_inline(s: &str) -> String {
    let mut chars = s.chars();
    let mut out: String = chars
        .by_ref()
        .take(MAX_UNTRUSTED_TEXT)
        .map(|c| scrub_char(c, Whitespace::Scrub))
        .collect();
    // The iterator has been advanced exactly `MAX_UNTRUSTED_TEXT` times (or
    // fewer); anything left means we truncated.
    if chars.next().is_some() {
        append_truncation_note(&mut out, s.len());
    }
    out
}

/// Scrub terminal-steering characters from a raw byte body, preserving `\n` and
/// `\t`, and cap the result at [`MAX_UNTRUSTED_TEXT`] bytes.
///
/// Use for an HTTP response body surfaced in an error message. Invalid UTF-8 is
/// replaced lossily rather than rejected — the point is to report what happened,
/// not to parse it.
pub(crate) fn untrusted_block(body: &[u8]) -> String {
    let slice = body.get(..MAX_UNTRUSTED_TEXT).unwrap_or(body);
    let lossy = String::from_utf8_lossy(slice);
    let mut out: String = lossy
        .chars()
        .map(|c| scrub_char(c, Whitespace::Preserve))
        .collect();
    if body.len() > MAX_UNTRUSTED_TEXT {
        append_truncation_note(&mut out, body.len());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── untrusted_block: behaviour moved verbatim from the former
    //    `client::http_transport::truncate_for_log` (SEC-15) ──────────────────

    #[test]
    fn untrusted_block_caps_oversize_bodies() {
        let big = vec![b'A'; MAX_UNTRUSTED_TEXT + 500];
        let out = untrusted_block(&big);
        assert!(out.contains("truncated"));
        assert!(out.contains(&format!("{} bytes total", MAX_UNTRUSTED_TEXT + 500)));
        assert!(out.len() < MAX_UNTRUSTED_TEXT + 100);
    }

    #[test]
    fn untrusted_block_replaces_control_chars_but_keeps_newline_tab() {
        let body = b"line1\nline2\r\x1b[31mred\x1b[0m\tend\x07\x00bell";
        let out = untrusted_block(body);
        assert!(out.contains("line1\nline2"), "newline preserved: {out:?}");
        assert!(out.contains("\tend"), "tab preserved: {out:?}");
        assert!(!out.contains('\r'), "CR replaced: {out:?}");
        assert!(!out.contains('\x1b'), "ESC replaced: {out:?}");
        assert!(!out.contains('\x07'), "BEL replaced: {out:?}");
        assert!(!out.contains('\x00'), "NUL replaced: {out:?}");
        assert!(
            out.contains(REPLACEMENT),
            "replacement char present: {out:?}"
        );
    }

    #[test]
    fn untrusted_block_handles_invalid_utf8() {
        let body = b"valid\xff\xfeend";
        let out = untrusted_block(body);
        assert!(out.contains("valid"));
        assert!(out.contains("end"));
    }

    // ── untrusted_inline ────────────────────────────────────────────────────

    #[test]
    fn untrusted_inline_scrubs_newline_and_tab_too() {
        let out = untrusted_inline("a\nb\tc");
        assert!(!out.contains('\n'), "inline must not keep newline: {out:?}");
        assert!(!out.contains('\t'), "inline must not keep tab: {out:?}");
        assert_eq!(out, format!("a{REPLACEMENT}b{REPLACEMENT}c"));
    }

    #[test]
    fn untrusted_inline_neutralises_the_e1_payload() {
        // Exactly the payload that reached a real terminal in the audit repro.
        let out = untrusted_inline("\u{1b}[2J\u{1b}[31mSPOOFED\u{1b}[0m\rOVERWRITE\u{7}");
        assert!(
            !out.bytes().any(|b| b < 0x20 || b == 0x7f),
            "no C0 control bytes may survive: {out:?}"
        );
        assert!(
            out.contains("SPOOFED"),
            "printable text is preserved: {out:?}"
        );
    }

    #[test]
    fn untrusted_inline_scrubs_c1_csi_introducer() {
        // U+009B is a single-character CSI. Screening only C0 would miss it.
        let out = untrusted_inline("before\u{9b}31mafter");
        assert!(!out.contains('\u{9b}'), "C1 CSI must be scrubbed: {out:?}");
    }

    #[test]
    fn untrusted_inline_scrubs_unicode_line_separators() {
        let out = untrusted_inline("a\u{2028}b\u{2029}c");
        assert!(!out.contains('\u{2028}'));
        assert!(!out.contains('\u{2029}'));
    }

    #[test]
    fn untrusted_inline_is_identity_for_printable_ascii() {
        let s = "letsencrypt.org; accounturi=https://acme.example/acct/1 (tlsserver)";
        assert_eq!(untrusted_inline(s), s);
    }

    #[test]
    fn untrusted_inline_caps_and_reports_byte_total() {
        let long = "A".repeat(MAX_UNTRUSTED_TEXT + 500);
        let out = untrusted_inline(&long);
        assert!(out.contains("truncated"));
        assert!(out.contains(&format!("{} bytes total", MAX_UNTRUSTED_TEXT + 500)));
        assert!(
            out.chars().filter(|c| *c == 'A').count() == MAX_UNTRUSTED_TEXT,
            "exactly the cap is kept"
        );
    }

    #[test]
    fn untrusted_inline_cap_never_splits_a_utf8_char() {
        // Multi-byte characters, more than the cap. Capping by char (not byte)
        // must still produce well-formed UTF-8.
        let long = "é".repeat(MAX_UNTRUSTED_TEXT + 10);
        let out = untrusted_inline(&long);
        assert!(out.contains("truncated"));
        assert_eq!(
            out.chars().filter(|c| *c == 'é').count(),
            MAX_UNTRUSTED_TEXT
        );
    }

    #[test]
    fn untrusted_inline_at_exact_cap_is_not_truncated() {
        let exact = "A".repeat(MAX_UNTRUSTED_TEXT);
        let out = untrusted_inline(&exact);
        assert_eq!(out, exact);
        assert!(!out.contains("truncated"));
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert_eq!(untrusted_inline(""), "");
        assert_eq!(untrusted_block(b""), "");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Arbitrary `String` including control characters, which the default `.*`
    /// regex strategy never produces.
    fn arb_string() -> impl Strategy<Value = String> {
        proptest::collection::vec(any::<char>(), 0..200).prop_map(|v| v.into_iter().collect())
    }

    proptest! {
        #[test]
        fn inline_never_emits_a_terminal_steering_char(s in arb_string()) {
            prop_assert!(!untrusted_inline(&s).chars().any(steers_terminal));
        }

        #[test]
        fn block_keeps_only_newline_and_tab(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let out = untrusted_block(&bytes);
            prop_assert!(
                out.chars().all(|c| !steers_terminal(c) || c == '\n' || c == '\t')
            );
        }

        #[test]
        fn inline_is_identity_for_printable_ascii(s in "[ -~]{0,1024}") {
            prop_assert_eq!(untrusted_inline(&s), s);
        }

        #[test]
        fn inline_output_length_is_bounded(s in arb_string()) {
            let out = untrusted_inline(&s);
            prop_assert!(out.chars().count() <= MAX_UNTRUSTED_TEXT + 64);
        }
    }
}
