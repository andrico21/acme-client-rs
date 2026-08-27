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

/// Cap for terminal-rendered certificate text (`--print-cert`).
///
/// A Let's Encrypt leaf+intermediate chain is ~3.5 KB, so this is ~300x the
/// largest realistic input; it exists only to bound a hostile CA flooding the
/// operator's terminal or log pipeline.
pub(crate) const MAX_CERT_TEXT: usize = 1024 * 1024;

/// Whether `c` may reach the terminal, given the character that follows it.
///
/// `\r` is permitted **only** as the leading half of a CRLF pair. That keeps
/// CRLF-encoded PEM byte-identical (some CAs emit it, and `openssl` accepts
/// both) while still neutralising a standalone `CR`, which is the character
/// that actually overwrites the line just printed.
fn passes_terminal_policy(c: char, next: Option<char>) -> bool {
    match c {
        '\n' | '\t' => true,
        '\r' => next == Some('\n'),
        _ => !steers_terminal(c),
    }
}

/// `true` if every character in `s` is safe to emit to a terminal.
///
/// The `out!`/`outln!` sink asserts this in debug builds, so an unsanitized
/// sink fails loudly in tests rather than silently reintroducing
/// terminal-escape injection. Debug-only: release enforces nothing here, since
/// the fix belongs at the source sink.
#[cfg(debug_assertions)]
pub(crate) fn is_terminal_safe(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if !passes_terminal_policy(c, chars.peek().copied()) {
            return false;
        }
    }
    true
}

/// Scrub a CA-supplied certificate body for terminal rendering.
///
/// Preserves `\n`, `\t` and CRLF pairs, so any legitimate PEM — LF or CRLF —
/// round-trips byte-identically and still pipes into `openssl x509`. Capped at
/// [`MAX_CERT_TEXT`].
pub(crate) fn untrusted_certificate(cert: &str) -> String {
    let mut out = String::with_capacity(cert.len().min(MAX_CERT_TEXT));
    let mut chars = cert.chars().peekable();
    let mut kept = 0usize;
    while let Some(c) = chars.next() {
        if kept == MAX_CERT_TEXT {
            append_truncation_note(&mut out, cert.len());
            return out;
        }
        out.push(if passes_terminal_policy(c, chars.peek().copied()) {
            c
        } else {
            REPLACEMENT
        });
        kept += 1;
    }
    out
}

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

    // ── --print-cert path ───────────────────────────────────────────────

    fn pem(line_ending: &str) -> String {
        let le = line_ending;
        let body: String = std::iter::repeat_n("MIIFazCCA1OgAwIBAgIRAKc", 60)
            .collect::<Vec<_>>()
            .join(le);
        format!("-----BEGIN CERTIFICATE-----{le}{body}{le}-----END CERTIFICATE-----{le}")
    }

    #[test]
    fn certificate_lf_pem_round_trips_byte_identically() {
        let input = pem("\n");
        assert!(input.len() > 1000, "fixture is a realistic multi-KB chain");
        assert_eq!(untrusted_certificate(&input), input);
    }

    // Some CAs emit CRLF PEM and `openssl` accepts it; a naive scrubber turns
    // each line ending into `·\n` and breaks `--print-cert | openssl x509`.
    #[test]
    fn certificate_crlf_pem_round_trips_byte_identically() {
        let input = pem("\r\n");
        assert!(input.contains("\r\n"));
        assert_eq!(untrusted_certificate(&input), input);
    }

    #[test]
    fn certificate_scrubs_standalone_cr_but_keeps_crlf() {
        let out = untrusted_certificate("keep\r\nkill\rtail");
        assert_eq!(out, format!("keep\r\nkill{REPLACEMENT}tail"));
    }

    #[test]
    fn certificate_neutralises_a_hostile_body() {
        let hostile =
            "-----BEGIN CERTIFICATE-----\n\u{1b}[2JSPOOF\u{7}\r-----END CERTIFICATE-----\n";
        let out = untrusted_certificate(hostile);
        assert!(
            !out.bytes()
                .any(|b| (b < 0x20 && b != b'\n' && b != b'\t') || b == 0x7f),
            "no steering bytes may survive: {out:?}"
        );
        assert!(out.contains("SPOOF"), "printable text preserved");
    }

    #[test]
    fn certificate_caps_a_flood() {
        let flood = "A".repeat(MAX_CERT_TEXT + 10);
        let out = untrusted_certificate(&flood);
        assert!(out.contains("truncated"));
        assert_eq!(out.chars().filter(|c| *c == 'A').count(), MAX_CERT_TEXT);
    }

    #[test]
    fn untrusted_block_at_exact_cap_is_not_truncated() {
        let exact = vec![b'A'; MAX_UNTRUSTED_TEXT];
        let out = untrusted_block(&exact);
        assert!(
            !out.contains("truncated"),
            "exactly the cap must pass through"
        );
        assert_eq!(out.len(), MAX_UNTRUSTED_TEXT);

        let over = vec![b'A'; MAX_UNTRUSTED_TEXT + 1];
        assert!(untrusted_block(&over).contains("truncated"));
    }

    #[test]
    fn certificate_cap_admits_one_mebibyte_and_truncates_beyond() {
        let exact = "A".repeat(1_048_576);
        let out = untrusted_certificate(&exact);
        assert!(!out.contains("truncated"), "1 MiB must pass through intact");
        assert_eq!(out.chars().count(), 1_048_576);

        let over = "A".repeat(1_048_577);
        let out = untrusted_certificate(&over);
        assert!(out.contains("truncated"));
        assert_eq!(out.chars().filter(|c| *c == 'A').count(), 1_048_576);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn terminal_safety_predicate_matches_the_scrubbers() {
        assert!(is_terminal_safe("plain text"));
        assert!(is_terminal_safe("multi\nline\twith tabs"));
        assert!(is_terminal_safe("crlf\r\nis fine"));
        assert!(!is_terminal_safe("bare\rcarriage"));
        assert!(!is_terminal_safe("esc\u{1b}[31m"));
        assert!(!is_terminal_safe("bell\u{7}"));
        assert!(!is_terminal_safe("c1\u{9b}31m"));
        assert!(is_terminal_safe(&untrusted_certificate(
            "hostile\u{1b}\rmix"
        )));
        assert!(is_terminal_safe(&untrusted_inline("hostile\u{1b}\rmix")));
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
