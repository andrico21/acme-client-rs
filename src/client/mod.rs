//! ACME HTTP client - drives the full RFC 8555 protocol flow.
//!
//! # Module layout
//!
//! - [`net_policy`] — `TlsPolicy`, `NetworkPolicy`, IP classification
//! - [`url_validation`] — synchronous URL + identifier validators
//! - [`http_transport`] — SSRF-safe DNS resolver, HTTP client builder,
//!   `AcmeResponse` wrapper
//! - [`acme`] — `AcmeClient` (the RFC 8555 driver) + `compute_cert_id`
//!
//! # SSRF defenses
//!
//! Two complementary checks guard every URL we follow:
//!
//!   1. [`url_validation::validate_acme_url`] — synchronous scheme + literal-IP
//!      check applied at every URL ingress (CLI args, server-returned URLs in
//!      Directory/Order/Authorization). Cheap, no I/O, catches `file://`,
//!      `data:`, embedded IPv4/IPv6 literals in private/loopback ranges.
//!
//!   2. [`http_transport::SsrfSafeResolver`] — wraps the system DNS resolver
//!      inside the reqwest `Client`. Catches DNS-rebinding and the case where
//!      a hostname resolves to a private IP. This is the layer that matters
//!      for `corp.local`-style names that bypass the synchronous check.
//!
//! Both layers respect `--allow-private-network` (and `--insecure`, which
//! implies it). Default: BLOCK.

mod acme;
mod http_transport;
mod net_policy;
mod url_validation;

pub use acme::{AcmeClient, compute_cert_id};
pub use http_transport::build_http_client;
pub use net_policy::{NetFlags, policies_from_cli_flags};
pub use url_validation::{
    validate_account_uri, validate_acme_url, validate_caa_parameter_value, validate_directory_url,
    validate_issuer_domain_name,
};
