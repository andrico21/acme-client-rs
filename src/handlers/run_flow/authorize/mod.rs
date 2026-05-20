//! Per-domain authorization phase.
//!
//! Drives every authorization on the order to `valid`. Two sub-paths:
//!
//! - **Phased DNS** (used when `--dns-hook` is set with dns-01 / dns-persist-01):
//!   provision all TXT records first, run propagation checks concurrently, then
//!   respond to challenges serially.
//! - **Sequential** (HTTP-01, TLS-ALPN-01, manual DNS): provision + validate
//!   one identifier at a time.

use anyhow::Result;
use tracing::info;

use crate::client::AcmeClient;
use crate::types::{ChallengeToken, ChallengeType, DnsName, Order};

use super::RunContext;

mod phased_dns;
mod provisioners;
mod sequential;

/// Per-domain state carried through the phased-DNS pipeline.
///
/// Lifted out of the original `authorize` fn body so it is reachable from the
/// `phased_dns` submodule. Each instance represents one TXT record that has
/// been created (via the DNS hook) and is awaiting propagation + validation.
pub(super) struct DnsPending {
    pub authz_url: url::Url,
    pub domain: DnsName,
    pub challenge_url: url::Url,
    pub token: Option<ChallengeToken>,
    pub txt_name: DnsName,
    pub txt_value: String,
}

// NOT cancel-safe: thin dispatcher to run_phased_dns / run_sequential.
// Inherits NOT-cancel-safe contract from both pipelines.
pub(super) async fn authorize(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
    order: &Order,
) -> Result<()> {
    info!(
        "Step {}: Completing authorizations",
        if ctx.pre_authorize { 4 } else { 3 }
    );

    // DNS challenges with a hook benefit from parallel propagation waiting:
    // all TXT records are created first, then all propagation checks run
    // concurrently, then challenges are responded to serially (nonce chain).
    let use_parallel_dns = ctx.dns_hook.is_some()
        && (ctx.challenge_type == ChallengeType::Dns01
            || ctx.challenge_type == ChallengeType::DnsPersist01);

    if use_parallel_dns {
        phased_dns::run_phased_dns(ctx, client, order).await
    } else {
        sequential::run_sequential(ctx, client, order).await
    }
}
