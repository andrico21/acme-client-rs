//! Step 2 (or 3, with `--pre-authorize`) of the `run` flow: order placement.
//!
//! Validates the requested profile against the CA's advertised list, builds
//! the identifier vector, and submits either a fresh `newOrder` or an
//! ARI-driven `newOrder` carrying the `replaces` field.

use anyhow::Result;
use tracing::info;

use crate::client::AcmeClient;
use crate::outln;
use crate::types::{Identifier, Order};

use super::RunContext;

// NOT cancel-safe: new_order / new_order_replacing performs an HTTP
// newOrder request; cancellation can leave an orphan order on the CA side.
pub(super) async fn place(
    ctx: &mut RunContext<'_>,
    client: &mut AcmeClient,
) -> Result<(Order, url::Url)> {
    info!(
        "Step {}: Placing order",
        if ctx.pre_authorize { 3 } else { 2 }
    );

    let profile_owned = ctx.profile.map(String::from);
    // Validate profile against advertised list (draft-ietf-acme-profiles-01 §4)
    if let Some(ref p) = profile_owned
        && let Some(available) = client.available_profiles()
        && !available.contains_key(p)
    {
        tracing::warn!(
            "Profile \"{p}\" is not advertised by the server (available: {})",
            available.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }

    let ids: Vec<Identifier> = ctx
        .domains
        .iter()
        .map(|d| Identifier::from_str_auto(d))
        .collect::<Result<Vec<_>>>()?;

    let (order, order_url) = if let Some(cert_id) = ctx.ari_cert_id.take() {
        info!("Using ARI replaces field (certID: {cert_id})");
        client
            .new_order_replacing(ids, cert_id, profile_owned)
            .await?
    } else {
        client.new_order(ids, profile_owned).await?
    };

    if !ctx.json && !ctx.silent {
        outln!("Order URL:  {order_url}");
        if let Some(ref p) = order.profile {
            outln!("Profile:    {p}");
        }
        outln!("Order status: {}", order.status);
    }

    Ok((order, order_url))
}
