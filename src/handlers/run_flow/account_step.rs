//! Step 1 of the `run` flow: account creation / lookup.
//!
//! Builds an `AcmeClient` (or reuses one captured by the renewal phase),
//! parses optional EAB credentials, and registers / looks up the account.

use anyhow::Result;

use crate::client::AcmeClient;
use crate::{build_client, outln};

use super::super::parse_eab;
use super::RunContext;

// NOT cancel-safe: create_account performs an HTTP newAccount request;
// cancellation between the request and the response can leave a partially
// registered account on the CA side.
pub(super) async fn create_or_lookup(ctx: &mut RunContext<'_>) -> Result<AcmeClient> {
    tracing::info!("Step 1: Creating / looking up account");

    let mut client = match ctx.early_client.take() {
        Some(c) => c,
        None => build_client(ctx.cli).await?,
    };
    let contact_list = ctx.contact.take().map(|c| vec![format!("mailto:{c}")]);
    let eab = parse_eab(
        ctx.eab_kid,
        ctx.eab_hmac_key
            .as_ref()
            .map(<secrecy::SecretString as secrecy::ExposeSecret<str>>::expose_secret),
    )?;
    let eab_ref = eab.as_ref().map(|(kid, key)| (kid.as_str(), key));
    let account = client.create_account(contact_list, true, eab_ref).await?;
    if !ctx.json && !ctx.silent {
        outln!("Account status: {}", account.status);
    }

    Ok(client)
}
