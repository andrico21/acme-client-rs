//! Pre-flight validation and side-effects for the `run` subcommand.
//!
//! Runs *before* `RunContext` is built. Validates hooks, optionally
//! auto-generates the account key on first use (`--generate-account-key-if-missing`),
//! and refuses to start fresh issuance when `--key-output` already points at
//! a file but neither `--reuse-key` nor `--force` is set.
//!
//! Wildcard / challenge-type compatibility is checked by the caller *before*
//! invoking this module so that wildcard rejection happens before any
//! side-effect (e.g. account-key file creation).

use anyhow::{Context, Result};
use tracing::info;

use crate::cli::{Cli, RunArgs};
use crate::handlers::account::cmd_generate_key;

// NOT cancel-safe: writes account-key file via cmd_generate_key.
pub(super) async fn run(cli: &Cli, args: &RunArgs) -> Result<()> {
    crate::hook_check::validate_all_hooks(
        &[
            ("dns_hook", args.dns_hook.as_deref()),
            ("on_challenge_ready", args.on_challenge_ready.as_deref()),
            ("on_cert_issued", args.on_cert_issued.as_deref()),
        ],
        cli.unsafe_hooks,
    )?;

    if args.generate_account_key_if_missing && !cli.account_key.exists() {
        info!(
            "--generate-account-key-if-missing set and {} does not exist: generating {} account key",
            cli.account_key.display(),
            args.account_key_algorithm,
        );
        cmd_generate_key(
            &cli.account_key,
            args.account_key_algorithm,
            false,
            cli.output_format,
            cli.silent,
            cli.account_key_password.as_ref(),
        )
        .await
        .context("failed to auto-generate account key")?;
    }

    // Pre-flight: on fresh issuance (no existing cert), refuse to start
    // when --key-output already points at a file but neither --reuse-key
    // nor --force is set. Catches the footgun where the CA issues a cert
    // and then fs_secure rejects the key write, orphaning the cert.
    // Renewal paths (cert_output exists) bypass this: renewal::check may
    // decide Skip (no write), and Renew/Reissue inherently overwrite the
    // existing keypair by user intent.
    if !args.force
        && args.reuse_key.is_none()
        && !args.cert_output.exists()
        && args.key_output.exists()
    {
        anyhow::bail!(
            "private key already exists at {} but no certificate found at {}: \
             pass --reuse-key {} to reuse the key, or --force to overwrite",
            args.key_output.display(),
            args.cert_output.display(),
            args.key_output.display(),
        );
    }

    Ok(())
}
