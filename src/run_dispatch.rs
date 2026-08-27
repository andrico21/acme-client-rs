//! Dispatch helpers for `main::run`'s multi-argument command arms.
//!
//! Each helper is a thin forwarder that owns the argument marshalling one
//! `Commands` variant needs, keeping `run` a flat one-line-per-arm dispatcher.

use std::path::Path;

use anyhow::Result;
use secrecy::SecretString;

use crate::account_key::resolve_account_key_password;
use crate::cli::{CertKeyAlgorithm, Cli, Commands};
use crate::handlers::{
    cmd_account, cmd_deactivate, cmd_download_cert, cmd_finalize, cmd_generate_config,
    cmd_generate_key, cmd_get_authz, cmd_key_rollover, cmd_list_profiles, cmd_order,
    cmd_poll_order, cmd_pre_authorize, cmd_renewal_info, cmd_respond_challenge, cmd_revoke,
    cmd_serve_http01, cmd_show_dns_persist01, cmd_show_dns01,
};
use crate::jws::KeyAlgorithm;

// NOT cancel-safe: routes to every context-free cmd_*; inherits each one's
// contract. `ShowConfig` and `Run` are handled by `main::run` because they
// need config/matches/cleanup-registry context this router does not carry;
// their arms here are unreachable guards, not a dispatch path.
pub(crate) async fn handle_simple_command(cli: &Cli, command: &Commands) -> Result<()> {
    match command {
        Commands::GenerateConfig => cmd_generate_config(cli.silent),
        Commands::GenerateKey { algorithm, force } => {
            handle_generate_key(cli, *algorithm, *force).await
        }
        Commands::Account {
            contact,
            agree_tos,
            eab_kid,
            eab_hmac_key,
        } => {
            handle_account(
                cli,
                contact,
                *agree_tos,
                eab_kid.as_deref(),
                eab_hmac_key.as_ref(),
            )
            .await
        }
        Commands::Order { domains, profile } => {
            cmd_order(cli, domains.clone(), profile.clone()).await
        }
        Commands::GetAuthz { url } => cmd_get_authz(cli, url).await,
        Commands::RespondChallenge { url } => cmd_respond_challenge(cli, url).await,
        Commands::ServeHttp01 {
            token,
            port,
            challenge_dir,
        } => cmd_serve_http01(cli, token, *port, challenge_dir.as_deref()).await,
        Commands::ShowDns01 { domain, token } => cmd_show_dns01(cli, domain, token).await,
        Commands::ShowDnsPersist01 {
            domain,
            issuer_domain_name,
            persist_policy,
            persist_until,
            agree_tos,
        } => {
            handle_show_dns_persist01(
                cli,
                domain,
                issuer_domain_name,
                persist_policy.as_deref(),
                *persist_until,
                *agree_tos,
            )
            .await
        }
        Commands::Finalize {
            finalize_url,
            cert_key_algorithm,
            key_output,
            key_password,
            key_password_file,
            force,
            domains,
        } => {
            handle_finalize(
                cli,
                FinalizeDispatch {
                    finalize_url,
                    domains: domains.as_slice(),
                    cert_key_algorithm: *cert_key_algorithm,
                    key_output: key_output.as_path(),
                    key_password: key_password.as_ref(),
                    key_password_file: key_password_file.as_deref(),
                    force: *force,
                },
            )
            .await
        }
        Commands::PollOrder { url } => cmd_poll_order(cli, url).await,
        Commands::DownloadCert { url, output } => cmd_download_cert(cli, url, output).await,
        command @ (Commands::DeactivateAccount
        | Commands::KeyRollover { .. }
        | Commands::RevokeCert { .. }
        | Commands::RenewalInfo { .. }
        | Commands::ListProfiles
        | Commands::PreAuthorize { .. }
        | Commands::ShowConfig { .. }
        | Commands::Run(_)) => handle_account_lifecycle_command(cli, command).await,
    }
}

// NOT cancel-safe: routes to account-lifecycle and certificate-maintenance
// commands; inherits each one's contract. Split from `handle_simple_command`
// only to keep both under the 100-line ceiling.
async fn handle_account_lifecycle_command(cli: &Cli, command: &Commands) -> Result<()> {
    match command {
        Commands::DeactivateAccount => cmd_deactivate(cli).await,
        Commands::KeyRollover {
            new_key,
            new_key_password,
            new_key_password_file,
            agree_tos,
        } => {
            handle_key_rollover(
                cli,
                new_key.as_path(),
                new_key_password.as_ref(),
                new_key_password_file.as_deref(),
                *agree_tos,
            )
            .await
        }
        Commands::RevokeCert {
            cert_path,
            reason,
            agree_tos,
        } => cmd_revoke(cli, cert_path, *reason, *agree_tos).await,
        Commands::RenewalInfo { cert_path } => cmd_renewal_info(cli, cert_path).await,
        Commands::ListProfiles => cmd_list_profiles(cli).await,
        Commands::PreAuthorize {
            domain,
            challenge_type,
            agree_tos,
        } => cmd_pre_authorize(cli, domain, challenge_type, *agree_tos).await,
        Commands::ShowConfig { .. } => unexpected_context_command("show-config"),
        Commands::Run(_) => unexpected_context_command("run"),
        Commands::GenerateConfig
        | Commands::GenerateKey { .. }
        | Commands::Account { .. }
        | Commands::Order { .. }
        | Commands::GetAuthz { .. }
        | Commands::RespondChallenge { .. }
        | Commands::ServeHttp01 { .. }
        | Commands::ShowDns01 { .. }
        | Commands::ShowDnsPersist01 { .. }
        | Commands::Finalize { .. }
        | Commands::PollOrder { .. }
        | Commands::DownloadCert { .. } => unexpected_context_command("account-lifecycle dispatch"),
    }
}

fn unexpected_context_command(name: &str) -> Result<()> {
    anyhow::bail!("{name} must be handled by main::run before simple dispatch")
}

// cancel-safe before the final `spawn_blocking` write, NOT cancel-safe once it
// is spawned: the detached blocking task may create the secret file after the
// caller has gone away. Inherits `cmd_generate_key`'s contract verbatim.
pub(crate) async fn handle_generate_key(
    cli: &Cli,
    algorithm: KeyAlgorithm,
    force: bool,
) -> Result<()> {
    let fmt = cli.output_format;
    let pw = resolve_account_key_password(
        cli.account_key_password
            .as_ref()
            .map(secrecy::ExposeSecret::expose_secret),
        cli.account_key_password_file.as_deref(),
    )
    .await?;
    cmd_generate_key(
        &cli.account_key,
        algorithm,
        force,
        fmt,
        cli.silent,
        pw.as_ref(),
    )
    .await
}

// NOT cancel-safe: creates ACME account on CA + EAB binding. Drop after
// POST leaves account registered remotely; caller loses the account URL.
pub(crate) async fn handle_account(
    cli: &Cli,
    contact: &[String],
    agree_tos: bool,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<&SecretString>,
) -> Result<()> {
    cmd_account(
        cli,
        contact.to_vec(),
        agree_tos,
        eab_kid,
        eab_hmac_key.cloned(),
    )
    .await
}

// cancel-safe: prints DNS-PERSIST-01 setup instructions; pure compute + stdout.
pub(crate) async fn handle_show_dns_persist01(
    cli: &Cli,
    domain: &str,
    issuer_domain_name: &str,
    persist_policy: Option<&str>,
    persist_until: Option<u64>,
    agree_tos: bool,
) -> Result<()> {
    cmd_show_dns_persist01(
        cli,
        domain,
        issuer_domain_name,
        persist_policy,
        persist_until,
        agree_tos,
    )
    .await
}

/// Borrowed view of the `Commands::Finalize` fields.
///
/// Exists so [`handle_finalize`] stays within `clippy::too_many_arguments`;
/// `cmd_finalize` itself carries an explicit allow for the same reason.
pub(crate) struct FinalizeDispatch<'a> {
    pub(crate) finalize_url: &'a str,
    pub(crate) domains: &'a [String],
    pub(crate) cert_key_algorithm: CertKeyAlgorithm,
    pub(crate) key_output: &'a Path,
    pub(crate) key_password: Option<&'a SecretString>,
    pub(crate) key_password_file: Option<&'a Path>,
    pub(crate) force: bool,
}

// NOT cancel-safe: generates key off-runtime, submits CSR, writes private
// key to disk. Drop between key-write and CSR submission orphans key file;
// drop between submission and exit means caller loses the order URL.
pub(crate) async fn handle_finalize(cli: &Cli, args: FinalizeDispatch<'_>) -> Result<()> {
    cmd_finalize(
        cli,
        args.finalize_url,
        args.domains,
        args.cert_key_algorithm,
        args.key_output,
        args.key_password.cloned(),
        args.key_password_file,
        args.force,
    )
    .await
}

// NOT cancel-safe: rotates account key on CA. Drop after key-change POST
// but before caller saves the new key reference leaves account using new
// key with no local record.
pub(crate) async fn handle_key_rollover(
    cli: &Cli,
    new_key: &Path,
    new_key_password: Option<&SecretString>,
    new_key_password_file: Option<&Path>,
    agree_tos: bool,
) -> Result<()> {
    cmd_key_rollover(
        cli,
        new_key,
        new_key_password.cloned(),
        new_key_password_file,
        agree_tos,
    )
    .await
}
