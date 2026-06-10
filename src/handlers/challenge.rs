//! Challenge-helper subcommands (serve-http-01, show-dns-01, show-dns-persist-01, pre-authorize).

use anyhow::{Context, Result};

use crate::account_key::{load_account_key_with_password, resolve_account_key_password};
use crate::cli::Cli;
use crate::types::Identifier;
use crate::{build_client, outln};

use super::check_wildcard_compatible;
// NOT cancel-safe: binds TCP listener and serves a single challenge
// response, or writes a challenge file via a detached `spawn_blocking`
// task. Drop releases the listener (CA poll will then fail), and a drop
// between the write `spawn_blocking` await and the cleanup leaves the
// challenge file on disk.
pub(crate) async fn cmd_serve_http01(
    cli: &Cli,
    token: &crate::types::ChallengeToken,
    port: u16,
    challenge_dir: Option<&std::path::Path>,
) -> Result<()> {
    let pw = resolve_account_key_password(
        cli.account_key_password
            .as_ref()
            .map(secrecy::ExposeSecret::expose_secret),
        cli.account_key_password_file.as_deref(),
    )
    .await?;
    let key = load_account_key_with_password(
        &cli.account_key,
        pw.as_ref().map(secrecy::ExposeSecret::expose_secret),
    )
    .await?;
    if let Some(dir) = challenge_dir {
        let dir_owned = dir.to_path_buf();
        let token_owned = token.clone();
        let file = tokio::task::spawn_blocking(move || {
            crate::challenge::http01::write_challenge_file(&dir_owned, &token_owned, &key)
        })
        .await
        .context("write_challenge_file task panicked")??;
        super::emit_result(
            cli,
            || {
                serde_json::json!({
                    "command": "serve-http-01",
                    "mode": "challenge-dir",
                    "path": file.display().to_string(),
                })
            },
            || outln!("Challenge file written to {}", file.display()),
        );
        // Keep serving until shutdown regardless of --silent: the challenge
        // file must outlive the wait or the CA cannot validate. Gate only the
        // interactive prompt on output suppression.
        if crate::output::is_silent() {
            let _ = tokio::signal::ctrl_c().await;
        } else {
            outln!("Press Enter after validation to clean up...");
            let _ = tokio::task::spawn_blocking(|| std::io::stdin().read_line(&mut String::new()))
                .await;
        }
        let file_for_cleanup = file.clone();
        let _ = tokio::task::spawn_blocking(move || {
            crate::challenge::http01::cleanup_challenge_file(&file_for_cleanup);
        })
        .await;
        Ok(())
    } else {
        crate::challenge::http01::serve(token, &key, port).await
    }
}

// cancel-safe: prints DNS-01 setup instructions; pure compute + stdout.
pub(crate) async fn cmd_show_dns01(
    cli: &Cli,
    domain: &str,
    token: &crate::types::ChallengeToken,
) -> Result<()> {
    let domain =
        crate::types::DnsName::parse(domain).context("invalid --domain for show-dns-01")?;
    let pw = resolve_account_key_password(
        cli.account_key_password
            .as_ref()
            .map(secrecy::ExposeSecret::expose_secret),
        cli.account_key_password_file.as_deref(),
    )
    .await?;
    let key = load_account_key_with_password(
        &cli.account_key,
        pw.as_ref().map(secrecy::ExposeSecret::expose_secret),
    )
    .await?;
    let name = crate::challenge::dns01::record_name(&domain)?;
    let value = crate::challenge::dns01::txt_record_value(token, &key)?;
    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "show-dns-01",
                "domain": domain,
                "record_name": name,
                "record_type": "TXT",
                "record_value": value,
            })
        },
        || {
            crate::outln!();
            crate::outln!("=== DNS-01 Challenge ===");
            crate::outln!("Create a DNS TXT record:");
            crate::outln!("  Name:  {name}");
            crate::outln!("  Type:  TXT");
            crate::outln!("  Value: {value}");
            crate::outln!();
        },
    );
    Ok(())
}

// cancel-safe: prints DNS-PERSIST-01 setup instructions; pure compute + stdout.
pub(crate) async fn cmd_show_dns_persist01(
    cli: &Cli,
    domain: &str,
    issuer_domain_name: &str,
    persist_policy: Option<&str>,
    persist_until: Option<u64>,
) -> Result<()> {
    use crate::cli::OutputFormat;

    let domain =
        crate::types::DnsName::parse(domain).context("invalid --domain for show-dns-persist-01")?;
    let _issuer_check = crate::client::validate_issuer_domain_name(issuer_domain_name)
        .context("invalid --issuer-domain-name for show-dns-persist-01")?;
    if let Some(p) = persist_policy {
        crate::client::validate_caa_parameter_value(p)
            .context("invalid --persist-policy for show-dns-persist-01")?;
    }
    let mut client = build_client(cli).await?;

    // Need account URL for the accounturi parameter
    if client.account_url().is_none() {
        client.create_account(None, true, None).await?;
    }
    let account_uri = client
        .account_url()
        .context("account URL not known")?
        .to_string();

    let name = crate::challenge::dns_persist01::record_name(&domain)?;
    let value = crate::challenge::dns_persist01::txt_record_value(
        issuer_domain_name,
        &account_uri,
        persist_policy,
        persist_until,
    )?;

    if !cli.silent {
        if cli.output_format == OutputFormat::Json {
            outln!(
                "{}",
                serde_json::json!({
                    "command": "show-dns-persist-01",
                    "domain": domain,
                    "record_name": name,
                    "record_type": "TXT",
                    "record_value": value,
                    "issuer_domain_name": issuer_domain_name,
                    "account_uri": account_uri,
                    "persist_policy": persist_policy,
                    "persist_until": persist_until,
                })
            );
        } else {
            let issuer_names = vec![issuer_domain_name.to_string()];
            crate::challenge::dns_persist01::print_instructions(
                &domain,
                &issuer_names,
                &account_uri,
                persist_policy,
                persist_until,
            )?;
        }
    }
    Ok(())
}

// NOT cancel-safe: creates newAuthz on CA. Drop after POST cannot undo.
pub(crate) async fn cmd_pre_authorize(cli: &Cli, domain: &str, challenge_type: &str) -> Result<()> {
    let challenge_type = crate::types::ChallengeType::parse_strict(challenge_type)?;
    check_wildcard_compatible(&[domain], &challenge_type)?;
    let identifier = Identifier::from_str_auto(domain)?;

    let mut client = build_client(cli).await?;

    // Pre-authorization requires KID signing; look up account if URL not provided
    if client.account_url().is_none() {
        client.create_account(None, true, None).await?;
    }

    let (authz, authz_url) = client.new_authorization(identifier).await?;

    // Pre-compute key authorizations for any matching challenge tokens so the
    // text closure stays infallible.
    let key_auths: Vec<(String, String)> = authz
        .challenges
        .iter()
        .filter(|ch| ch.challenge_type == challenge_type)
        .filter_map(|ch| ch.token.as_ref().map(|t| (t.to_string(), t.clone())))
        .map(|(s, t)| {
            crate::challenge::key_authorization(&t, client.account_key()).map(|ka| (s, ka))
        })
        .collect::<Result<_>>()?;

    super::emit_result(
        cli,
        || {
            serde_json::json!({
                "command": "pre-authorize",
                "identifier": authz.identifier.value_str(),
                "identifier_type": authz.identifier.type_str(),
                "status": format!("{}", authz.status),
                "authz_url": authz_url,
                "challenges": authz.challenges.iter().map(|ch| serde_json::json!({
                    "type": ch.challenge_type,
                    "status": format!("{}", ch.status),
                    "url": ch.url,
                    "token": ch.token,
                })).collect::<Vec<_>>(),
            })
        },
        || {
            outln!("Authorization URL: {authz_url}");
            outln!(
                "Identifier:  {} ({})",
                authz.identifier.value_str(),
                authz.identifier.type_str()
            );
            outln!("Status:      {}", authz.status);
            for ch in &authz.challenges {
                if ch.challenge_type == challenge_type {
                    outln!("Challenge ({}):", ch.challenge_type);
                    outln!("  URL:   {}", ch.url);
                    outln!("  Status: {}", ch.status);
                    if let Some(ref t) = ch.token {
                        outln!("  Token: {t}");
                        if let Some((_, key_auth)) =
                            key_auths.iter().find(|(tok, _)| tok == t.as_str())
                        {
                            outln!("  Key authorization: {key_auth}");
                        }
                    }
                }
            }
        },
    );
    Ok(())
}
