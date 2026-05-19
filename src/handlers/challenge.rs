//! Challenge-helper subcommands (serve-http01, show-dns01, show-dns-persist01, pre-authorize).

use anyhow::{Context, Result};

use crate::account_key::{load_account_key_with_password, resolve_account_key_password};
use crate::cli::{Cli, OutputFormat};
use crate::types::Identifier;
use crate::{build_client, outln};

use super::check_wildcard_compatible;
pub(crate) async fn cmd_serve_http01(
    cli: &Cli,
    token: &crate::types::ChallengeToken,
    port: u16,
    challenge_dir: Option<&std::path::Path>,
    fmt: OutputFormat,
    silent: bool,
) -> Result<()> {
    use secrecy::ExposeSecret;
    let pw = resolve_account_key_password(
        cli.account_key_password.as_deref(),
        cli.account_key_password_file.as_deref(),
    )?;
    let key =
        load_account_key_with_password(&cli.account_key, pw.as_ref().map(|s| s.expose_secret()))?;
    if let Some(dir) = challenge_dir {
        let file = crate::challenge::http01::write_challenge_file(dir, token, &key)?;
        if !silent {
            if fmt == OutputFormat::Json {
                outln!(
                    "{}",
                    serde_json::json!({
                        "command": "serve-http01",
                        "mode": "challenge-dir",
                        "path": file.display().to_string(),
                    })
                );
            } else {
                outln!("Challenge file written to {}", file.display());
            }
            outln!("Press Enter after validation to clean up...");
            let _ = std::io::stdin().read_line(&mut String::new());
        }
        crate::challenge::http01::cleanup_challenge_file(&file);
        Ok(())
    } else {
        crate::challenge::http01::serve(token, &key, port).await
    }
}

pub(crate) fn cmd_show_dns01(
    cli: &Cli,
    domain: &str,
    token: &crate::types::ChallengeToken,
    fmt: OutputFormat,
    silent: bool,
) -> Result<()> {
    use secrecy::ExposeSecret;
    let domain = crate::types::DnsName::parse(domain).context("invalid --domain for show-dns01")?;
    let pw = resolve_account_key_password(
        cli.account_key_password.as_deref(),
        cli.account_key_password_file.as_deref(),
    )?;
    let key =
        load_account_key_with_password(&cli.account_key, pw.as_ref().map(|s| s.expose_secret()))?;
    if !silent {
        if fmt == OutputFormat::Json {
            let name = crate::challenge::dns01::record_name(&domain);
            let value = crate::challenge::dns01::txt_record_value(token, &key);
            outln!(
                "{}",
                serde_json::json!({
                    "command": "show-dns01",
                    "domain": domain,
                    "record_name": name,
                    "record_type": "TXT",
                    "record_value": value,
                })
            );
        } else {
            crate::challenge::dns01::print_instructions(&domain, token, &key);
        }
    }
    Ok(())
}

pub(crate) async fn cmd_show_dns_persist01(
    cli: &Cli,
    domain: &str,
    issuer_domain_name: &str,
    persist_policy: Option<&str>,
    persist_until: Option<u64>,
    fmt: OutputFormat,
) -> Result<()> {
    let domain =
        crate::types::DnsName::parse(domain).context("invalid --domain for show-dns-persist01")?;
    let _issuer_check = crate::client::validate_issuer_domain_name(issuer_domain_name)
        .context("invalid --issuer-domain-name for show-dns-persist01")?;
    if let Some(p) = persist_policy {
        crate::client::validate_caa_parameter_value(p)
            .context("invalid --persist-policy for show-dns-persist01")?;
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

    let name = crate::challenge::dns_persist01::record_name(&domain);
    let value = crate::challenge::dns_persist01::txt_record_value(
        issuer_domain_name,
        &account_uri,
        persist_policy,
        persist_until,
    )?;

    if !cli.silent {
        if fmt == OutputFormat::Json {
            outln!(
                "{}",
                serde_json::json!({
                    "command": "show-dns-persist01",
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
                        let key_auth = crate::challenge::key_authorization(t, client.account_key());
                        outln!("  Key authorization: {key_auth}");
                    }
                }
            }
        },
    );
    Ok(())
}
