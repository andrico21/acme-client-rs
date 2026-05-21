use anyhow::{Context, Result};

use crate::cli::CertKeyAlgorithm;

/// Generate a fresh CSR key pair (per `alg`) and a CSR over `domains`.
///
/// Returns `(csr_der, key_pem)` where `key_pem` is the freshly generated
/// PKCS#8-PEM-encoded private key (zeroized on drop).
pub(crate) fn generate_csr(
    domains: &[String],
    alg: CertKeyAlgorithm,
) -> Result<(Vec<u8>, zeroize::Zeroizing<String>)> {
    use rcgen::KeyPair;

    let key_pair = match alg {
        CertKeyAlgorithm::EcP256 => KeyPair::generate(),
        CertKeyAlgorithm::EcP384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384),
        CertKeyAlgorithm::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519),
    }
    .context("failed to generate CSR key pair")?;
    build_csr_with_keypair(domains, &key_pair)
}

/// Build a CSR over `domains` using the supplied `key_pair`.
///
/// Used by both the fresh-keygen path ([`generate_csr`]) and the
/// `--reuse-key` path. Returns the CSR DER and a re-serialized PEM of
/// the key (zeroized on drop) — the PEM round-trip lets the caller use
/// the same downstream write/encrypt/copy logic regardless of where the
/// key came from.
pub(crate) fn build_csr_with_keypair(
    domains: &[String],
    key_pair: &rcgen::KeyPair,
) -> Result<(Vec<u8>, zeroize::Zeroizing<String>)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType};

    let common_name = domains
        .first()
        .context("CSR requires at least one domain")?
        .clone();
    let mut params =
        CertificateParams::new(domains.to_vec()).context("failed to create CSR parameters")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    let key_pem = zeroize::Zeroizing::new(key_pair.serialize_pem());
    let csr = params
        .serialize_request(key_pair)
        .context("failed to serialize CSR")?;
    Ok((csr.der().to_vec(), key_pem))
}

/// Load a CSR key pair from an unencrypted PKCS#8 PEM file on disk.
///
/// RFC 8555 §11.1 places no constraints on certificate key freshness,
/// so reusing an on-disk key across renewals is conformant. Encrypted
/// source keys are rejected — the CSR key is intentionally never
/// decrypted on the fly. `rcgen::KeyPair::from_pem` auto-detects the
/// algorithm from the PKCS#8 OID, so `--cert-key-algorithm` is not
/// consulted on this path.
pub(crate) fn load_keypair_from_pem_file(path: &std::path::Path) -> Result<rcgen::KeyPair> {
    let pem = zeroize::Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read --reuse-key file: {}", path.display()))?,
    );
    if pem.contains("ENCRYPTED PRIVATE KEY") {
        anyhow::bail!(
            "--reuse-key file {} contains an encrypted PKCS#8 key; \
             decrypt it out-of-band first (CSR keys cannot be decrypted on the fly)",
            path.display(),
        );
    }
    rcgen::KeyPair::from_pem(&pem)
        .with_context(|| format!("failed to parse --reuse-key PEM at {}", path.display()))
}

pub(crate) fn pem_to_der(pem_data: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_data).context("failed to parse PEM data")?;
    Ok(parsed.contents().to_vec())
}

pub(crate) fn encrypt_private_key(key_pem: &str, password: &str) -> Result<String> {
    use rand_core::RngCore;

    let parsed = pem::parse(key_pem).context("failed to parse private key PEM")?;
    let pk_info = pkcs8::PrivateKeyInfoRef::try_from(parsed.contents())
        .map_err(|e| anyhow::anyhow!("failed to parse PKCS#8 private key: {e}"))?;

    // Use log_n=14 (N=16384) for OpenSSL CLI compatibility.
    // Default log_n=17 (N=131072) requires ~128 MB which exceeds OpenSSL's 32 MB scrypt limit.
    let scrypt_params = scrypt::Params::new(14, 8, 1)
        .map_err(|e| anyhow::anyhow!("invalid scrypt parameters: {e}"))?;
    let mut salt = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut iv);
    let pbes2_params =
        pkcs8::pkcs5::pbes2::Parameters::generate_scrypt_aes256cbc(scrypt_params, &salt, iv)
            .map_err(|e| anyhow::anyhow!("failed to build PBES2 parameters: {e}"))?;

    let encrypted_doc = pk_info
        .encrypt_with_params(pbes2_params, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to encrypt private key: {e}"))?;
    Ok(pem::encode(&pem::Pem::new(
        "ENCRYPTED PRIVATE KEY",
        encrypted_doc.as_bytes().to_vec(),
    )))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn csr_spki(csr_der: &[u8]) -> Vec<u8> {
        use x509_parser::prelude::*;
        let (_, csr) = X509CertificationRequest::from_der(csr_der).expect("parse CSR DER");
        csr.certification_request_info.subject_pki.raw.to_vec()
    }

    #[test]
    fn reuse_key_round_trip_keeps_same_csr_pubkey() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let kp = rcgen::KeyPair::generate().context("generate keypair")?;
        std::fs::write(tmp.path(), kp.serialize_pem())?;

        let domains = vec!["example.com".to_string()];

        let kp_a = load_keypair_from_pem_file(tmp.path())?;
        let (csr_a, _) = build_csr_with_keypair(&domains, &kp_a)?;

        let kp_b = load_keypair_from_pem_file(tmp.path())?;
        let (csr_b, _) = build_csr_with_keypair(&domains, &kp_b)?;

        assert_eq!(
            csr_spki(&csr_a),
            csr_spki(&csr_b),
            "two loads of the same --reuse-key file must yield identical CSR pubkeys"
        );

        let (csr_fresh, _) = generate_csr(&domains, CertKeyAlgorithm::EcP256)?;
        assert_ne!(
            csr_spki(&csr_a),
            csr_spki(&csr_fresh),
            "fresh generate_csr must produce a different pubkey from the reused key"
        );
        Ok(())
    }

    #[test]
    fn reuse_key_rejects_encrypted_pkcs8() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let fake_encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
            MIIBHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI...\n\
            -----END ENCRYPTED PRIVATE KEY-----\n";
        std::fs::write(tmp.path(), fake_encrypted)?;

        let err = load_keypair_from_pem_file(tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("encrypted PKCS#8"),
            "expected encrypted-key rejection, got: {err}"
        );
        Ok(())
    }
}
