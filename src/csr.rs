use anyhow::{Context, Result};

use crate::cli::CertKeyAlgorithm;

pub(crate) fn generate_csr(
    domains: &[String],
    alg: CertKeyAlgorithm,
) -> Result<(Vec<u8>, zeroize::Zeroizing<String>)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    let common_name = domains
        .first()
        .context("CSR requires at least one domain")?
        .clone();
    let mut params =
        CertificateParams::new(domains.to_vec()).context("failed to create CSR parameters")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    let key_pair = match alg {
        CertKeyAlgorithm::EcP256 => KeyPair::generate(),
        CertKeyAlgorithm::EcP384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384),
        CertKeyAlgorithm::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519),
    }
    .context("failed to generate CSR key pair")?;
    let key_pem = zeroize::Zeroizing::new(key_pair.serialize_pem());
    let csr = params
        .serialize_request(&key_pair)
        .context("failed to serialize CSR")?;
    Ok((csr.der().to_vec(), key_pem))
}

pub(crate) fn pem_to_der(pem_data: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_data).context("failed to parse PEM data")?;
    Ok(parsed.contents().to_vec())
}

pub(crate) fn encrypt_private_key(key_pem: &str, password: &str) -> Result<String> {
    use rand_core::RngCore;

    let parsed = pem::parse(key_pem).context("failed to parse private key PEM")?;
    let pk_info = pkcs8::PrivateKeyInfo::try_from(parsed.contents())
        .map_err(|e| anyhow::anyhow!("failed to parse PKCS#8 private key: {e}"))?;

    // Use log_n=14 (N=16384) for OpenSSL CLI compatibility.
    // Default log_n=17 (N=131072) requires ~128 MB which exceeds OpenSSL's 32 MB scrypt limit.
    let scrypt_params = scrypt::Params::new(14, 8, 1, 32)
        .map_err(|e| anyhow::anyhow!("invalid scrypt parameters: {e}"))?;
    let mut salt = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut iv);
    let pbes2_params = pkcs8::pkcs5::pbes2::Parameters::scrypt_aes256cbc(scrypt_params, &salt, &iv)
        .map_err(|e| anyhow::anyhow!("failed to build PBES2 parameters: {e}"))?;

    let encrypted_doc = pk_info
        .encrypt_with_params(pbes2_params, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to encrypt private key: {e}"))?;
    Ok(pem::encode(&pem::Pem::new(
        "ENCRYPTED PRIVATE KEY",
        encrypted_doc.as_bytes().to_vec(),
    )))
}
