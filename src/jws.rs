//! JWS (JSON Web Signature) implementation for ACME per RFC 8555 §6.2
//!
//! All ACME requests with a non-empty body MUST use JWS Flattened JSON
//! Serialization.  The protected header MUST include "alg", "nonce", "url",
//! and exactly one of "jwk" or "kid" (mutually exclusive).

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// ACME account key pair — ES256 (ECDSA with NIST P-256 and SHA-256).
pub struct AccountKey {
    signing_key: SigningKey,
}

// ── Internal serialization helpers ──────────────────────────────────────────

/// JWK representation of an ES256 public key (RFC 7517, RFC 7518 §6.2).
#[derive(Serialize, Clone)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

/// JWS Protected Header (RFC 8555 §6.2).
#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: &'a str,
    url: &'a str,
}

/// JWS Flattened JSON Serialization (RFC 7515 §7.2.2).
#[derive(Serialize)]
struct FlattenedJws {
    protected: String,
    payload: String,
    signature: String,
}

// ── AccountKey implementation ───────────────────────────────────────────────

impl AccountKey {
    /// Generate a new random ES256 key pair.
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        Ok(Self { signing_key })
    }

    /// Load an account key from a PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem_data: &str) -> Result<Self> {
        use p256::pkcs8::DecodePrivateKey;
        let secret_key = p256::SecretKey::from_pkcs8_pem(pem_data)
            .context("failed to decode PKCS#8 PEM private key")?;
        let signing_key = SigningKey::from(secret_key);
        Ok(Self { signing_key })
    }

    /// Export the account key as a PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        use p256::pkcs8::EncodePrivateKey;
        let bytes = self.signing_key.to_bytes();
        let secret_key = p256::SecretKey::from_bytes(&bytes)
            .context("failed to reconstruct secret key")?;
        let pem = secret_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .context("failed to encode private key to PKCS#8 PEM")?;
        Ok(pem.to_string())
    }

    /// Build the JWK (public-key only) for this account key.
    fn jwk(&self) -> Jwk {
        let verifying_key = self.signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(point.x().expect("valid EC point")),
            y: URL_SAFE_NO_PAD.encode(point.y().expect("valid EC point")),
        }
    }

    /// JWK Thumbprint per RFC 7638.
    ///
    /// Used in key authorizations: `token || '.' || thumbprint`.
    /// Lexicographic ordering of the *required* EC members: crv, kty, x, y.
    pub fn thumbprint(&self) -> String {
        let jwk = self.jwk();
        let thumbprint_input = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            jwk.crv, jwk.kty, jwk.x, jwk.y
        );
        let digest = Sha256::digest(thumbprint_input.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }

    /// Sign a request with JWK in the protected header.
    ///
    /// Per RFC 8555 §6.2 this is used for `newAccount` and for `revokeCert`
    /// when signing with the certificate key.
    pub fn sign_with_jwk(&self, payload: &str, nonce: &str, url: &str) -> Result<String> {
        let header = ProtectedHeader {
            alg: "ES256",
            jwk: Some(self.jwk()),
            kid: None,
            nonce,
            url,
        };
        self.sign_jws(&header, payload)
    }

    /// Sign a request with KID (account URL) in the protected header.
    ///
    /// Per RFC 8555 §6.2 this is used for all requests *after* account
    /// creation.
    pub fn sign_with_kid(
        &self,
        payload: &str,
        nonce: &str,
        url: &str,
        kid: &str,
    ) -> Result<String> {
        let header = ProtectedHeader {
            alg: "ES256",
            jwk: None,
            kid: Some(kid),
            nonce,
            url,
        };
        self.sign_jws(&header, payload)
    }

    /// Produce a JWS Flattened JSON Serialization.
    fn sign_jws(&self, header: &ProtectedHeader<'_>, payload: &str) -> Result<String> {
        let protected =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(header)?.as_bytes());

        // RFC 8555 §6.2: POST-as-GET uses an empty string as the payload
        // (the base64url encoding of "" is "").
        let payload_b64 = if payload.is_empty() {
            String::new()
        } else {
            URL_SAFE_NO_PAD.encode(payload.as_bytes())
        };

        let signing_input = format!("{protected}.{payload_b64}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let jws = FlattenedJws {
            protected,
            payload: payload_b64,
            signature: sig_b64,
        };

        serde_json::to_string(&jws).context("failed to serialize JWS")
    }
}
