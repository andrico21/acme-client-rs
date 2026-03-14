//! JWS (JSON Web Signature) implementation for ACME per RFC 8555 §6.2
//!
//! All ACME requests with a non-empty body MUST use JWS Flattened JSON
//! Serialization.  The protected header MUST include "alg", "nonce", "url",
//! and exactly one of "jwk" or "kid" (mutually exclusive).
//!
//! Supported account key algorithms:
//! - ES256 (ECDSA P-256 + SHA-256) - RFC 8555 §6.2 mandatory
//! - ES384 (ECDSA P-384 + SHA-384)
//! - ES512 (ECDSA P-521 + SHA-512)
//! - RS256 (RSASSA-PKCS1-v1.5 + SHA-256)
//! - EdDSA (Ed25519)

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ecdsa::signature::Signer;
use serde::Serialize;
use sha2::{Digest, Sha256};

use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p521::ecdsa::SigningKey as P521SigningKey;

/// Supported account key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum KeyAlgorithm {
    /// ECDSA P-256 + SHA-256 (default, RFC 8555 §6.2 mandatory)
    Es256,
    /// ECDSA P-384 + SHA-384
    Es384,
    /// ECDSA P-521 + SHA-512
    Es512,
    /// RSA 2048-bit + PKCS#1 v1.5 + SHA-256
    Rsa2048,
    /// RSA 4096-bit + PKCS#1 v1.5 + SHA-256
    Rsa4096,
    /// Ed25519 (EdDSA)
    Ed25519,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Es256 => write!(f, "ES256"),
            Self::Es384 => write!(f, "ES384"),
            Self::Es512 => write!(f, "ES512"),
            Self::Rsa2048 => write!(f, "RSA-2048"),
            Self::Rsa4096 => write!(f, "RSA-4096"),
            Self::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

// ── Internal key storage ────────────────────────────────────────────────────

enum KeyInner {
    Es256(P256SigningKey),
    Es384(P384SigningKey),
    Es512(P521SigningKey),
    Rs256(Box<rsa::RsaPrivateKey>),
    Ed25519(ed25519_dalek::SigningKey),
}

/// ACME account key pair - supports ES256, ES384, ES512, RS256, Ed25519.
pub struct AccountKey {
    inner: KeyInner,
}

// ── JWS serialization helpers ───────────────────────────────────────────────

/// JWS Protected Header (RFC 8555 §6.2).
#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<serde_json::Value>,
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
    /// Generate a new random key pair for the given algorithm.
    pub fn generate(alg: KeyAlgorithm) -> Result<Self> {
        use rand_core::OsRng;
        let inner = match alg {
            KeyAlgorithm::Es256 => KeyInner::Es256(P256SigningKey::random(&mut OsRng)),
            KeyAlgorithm::Es384 => KeyInner::Es384(P384SigningKey::random(&mut OsRng)),
            KeyAlgorithm::Es512 => KeyInner::Es512(P521SigningKey::random(&mut OsRng)),
            KeyAlgorithm::Rsa2048 => {
                let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048)
                    .context("failed to generate RSA-2048 key")?;
                KeyInner::Rs256(Box::new(key))
            }
            KeyAlgorithm::Rsa4096 => {
                let key = rsa::RsaPrivateKey::new(&mut OsRng, 4096)
                    .context("failed to generate RSA-4096 key")?;
                KeyInner::Rs256(Box::new(key))
            }
            KeyAlgorithm::Ed25519 => {
                KeyInner::Ed25519(ed25519_dalek::SigningKey::generate(&mut OsRng))
            }
        };
        Ok(Self { inner })
    }

    /// Load an account key from a PKCS#8 PEM string.
    /// The algorithm is auto-detected from the key's OID.
    pub fn from_pkcs8_pem(pem_data: &str) -> Result<Self> {
        use p256::pkcs8::DecodePrivateKey;

        if let Ok(sk) = p256::SecretKey::from_pkcs8_pem(pem_data) {
            return Ok(Self {
                inner: KeyInner::Es256(P256SigningKey::from(sk)),
            });
        }
        if let Ok(sk) = p384::SecretKey::from_pkcs8_pem(pem_data) {
            return Ok(Self {
                inner: KeyInner::Es384(P384SigningKey::from(sk)),
            });
        }
        if let Ok(sk) = p521::SecretKey::from_pkcs8_pem(pem_data) {
            let signing_key = P521SigningKey::from_bytes(&sk.to_bytes())
                .context("failed to create P-521 signing key from loaded secret")?;
            return Ok(Self {
                inner: KeyInner::Es512(signing_key),
            });
        }
        if let Ok(sk) = rsa::RsaPrivateKey::from_pkcs8_pem(pem_data) {
            return Ok(Self {
                inner: KeyInner::Rs256(Box::new(sk)),
            });
        }
        if let Ok(sk) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem_data) {
            return Ok(Self {
                inner: KeyInner::Ed25519(sk),
            });
        }

        bail!(
            "unsupported or invalid PKCS#8 PEM key \
             (supported: ES256, ES384, ES512, RS256, Ed25519)"
        )
    }

    /// Export the account key as a PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};

        match &self.inner {
            KeyInner::Es256(sk) => {
                let secret = p256::SecretKey::from_bytes(&sk.to_bytes())
                    .context("failed to reconstruct P-256 secret key")?;
                let pem = secret
                    .to_pkcs8_pem(LineEnding::LF)
                    .context("failed to encode key to PKCS#8 PEM")?;
                Ok(pem.to_string())
            }
            KeyInner::Es384(sk) => {
                let secret = p384::SecretKey::from_bytes(&sk.to_bytes())
                    .context("failed to reconstruct P-384 secret key")?;
                let pem = secret
                    .to_pkcs8_pem(LineEnding::LF)
                    .context("failed to encode key to PKCS#8 PEM")?;
                Ok(pem.to_string())
            }
            KeyInner::Es512(sk) => {
                let secret = p521::SecretKey::from_bytes(&sk.to_bytes())
                    .context("failed to reconstruct P-521 secret key")?;
                let pem = secret
                    .to_pkcs8_pem(LineEnding::LF)
                    .context("failed to encode key to PKCS#8 PEM")?;
                Ok(pem.to_string())
            }
            KeyInner::Rs256(sk) => {
                let pem = sk
                    .to_pkcs8_pem(LineEnding::LF)
                    .context("failed to encode key to PKCS#8 PEM")?;
                Ok(pem.to_string())
            }
            KeyInner::Ed25519(sk) => {
                let pem = sk
                    .to_pkcs8_pem(LineEnding::LF)
                    .context("failed to encode key to PKCS#8 PEM")?;
                Ok(pem.to_string())
            }
        }
    }

    /// JWS algorithm identifier (RFC 7518).
    pub fn alg(&self) -> &'static str {
        match &self.inner {
            KeyInner::Es256(_) => "ES256",
            KeyInner::Es384(_) => "ES384",
            KeyInner::Es512(_) => "ES512",
            KeyInner::Rs256(_) => "RS256",
            KeyInner::Ed25519(_) => "EdDSA",
        }
    }

    /// Build the JWK (public-key only) as a JSON value (RFC 7517).
    pub fn jwk(&self) -> serde_json::Value {
        match &self.inner {
            KeyInner::Es256(sk) => {
                let pt = sk.verifying_key().to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": URL_SAFE_NO_PAD.encode(pt.x().expect("valid EC point")),
                    "y": URL_SAFE_NO_PAD.encode(pt.y().expect("valid EC point")),
                })
            }
            KeyInner::Es384(sk) => {
                let pt = sk.verifying_key().to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC",
                    "crv": "P-384",
                    "x": URL_SAFE_NO_PAD.encode(pt.x().expect("valid EC point")),
                    "y": URL_SAFE_NO_PAD.encode(pt.y().expect("valid EC point")),
                })
            }
            KeyInner::Es512(sk) => {
                // p521 0.13's wrapper doesn't expose verifying_key(), so
                // reconstruct via the inner ecdsa::SigningKey type.
                let inner = ecdsa::SigningKey::<p521::NistP521>::from_bytes(&sk.to_bytes())
                    .expect("valid P-521 key");
                let pt = inner.verifying_key().to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC",
                    "crv": "P-521",
                    "x": URL_SAFE_NO_PAD.encode(pt.x().expect("valid EC point")),
                    "y": URL_SAFE_NO_PAD.encode(pt.y().expect("valid EC point")),
                })
            }
            KeyInner::Rs256(sk) => {
                use rsa::traits::PublicKeyParts;
                serde_json::json!({
                    "kty": "RSA",
                    "n": URL_SAFE_NO_PAD.encode(sk.n().to_bytes_be()),
                    "e": URL_SAFE_NO_PAD.encode(sk.e().to_bytes_be()),
                })
            }
            KeyInner::Ed25519(sk) => {
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes()),
                })
            }
        }
    }

    /// JWK Thumbprint per RFC 7638.
    ///
    /// Used in key authorizations: `token || '.' || thumbprint`.
    /// Required members in lexicographic order per key type.
    pub fn thumbprint(&self) -> String {
        let input = match &self.inner {
            KeyInner::Es256(sk) => {
                let pt = sk.verifying_key().to_encoded_point(false);
                let x = URL_SAFE_NO_PAD.encode(pt.x().expect("valid EC point"));
                let y = URL_SAFE_NO_PAD.encode(pt.y().expect("valid EC point"));
                format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            KeyInner::Es384(sk) => {
                let pt = sk.verifying_key().to_encoded_point(false);
                let x = URL_SAFE_NO_PAD.encode(pt.x().expect("valid EC point"));
                let y = URL_SAFE_NO_PAD.encode(pt.y().expect("valid EC point"));
                format!(r#"{{"crv":"P-384","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            KeyInner::Es512(sk) => {
                let inner = ecdsa::SigningKey::<p521::NistP521>::from_bytes(&sk.to_bytes())
                    .expect("valid P-521 key");
                let pt = inner.verifying_key().to_encoded_point(false);
                let x = URL_SAFE_NO_PAD.encode(pt.x().expect("valid EC point"));
                let y = URL_SAFE_NO_PAD.encode(pt.y().expect("valid EC point"));
                format!(r#"{{"crv":"P-521","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            KeyInner::Rs256(sk) => {
                use rsa::traits::PublicKeyParts;
                let e = URL_SAFE_NO_PAD.encode(sk.e().to_bytes_be());
                let n = URL_SAFE_NO_PAD.encode(sk.n().to_bytes_be());
                format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
            }
            KeyInner::Ed25519(sk) => {
                let x = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
                format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#)
            }
        };
        let digest = Sha256::digest(input.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }

    /// Sign a request with JWK in the protected header.
    ///
    /// Per RFC 8555 §6.2 this is used for `newAccount` and for `revokeCert`
    /// when signing with the certificate key.
    pub fn sign_with_jwk(&self, payload: &str, nonce: &str, url: &str) -> Result<String> {
        let header = ProtectedHeader {
            alg: self.alg(),
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
            alg: self.alg(),
            jwk: None,
            kid: Some(kid),
            nonce,
            url,
        };
        self.sign_jws(&header, payload)
    }

    /// Raw signature bytes over the given data.
    fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        match &self.inner {
            KeyInner::Es256(sk) => {
                let sig: p256::ecdsa::Signature = sk.sign(data);
                sig.to_bytes().to_vec()
            }
            KeyInner::Es384(sk) => {
                let sig: p384::ecdsa::Signature = sk.sign(data);
                sig.to_bytes().to_vec()
            }
            KeyInner::Es512(sk) => {
                let sig: p521::ecdsa::Signature = sk.sign(data);
                sig.to_bytes().to_vec()
            }
            KeyInner::Rs256(sk) => {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<Sha256>::new(sk.as_ref().clone());
                let sig: rsa::pkcs1v15::Signature = signing_key.sign(data);
                let bytes: Box<[u8]> = sig.into();
                bytes.to_vec()
            }
            KeyInner::Ed25519(sk) => {
                let sig = ed25519_dalek::Signer::sign(sk, data);
                sig.to_bytes().to_vec()
            }
        }
    }

    /// Sign the inner JWS for key-change (RFC 8555 Section 7.3.5).
    ///
    /// The inner JWS uses a protected header with `alg`, `jwk` (the NEW
    /// key's public JWK), and `url` (the key-change URL).  No `nonce` or `kid`.
    pub fn sign_key_change_inner(&self, payload: &str, url: &str) -> Result<String> {
        let header = serde_json::json!({
            "alg": self.alg(),
            "jwk": self.jwk(),
            "url": url,
        });
        let protected =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signing_input = format!("{protected}.{payload_b64}");
        let sig_bytes = self.sign_raw(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

        let jws = FlattenedJws {
            protected,
            payload: payload_b64,
            signature: sig_b64,
        };
        serde_json::to_string(&jws).context("failed to serialize inner JWS")
    }

    /// Build the inner JWS for External Account Binding (RFC 8555 §7.3.4).
    ///
    /// The payload is the account's public JWK, signed with HMAC-SHA256
    /// using the EAB key provided by the CA.
    pub fn sign_eab(
        &self,
        eab_kid: &str,
        hmac_key: &[u8],
        url: &str,
    ) -> Result<serde_json::Value> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let header = serde_json::json!({
            "alg": "HS256",
            "kid": eab_kid,
            "url": url,
        });
        let protected =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?.as_bytes());
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&self.jwk())?.as_bytes());
        let signing_input = format!("{protected}.{payload_b64}");

        let mut mac = HmacSha256::new_from_slice(hmac_key)
            .context("invalid HMAC key length")?;
        mac.update(signing_input.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

        Ok(serde_json::json!({
            "protected": protected,
            "payload": payload_b64,
            "signature": sig_b64,
        }))
    }

    /// Produce a JWS Flattened JSON Serialization.
    fn sign_jws(&self, header: &ProtectedHeader<'_>, payload: &str) -> Result<String> {
        let protected =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(header)?.as_bytes());

        let payload_b64 = if payload.is_empty() {
            String::new()
        } else {
            URL_SAFE_NO_PAD.encode(payload.as_bytes())
        };

        let signing_input = format!("{protected}.{payload_b64}");
        let sig_bytes = self.sign_raw(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

        let jws = FlattenedJws {
            protected,
            payload: payload_b64,
            signature: sig_b64,
        };

        serde_json::to_string(&jws).context("failed to serialize JWS")
    }
}
