//! Small, dependency-light JOSE toolkit: JWT parsing, detached JWS (RFC 7515
//! Appendix F) and ECDSA keys (ES256 / ES384) in JWK or SPKI form.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::canonical::to_canonical_json;
use crate::error::{Error, Result};

/// Encodes bytes as unpadded base64url.
pub fn b64url(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes base64 leniently: base64url or standard alphabet, padded or not.
pub fn b64_decode_lenient(data: &str) -> Result<Vec<u8>> {
    let data = data.trim();
    URL_SAFE_NO_PAD
        .decode(data)
        .or_else(|_| URL_SAFE.decode(data))
        .or_else(|_| STANDARD.decode(data))
        .or_else(|_| STANDARD_NO_PAD.decode(data))
        .map_err(|e| Error::identity(format!("invalid base64: {e}")))
}

/// Current UNIX time in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A public key able to verify ES256 / ES384 signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyingKey {
    /// NIST P-256, used with `ES256`.
    Es256(p256::ecdsa::VerifyingKey),
    /// NIST P-384, used with `ES384`.
    Es384(p384::ecdsa::VerifyingKey),
}

impl VerifyingKey {
    /// JOSE algorithm name associated with this key.
    pub fn alg(&self) -> &'static str {
        match self {
            Self::Es256(_) => "ES256",
            Self::Es384(_) => "ES384",
        }
    }

    /// Parses a JSON Web Key (RFC 7517) of type `EC`.
    pub fn from_jwk(jwk: &Value) -> Result<Self> {
        let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or_default();
        // Keep only the members the EC parser understands: real-world JWKs also
        // carry `kid`, `use`, `alg`, ... which it would reject.
        let text = serde_json::json!({
            "kty": jwk.get("kty"),
            "crv": crv,
            "x": jwk.get("x"),
            "y": jwk.get("y"),
        })
        .to_string();
        match crv {
            "P-256" => p256::PublicKey::from_jwk_str(&text)
                .map(|k| Self::Es256(k.into()))
                .map_err(|e| Error::identity(format!("invalid P-256 JWK: {e}"))),
            "P-384" => p384::PublicKey::from_jwk_str(&text)
                .map(|k| Self::Es384(k.into()))
                .map_err(|e| Error::identity(format!("invalid P-384 JWK: {e}"))),
            other => Err(Error::identity(format!("unsupported JWK curve `{other}`"))),
        }
    }

    /// Parses a base64-encoded DER SubjectPublicKeyInfo (the format historically
    /// used by Bedrock for identity public keys).
    pub fn from_spki_base64(data: &str) -> Result<Self> {
        use p256::pkcs8::DecodePublicKey as _;
        let der = b64_decode_lenient(data)?;
        if let Ok(k) = p384::PublicKey::from_public_key_der(&der) {
            return Ok(Self::Es384(k.into()));
        }
        if let Ok(k) = p256::PublicKey::from_public_key_der(&der) {
            return Ok(Self::Es256(k.into()));
        }
        Err(Error::identity(
            "public key is neither a P-256 nor a P-384 SPKI",
        ))
    }

    /// Parses a `cpk` claim: a JWK object, a JSON string containing a JWK, or a
    /// base64 DER SPKI string.
    pub fn from_cpk_claim(claim: &Value) -> Result<Self> {
        match claim {
            Value::Object(_) => Self::from_jwk(claim),
            Value::String(s) => {
                let trimmed = s.trim();
                if trimmed.starts_with('{') {
                    let jwk: Value = serde_json::from_str(trimmed)?;
                    Self::from_jwk(&jwk)
                } else {
                    Self::from_spki_base64(trimmed)
                }
            }
            _ => Err(Error::identity(
                "`cpk` claim must be a JWK object or a string",
            )),
        }
    }

    /// Returns the key as a JWK (`kty`, `crv`, `x`, `y`).
    pub fn to_jwk(&self) -> Value {
        let jwk = match self {
            Self::Es256(k) => serde_json::to_value(p256::PublicKey::from(k).to_jwk()),
            Self::Es384(k) => serde_json::to_value(p384::PublicKey::from(k).to_jwk()),
        };
        jwk.expect("JWK serialization cannot fail")
    }

    /// RFC 7638 JWK thumbprint (SHA-256 over the canonical required members).
    pub fn thumbprint(&self) -> [u8; 32] {
        jwk_thumbprint(&self.to_jwk())
    }

    /// Human friendly thumbprint: `AB:CD:...` (uppercase hex, colon separated).
    pub fn thumbprint_hex(&self) -> String {
        hex_colon(&self.thumbprint())
    }

    /// Verifies a raw JWS signature (`r || s`) for the given algorithm.
    pub fn verify(&self, alg: &str, signing_input: &[u8], signature: &[u8]) -> Result<()> {
        use p256::ecdsa::signature::Verifier as _;
        if alg != self.alg() {
            return Err(Error::identity(format!(
                "algorithm `{alg}` does not match the {} key",
                self.alg()
            )));
        }
        let ok = match self {
            Self::Es256(k) => p256::ecdsa::Signature::from_slice(signature)
                .ok()
                .map(|sig| k.verify(signing_input, &sig).is_ok()),
            Self::Es384(k) => p384::ecdsa::Signature::from_slice(signature)
                .ok()
                .map(|sig| k.verify(signing_input, &sig).is_ok()),
        };
        match ok {
            Some(true) => Ok(()),
            Some(false) => Err(Error::identity("signature verification failed")),
            None => Err(Error::identity("malformed ECDSA signature")),
        }
    }
}

/// An ES384 signing key (the algorithm NetherNet uses in the guide's examples).
#[derive(Clone)]
pub struct SigningKey(p384::ecdsa::SigningKey);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("alg", &"ES384")
            .field("thumbprint", &self.verifying_key().thumbprint_hex())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generates a fresh random P-384 key.
    pub fn generate() -> Self {
        Self(p384::ecdsa::SigningKey::random(&mut rand_core::OsRng))
    }

    /// Loads a PKCS#8 PEM encoded P-384 private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        use p384::pkcs8::DecodePrivateKey as _;
        p384::SecretKey::from_pkcs8_pem(pem)
            .map(|k| Self(k.into()))
            .map_err(|e| Error::Key(format!("invalid PKCS#8 P-384 private key: {e}")))
    }

    /// Encodes the key as PKCS#8 PEM.
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        use p384::pkcs8::{EncodePrivateKey as _, LineEnding};
        let secret = p384::SecretKey::from(&self.0);
        secret
            .to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|e| Error::Key(format!("cannot encode private key: {e}")))
    }

    /// JOSE algorithm of this key.
    pub fn alg(&self) -> &'static str {
        "ES384"
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::Es384(*self.0.verifying_key())
    }

    /// Signs `data`, returning the raw JWS signature (`r || s`, 96 bytes).
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        use p384::ecdsa::signature::Signer as _;
        let sig: p384::ecdsa::Signature = self.0.sign(data);
        sig.to_bytes().to_vec()
    }
}

/// A parsed (not yet verified) compact JWT.
#[derive(Debug, Clone)]
pub struct Jwt {
    /// Decoded JOSE header.
    pub header: Value,
    /// Decoded claims.
    pub claims: Value,
    signing_input: String,
    signature: Vec<u8>,
}

impl Jwt {
    /// Parses a compact `header.payload.signature` token.
    pub fn parse(token: &str) -> Result<Self> {
        let mut parts = token.trim().split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::identity("JWT must have exactly three segments"));
        };
        let header: Value = serde_json::from_slice(&b64_decode_lenient(h)?)
            .map_err(|e| Error::identity(format!("invalid JWT header: {e}")))?;
        let claims: Value = serde_json::from_slice(&b64_decode_lenient(p)?)
            .map_err(|e| Error::identity(format!("invalid JWT claims: {e}")))?;
        if !claims.is_object() {
            return Err(Error::identity("JWT claims must be a JSON object"));
        }
        Ok(Self {
            header,
            claims,
            signing_input: format!("{h}.{p}"),
            signature: b64_decode_lenient(s)?,
        })
    }

    /// `alg` header value.
    pub fn alg(&self) -> &str {
        self.header.get("alg").and_then(Value::as_str).unwrap_or("")
    }

    /// `kid` header value, if any.
    pub fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(Value::as_str)
    }

    /// Verifies the signature with `key`.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<()> {
        key.verify(self.alg(), self.signing_input.as_bytes(), &self.signature)
    }

    /// Checks `exp` / `nbf` against the current time, with some leeway (seconds).
    pub fn validate_time(&self, leeway: u64) -> Result<()> {
        let now = unix_now();
        if let Some(exp) = self.claims.get("exp").and_then(Value::as_u64)
            && now > exp.saturating_add(leeway)
        {
            return Err(Error::identity("token is expired"));
        }
        if let Some(nbf) = self.claims.get("nbf").and_then(Value::as_u64)
            && now.saturating_add(leeway) < nbf
        {
            return Err(Error::identity("token is not valid yet"));
        }
        Ok(())
    }
}

/// Creates a compact JWT signed with `key`.
pub fn sign_jwt(key: &SigningKey, claims: &Value) -> String {
    let header = serde_json::json!({ "alg": key.alg(), "typ": "JWT" });
    let signing_input = format!(
        "{}.{}",
        b64url(header.to_string()),
        b64url(claims.to_string())
    );
    let signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(signature))
}

/// Creates a detached JWS (`header..signature`) over `payload`.
pub fn sign_detached(key: &SigningKey, payload: &[u8]) -> String {
    let header = b64url(serde_json::json!({ "alg": key.alg() }).to_string());
    let signing_input = format!("{header}.{}", b64url(payload));
    let signature = key.sign(signing_input.as_bytes());
    format!("{header}..{}", b64url(signature))
}

/// Verifies a detached JWS (`header..signature`) against the reconstructed `payload`.
pub fn verify_detached(jws: &str, payload: &[u8], key: &VerifyingKey) -> Result<()> {
    let mut parts = jws.trim().split('.');
    let (Some(h), Some(""), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::identity(
            "detached JWS must have the form `header..signature`",
        ));
    };
    let header: Value = serde_json::from_slice(&b64_decode_lenient(h)?)
        .map_err(|e| Error::identity(format!("invalid JWS header: {e}")))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let signing_input = format!("{h}.{}", b64url(payload));
    key.verify(alg, signing_input.as_bytes(), &b64_decode_lenient(s)?)
}

/// RFC 7638 thumbprint of an EC JWK.
pub fn jwk_thumbprint(jwk: &Value) -> [u8; 32] {
    let required = serde_json::json!({
        "crv": jwk.get("crv"),
        "kty": jwk.get("kty"),
        "x": jwk.get("x"),
        "y": jwk.get("y"),
    });
    Sha256::digest(to_canonical_json(&required).as_bytes()).into()
}

/// Formats bytes as `AB:CD:EF`.
pub fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_roundtrip() {
        let key = SigningKey::generate();
        let token = sign_jwt(
            &key,
            &serde_json::json!({ "sub": "me", "exp": unix_now() + 60 }),
        );
        let jwt = Jwt::parse(&token).unwrap();
        assert_eq!(jwt.alg(), "ES384");
        jwt.verify_signature(&key.verifying_key()).unwrap();
        jwt.validate_time(0).unwrap();

        let other = SigningKey::generate();
        assert!(jwt.verify_signature(&other.verifying_key()).is_err());
    }

    #[test]
    fn expired_jwt_is_rejected() {
        let key = SigningKey::generate();
        let token = sign_jwt(&key, &serde_json::json!({ "exp": 10 }));
        assert!(Jwt::parse(&token).unwrap().validate_time(60).is_err());
    }

    #[test]
    fn detached_jws_roundtrip() {
        let key = SigningKey::generate();
        let jws = sign_detached(&key, b"payload");
        assert!(jws.contains(".."));
        verify_detached(&jws, b"payload", &key.verifying_key()).unwrap();
        assert!(verify_detached(&jws, b"tampered", &key.verifying_key()).is_err());
    }

    #[test]
    fn pem_roundtrip() {
        let key = SigningKey::generate();
        let pem = key.to_pkcs8_pem().unwrap();
        let back = SigningKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(key.verifying_key(), back.verifying_key());
    }

    #[test]
    fn cpk_claim_formats() {
        use p384::pkcs8::EncodePublicKey as _;
        let key = SigningKey::generate();
        let vk = key.verifying_key();
        let jwk = vk.to_jwk();
        assert_eq!(VerifyingKey::from_cpk_claim(&jwk).unwrap(), vk);
        assert_eq!(
            VerifyingKey::from_cpk_claim(&Value::String(jwk.to_string())).unwrap(),
            vk
        );

        let VerifyingKey::Es384(inner) = &vk else {
            unreachable!()
        };
        let der = p384::PublicKey::from(inner).to_public_key_der().unwrap();
        let spki = STANDARD.encode(der.as_bytes());
        assert_eq!(
            VerifyingKey::from_cpk_claim(&Value::String(spki)).unwrap(),
            vk
        );
    }

    #[test]
    fn es256_keys_are_supported() {
        use p256::ecdsa::signature::Signer as _;
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let vk = VerifyingKey::Es256(*sk.verifying_key());
        let jwk = vk.to_jwk();
        assert_eq!(jwk["crv"], "P-256");
        let sig: p256::ecdsa::Signature = sk.sign(b"abc");
        vk.verify("ES256", b"abc", &sig.to_bytes()).unwrap();
        assert!(vk.verify("ES384", b"abc", &sig.to_bytes()).is_err());
    }

    #[test]
    fn thumbprint_is_stable() {
        let key = SigningKey::generate();
        let a = key.verifying_key().thumbprint_hex();
        let b = VerifyingKey::from_jwk(&key.verifying_key().to_jwk())
            .unwrap()
            .thumbprint_hex();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32 * 3 - 1);
    }
}
