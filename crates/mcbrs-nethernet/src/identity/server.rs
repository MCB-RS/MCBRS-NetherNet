//! Server (operator) identity: produces the `a=identity` attribute that every
//! SDP answer must carry (guide §5.2).

use std::path::Path;
use std::time::Duration;

use super::jose::{self, SigningKey, VerifyingKey};
use super::{IDP_PROTOCOL, IdentityAssertion, canonical};
use crate::error::{Error, Result};
use crate::sdp;

/// Default lifetime of the self-signed server token.
pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The long-lived operator keypair plus the metadata embedded in the server JWT.
///
/// Trust is attached to the public key (`cpk`): share one keypair across your
/// whole fleet and avoid rotating it, otherwise TOFU clients get re-prompted.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    key: SigningKey,
    domain: String,
    issuer: Option<String>,
    token_lifetime: Duration,
}

impl ServerIdentity {
    /// Wraps an existing signing key.
    pub fn from_signing_key(key: SigningKey) -> Self {
        Self {
            key,
            domain: "localhost".into(),
            issuer: None,
            token_lifetime: DEFAULT_TOKEN_LIFETIME,
        }
    }

    /// Generates a brand-new operator keypair (P-384 / ES384).
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::generate())
    }

    /// Loads the keypair from a PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        SigningKey::from_pkcs8_pem(pem).map(Self::from_signing_key)
    }

    /// Serializes the private key as PKCS#8 PEM. Keep it secret!
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        self.key.to_pkcs8_pem()
    }

    /// Loads the keypair from `path`, or generates and saves a new one if the
    /// file does not exist yet.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        match std::fs::read_to_string(path) {
            Ok(pem) => Self::from_pkcs8_pem(&pem),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate();
                if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent)?;
                }
                write_private(path, identity.to_pkcs8_pem()?.as_bytes())?;
                Ok(identity)
            }
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Sets `idp.domain` (shown to players as untrusted text in the TOFU prompt).
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    /// Sets the `iss` claim (shown to players as untrusted text in the TOFU prompt).
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets the lifetime (`exp - iat`) of the issued tokens.
    pub fn with_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = lifetime;
        self
    }

    /// `idp.domain` value.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The operator public key (`cpk`).
    pub fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// RFC 7638 SHA-256 thumbprint of `cpk` (`AB:CD:..`). Publish it on a page
    /// your players trust if you accept plaintext HTTP signaling.
    pub fn key_fingerprint(&self) -> String {
        self.public_key().thumbprint_hex()
    }

    /// Issues a fresh self-signed server JWT containing `cpk`, `iat` and `exp`.
    pub fn issue_token(&self) -> String {
        let now = jose::unix_now();
        let mut claims = serde_json::json!({
            "cpk": self.public_key().to_jwk(),
            "iat": now,
            "exp": now + self.token_lifetime.as_secs(),
        });
        if let Some(iss) = &self.issuer {
            claims["iss"] = iss.clone().into();
        }
        jose::sign_jwt(&self.key, &claims)
    }

    /// Builds the server assertion for an answer SDP (the base64 attribute value).
    pub fn assertion_for(&self, answer_sdp: &str) -> Result<IdentityAssertion> {
        let fingerprints = sdp::fingerprints(answer_sdp);
        if fingerprints.is_empty() {
            return Err(Error::sdp("answer has no a=fingerprint line to sign"));
        }
        let payload = canonical::fingerprint_payload(&fingerprints);
        Ok(IdentityAssertion {
            domain: self.domain.clone(),
            protocol: IDP_PROTOCOL.into(),
            token: self.issue_token(),
            fingerprints: jose::sign_detached(&self.key, payload.as_bytes()),
        })
    }

    /// Returns `answer_sdp` with the session-level `a=identity` attribute added.
    pub fn sign_answer(&self, answer_sdp: &str) -> Result<String> {
        let assertion = self.assertion_for(answer_sdp)?;
        Ok(sdp::insert_identity(answer_sdp, &assertion.encode()))
    }
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::verify_server_answer;

    const ANSWER: &str = "v=0\r\no=- 987654321 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
a=fingerprint:sha-256 11:22:33:44\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=setup:active\r\n";

    #[test]
    fn signed_answer_verifies_like_a_client() {
        let id = ServerIdentity::generate()
            .with_domain("partner.example")
            .with_issuer("My Server Network");
        let signed = id.sign_answer(ANSWER).unwrap();
        assert!(signed.contains("a=identity:"));

        let verified = verify_server_answer(&signed).unwrap();
        assert_eq!(verified.domain, "partner.example");
        assert_eq!(verified.claims["iss"], "My Server Network");
        assert_eq!(verified.key_fingerprint(), id.key_fingerprint());
        assert_eq!(sdp::strip_identity(&signed), ANSWER);
    }

    #[test]
    fn tampered_fingerprint_fails() {
        let id = ServerIdentity::generate();
        let signed = id.sign_answer(ANSWER).unwrap();
        let tampered = signed.replace("11:22:33:44", "66:66:66:66");
        assert!(verify_server_answer(&tampered).is_err());
    }

    #[test]
    fn expired_token_fails() {
        let id = ServerIdentity::generate().with_token_lifetime(Duration::ZERO);
        let signed = id.sign_answer(ANSWER).unwrap();
        // exp == iat == now: still valid this very second, but a token issued in the
        // past with a zero lifetime must be rejected.
        let mut claims: serde_json::Value = serde_json::json!({
            "cpk": id.public_key().to_jwk(), "iat": 1, "exp": 2
        });
        claims["iss"] = "x".into();
        let token = jose::sign_jwt(&id.key, &claims);
        let mut a = crate::identity::IdentityAssertion::from_sdp(&signed)
            .unwrap()
            .unwrap();
        a.token = token;
        let resigned = sdp::insert_identity(&signed, &a.encode());
        assert!(verify_server_answer(&resigned).is_err());
    }

    #[test]
    fn load_or_generate_persists_the_key() {
        let dir = std::env::temp_dir().join(format!("mcbrs-nethernet-test-{}", jose::unix_now()));
        let path = dir.join(format!("key-{}.pem", std::process::id()));
        let a = ServerIdentity::load_or_generate(&path).unwrap();
        let b = ServerIdentity::load_or_generate(&path).unwrap();
        assert_eq!(a.key_fingerprint(), b.key_fingerprint());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
