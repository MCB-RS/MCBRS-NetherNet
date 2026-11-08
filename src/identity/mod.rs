//! Identity assertions carried in `a=identity` SDP attributes (guide §5).
//!
//! Wire format (both directions):
//!
//! ```text
//! a=identity:<base64( {"idp":{"domain":..,"protocol":"default"},"assertion":"<json string>"} )>
//! assertion = {"token":"<JWT>","fingerprints":"<detached JWS over the a=fingerprint lines>"}
//! ```

pub mod canonical;
pub mod client;
pub mod jose;
pub mod server;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::sdp;
use jose::{Jwt, VerifyingKey};

/// The only `idp.protocol` value defined by NetherNet.
pub const IDP_PROTOCOL: &str = "default";

/// Decoded content of an `a=identity` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityAssertion {
    /// `idp.domain`: auth service domain (client) or partner domain (server).
    pub domain: String,
    /// `idp.protocol`, always `"default"`.
    pub protocol: String,
    /// The JWT (GameServerToken for clients, self-signed token for servers).
    pub token: String,
    /// Detached JWS over the canonical fingerprint JSON.
    pub fingerprints: String,
}

impl IdentityAssertion {
    /// Encodes the assertion as the base64 value of an `a=identity` attribute.
    pub fn encode(&self) -> String {
        let assertion = serde_json::json!({
            "token": self.token,
            "fingerprints": self.fingerprints,
        })
        .to_string();
        let envelope = serde_json::json!({
            "idp": { "domain": self.domain, "protocol": self.protocol },
            "assertion": assertion,
        });
        STANDARD.encode(envelope.to_string())
    }

    /// Decodes the base64 value of an `a=identity` attribute.
    pub fn decode(value: &str) -> Result<Self> {
        let raw = jose::b64_decode_lenient(value)?;
        let envelope: Value = serde_json::from_slice(&raw)
            .map_err(|e| Error::identity(format!("identity envelope is not JSON: {e}")))?;
        let idp = envelope
            .get("idp")
            .ok_or_else(|| Error::identity("identity envelope has no `idp`"))?;
        let domain = idp
            .get("domain")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let protocol = idp
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or(IDP_PROTOCOL);

        // `assertion` is specified as a JSON *string*; accept an inline object too.
        let assertion: Value = match envelope.get("assertion") {
            Some(Value::String(s)) => serde_json::from_str(s)
                .map_err(|e| Error::identity(format!("assertion is not JSON: {e}")))?,
            Some(obj @ Value::Object(_)) => obj.clone(),
            _ => return Err(Error::identity("identity envelope has no `assertion`")),
        };
        let field = |name: &str| {
            assertion
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Error::identity(format!("assertion has no `{name}`")))
        };
        Ok(Self {
            domain: domain.to_owned(),
            protocol: protocol.to_owned(),
            token: field("token")?,
            fingerprints: field("fingerprints")?,
        })
    }

    /// Extracts and decodes the `a=identity` attribute of an SDP, if present.
    pub fn from_sdp(sdp: &str) -> Result<Option<Self>> {
        sdp::identity(sdp).map(Self::decode).transpose()
    }
}

/// Checks that `jws` is a valid detached signature, by `key`, over the
/// canonical JSON of the SDP's `a=fingerprint` lines.
pub fn verify_fingerprint_signature(sdp_text: &str, jws: &str, key: &VerifyingKey) -> Result<()> {
    let fingerprints = sdp::fingerprints(sdp_text);
    if fingerprints.is_empty() {
        return Err(Error::identity("SDP has no a=fingerprint line to verify"));
    }
    let payload = canonical::fingerprint_payload(&fingerprints);
    jose::verify_detached(jws, payload.as_bytes(), key)
        .map_err(|e| Error::identity(format!("fingerprint signature: {e}")))
}

/// Result of verifying a server (answer) assertion, as a Minecraft client would.
#[derive(Debug, Clone)]
pub struct VerifiedServerIdentity {
    /// `idp.domain` (untrusted display text).
    pub domain: String,
    /// Claims of the server JWT (`iss` etc. are untrusted display text).
    pub claims: Value,
    /// The operator public key (`cpk`) – the value a client pins for TOFU.
    pub public_key: VerifyingKey,
}

impl VerifiedServerIdentity {
    /// RFC 7638 thumbprint of `cpk`, formatted `AB:CD:..`.
    pub fn key_fingerprint(&self) -> String {
        self.public_key.thumbprint_hex()
    }
}

/// Verifies the server `a=identity` of an SDP answer exactly like the client
/// does (guide §5.2, "What the Client Does With It", steps 1–6). The trust
/// anchor decision (TLS vs TOFU pin store) is left to the caller.
pub fn verify_server_answer(answer_sdp: &str) -> Result<VerifiedServerIdentity> {
    let assertion = IdentityAssertion::from_sdp(answer_sdp)?
        .ok_or_else(|| Error::identity("answer has no a=identity attribute"))?;
    let jwt = Jwt::parse(&assertion.token)?;
    let cpk = jwt
        .claims
        .get("cpk")
        .ok_or_else(|| Error::identity("server token has no `cpk` claim"))?;
    let public_key = VerifyingKey::from_cpk_claim(cpk)?;
    jwt.verify_signature(&public_key)
        .map_err(|e| Error::identity(format!("server token self-signature: {e}")))?;
    verify_fingerprint_signature(answer_sdp, &assertion.fingerprints, &public_key)?;
    jwt.validate_time(0)?;
    Ok(VerifiedServerIdentity {
        domain: assertion.domain,
        claims: jwt.claims,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let a = IdentityAssertion {
            domain: "partner.example".into(),
            protocol: IDP_PROTOCOL.into(),
            token: "a.b.c".into(),
            fingerprints: "h..s".into(),
        };
        let encoded = a.encode();
        assert_eq!(IdentityAssertion::decode(&encoded).unwrap(), a);

        // The assertion field really is a JSON string inside the envelope.
        let raw: Value = serde_json::from_slice(&STANDARD.decode(&encoded).unwrap()).unwrap();
        assert!(raw["assertion"].is_string());
        assert_eq!(raw["idp"]["protocol"], "default");
    }

    #[test]
    fn rejects_garbage() {
        assert!(IdentityAssertion::decode("!!!").is_err());
        assert!(IdentityAssertion::decode(&STANDARD.encode("{}")).is_err());
    }
}
