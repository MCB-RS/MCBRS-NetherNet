//! Validation of the client assertion found in SDP offers (guide §5.1).

use serde_json::Value;

use super::jose::{Jwt, VerifyingKey};
use super::{IdentityAssertion, verify_fingerprint_signature};
use crate::error::{Error, Result};

/// Verifies the `GameServerToken` JWT issued by the Minecraft auth service and
/// returns its claims.
///
/// The auth service public keys are not part of the NetherNet guide, so this is
/// pluggable: use [`JwkSetVerifier`] with the keys you obtained from the auth
/// service, or implement your own (e.g. with key refresh / caching).
pub trait TokenVerifier: Send + Sync + 'static {
    /// Verifies `token` (signature, expiry, issuer, ...) and returns its claims.
    fn verify(&self, token: &str) -> Result<Value>;
}

/// Verifies tokens against a static set of JWKs (a JWKS document).
#[derive(Debug, Clone, Default)]
pub struct JwkSetVerifier {
    keys: Vec<(Option<String>, VerifyingKey)>,
    issuer: Option<String>,
    audience: Option<String>,
    leeway_secs: u64,
}

impl JwkSetVerifier {
    /// Creates a verifier with no key (add some with [`Self::with_key`]).
    pub fn new() -> Self {
        Self {
            leeway_secs: 60,
            ..Self::default()
        }
    }

    /// Parses a JWKS document (`{"keys":[...]}`). Unsupported keys are skipped.
    pub fn from_jwks(jwks: &Value) -> Result<Self> {
        let keys = jwks
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::identity("JWKS document has no `keys` array"))?;
        let mut verifier = Self::new();
        for jwk in keys {
            match VerifyingKey::from_jwk(jwk) {
                Ok(key) => {
                    let kid = jwk.get("kid").and_then(Value::as_str).map(str::to_owned);
                    verifier.keys.push((kid, key));
                }
                Err(e) => tracing::debug!("skipping unsupported JWK: {e}"),
            }
        }
        if verifier.keys.is_empty() {
            return Err(Error::identity(
                "JWKS document contains no supported EC key",
            ));
        }
        Ok(verifier)
    }

    /// Adds a trusted key, optionally bound to a `kid`.
    pub fn with_key(mut self, kid: Option<String>, key: VerifyingKey) -> Self {
        self.keys.push((kid, key));
        self
    }

    /// Requires the `iss` claim to equal `issuer`.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Requires the `aud` claim to contain `audience`.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Clock skew tolerated for `exp` / `nbf` (default 60 s).
    pub fn with_leeway_secs(mut self, leeway: u64) -> Self {
        self.leeway_secs = leeway;
        self
    }
}

impl TokenVerifier for JwkSetVerifier {
    fn verify(&self, token: &str) -> Result<Value> {
        let jwt = Jwt::parse(token)?;
        let by_kid: Vec<_> = match jwt.kid() {
            Some(kid) => self
                .keys
                .iter()
                .filter(|(k, _)| k.as_deref() == Some(kid))
                .collect(),
            None => Vec::new(),
        };
        let candidates = if by_kid.is_empty() {
            self.keys.iter().collect()
        } else {
            by_kid
        };
        if !candidates
            .iter()
            .any(|(_, key)| jwt.verify_signature(key).is_ok())
        {
            return Err(Error::identity(
                "GameServerToken signature does not match any trusted auth service key",
            ));
        }
        jwt.validate_time(self.leeway_secs)?;

        if let Some(expected) = &self.issuer
            && jwt.claims.get("iss").and_then(Value::as_str) != Some(expected.as_str())
        {
            return Err(Error::identity("GameServerToken has an unexpected issuer"));
        }
        if let Some(expected) = &self.audience {
            let ok = match jwt.claims.get("aud") {
                Some(Value::String(a)) => a == expected,
                Some(Value::Array(list)) => list.iter().any(|a| a.as_str() == Some(expected)),
                _ => false,
            };
            if !ok {
                return Err(Error::identity(
                    "GameServerToken has an unexpected audience",
                ));
            }
        }
        Ok(jwt.claims)
    }
}

/// **INSECURE – development only.** Decodes the token without checking its
/// signature. Anybody can impersonate anybody. The fingerprint signature is
/// still checked against the (unverified) `cpk`, which only proves internal
/// consistency of the offer.
#[derive(Debug, Clone, Copy, Default)]
pub struct InsecureTokenDecoder;

impl TokenVerifier for InsecureTokenDecoder {
    fn verify(&self, token: &str) -> Result<Value> {
        let jwt = Jwt::parse(token)?;
        jwt.validate_time(60)?;
        Ok(jwt.claims)
    }
}

/// An authenticated player, extracted from a validated client assertion.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// `idp.domain` of the auth service that issued the token.
    pub domain: String,
    /// Validated claims of the GameServerToken.
    pub claims: Value,
    /// The client public key (`cpk`) that signed the DTLS fingerprints.
    pub public_key: VerifyingKey,
}

impl ClientIdentity {
    /// Looks up a string (or number) claim by name, case-insensitively, at the
    /// top level of the token or inside an `extraData` object.
    pub fn claim(&self, name: &str) -> Option<String> {
        fn find(obj: &Value, name: &str) -> Option<String> {
            let map = obj.as_object()?;
            map.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .and_then(|(_, v)| match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
        }
        find(&self.claims, name).or_else(|| {
            self.claims
                .as_object()?
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("extraData"))
                .and_then(|(_, extra)| find(extra, name))
        })
    }

    fn first_claim(&self, names: &[&str]) -> Option<String> {
        names.iter().find_map(|n| self.claim(n))
    }

    /// Xbox user ID (claim `xuid` or `xid`).
    pub fn xuid(&self) -> Option<String> {
        self.first_claim(&["xuid", "xid"])
    }

    /// PlayFab ID (claim `PlayFabId` or `pfid`).
    pub fn playfab_id(&self) -> Option<String> {
        self.first_claim(&["playfabid", "pfid", "playfab_id"])
    }

    /// Player UUID (claim `uuid` or `identity`).
    pub fn uuid(&self) -> Option<String> {
        self.first_claim(&["uuid", "identity"])
    }

    /// Display name / gamertag, when present.
    pub fn display_name(&self) -> Option<String> {
        self.first_claim(&["displayName", "gamertag", "xname", "name"])
    }
}

/// Validates the client `a=identity` of an SDP offer (guide §5.1, steps 1–5).
///
/// Returns `Ok(None)` when the offer has no `a=identity` attribute (the caller
/// decides whether that is acceptable).
pub fn verify_client_offer(
    offer_sdp: &str,
    verifier: &dyn TokenVerifier,
) -> Result<Option<ClientIdentity>> {
    let Some(assertion) = IdentityAssertion::from_sdp(offer_sdp)? else {
        return Ok(None);
    };
    let claims = verifier.verify(&assertion.token)?;
    let cpk = claims
        .get("cpk")
        .ok_or_else(|| Error::identity("GameServerToken has no `cpk` claim"))?;
    let public_key = VerifyingKey::from_cpk_claim(cpk)?;
    verify_fingerprint_signature(offer_sdp, &assertion.fingerprints, &public_key)?;
    Ok(Some(ClientIdentity {
        domain: assertion.domain,
        claims,
        public_key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::jose::{self, SigningKey};
    use crate::identity::{IDP_PROTOCOL, canonical};
    use crate::sdp;

    const OFFER: &str = "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n\
a=fingerprint:sha-256 AA:BB:CC\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";

    fn signed_offer(auth: &SigningKey, client: &SigningKey) -> String {
        let claims = serde_json::json!({
            "xid": "2535400000000000",
            "pfid": "ABCDEF0123456789",
            "uuid": "4b8e8c4e-0000-4000-8000-000000000000",
            "cpk": client.verifying_key().to_jwk(),
            "exp": jose::unix_now() + 3600,
        });
        let token = jose::sign_jwt(auth, &claims);
        let payload = canonical::fingerprint_payload(&sdp::fingerprints(OFFER));
        let assertion = IdentityAssertion {
            domain: "auth.minecraft.example".into(),
            protocol: IDP_PROTOCOL.into(),
            token,
            fingerprints: jose::sign_detached(client, payload.as_bytes()),
        };
        sdp::insert_identity(OFFER, &assertion.encode())
    }

    #[test]
    fn valid_offer_is_accepted() {
        let auth = SigningKey::generate();
        let client = SigningKey::generate();
        let offer = signed_offer(&auth, &client);
        let verifier = JwkSetVerifier::new().with_key(None, auth.verifying_key());
        let id = verify_client_offer(&offer, &verifier).unwrap().unwrap();
        assert_eq!(id.xuid().as_deref(), Some("2535400000000000"));
        assert_eq!(id.playfab_id().as_deref(), Some("ABCDEF0123456789"));
        assert!(id.uuid().is_some());
        assert_eq!(id.domain, "auth.minecraft.example");
    }

    #[test]
    fn token_from_unknown_issuer_is_rejected() {
        let auth = SigningKey::generate();
        let client = SigningKey::generate();
        let offer = signed_offer(&auth, &client);
        let verifier = JwkSetVerifier::new().with_key(None, SigningKey::generate().verifying_key());
        assert!(verify_client_offer(&offer, &verifier).is_err());
    }

    #[test]
    fn tampered_fingerprint_is_rejected() {
        let auth = SigningKey::generate();
        let client = SigningKey::generate();
        let offer = signed_offer(&auth, &client).replace("AA:BB:CC", "DE:AD:00");
        let verifier = JwkSetVerifier::new().with_key(None, auth.verifying_key());
        assert!(verify_client_offer(&offer, &verifier).is_err());
    }

    #[test]
    fn missing_identity_is_none() {
        let verifier = InsecureTokenDecoder;
        assert!(verify_client_offer(OFFER, &verifier).unwrap().is_none());
    }

    #[test]
    fn jwks_document_is_parsed() {
        let auth = SigningKey::generate();
        let mut jwk = auth.verifying_key().to_jwk();
        jwk["kid"] = "key-1".into();
        let jwks = serde_json::json!({ "keys": [ { "kty": "RSA", "n": "x", "e": "AQAB" }, jwk ] });
        let verifier = JwkSetVerifier::from_jwks(&jwks).unwrap();
        let client = SigningKey::generate();
        assert!(verify_client_offer(&signed_offer(&auth, &client), &verifier).is_ok());
    }
}
