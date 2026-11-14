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
///
/// By default tokens must carry an `exp` claim (a token without expiry could
/// be replayed forever) and a 60 s clock skew is tolerated.
#[derive(Debug, Clone)]
pub struct JwkSetVerifier {
    keys: Vec<(Option<String>, VerifyingKey)>,
    issuer: Option<String>,
    audience: Option<String>,
    leeway_secs: u64,
    require_exp: bool,
}

impl Default for JwkSetVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl JwkSetVerifier {
    /// Creates a verifier with no key (add some with [`Self::with_key`]).
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            issuer: None,
            audience: None,
            leeway_secs: 60,
            require_exp: true,
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

    /// Whether tokens without an `exp` claim are rejected (default `true`).
    pub fn with_require_exp(mut self, require: bool) -> Self {
        self.require_exp = require;
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
        if self.require_exp && jwt.numeric_date("exp")?.is_none() {
            return Err(Error::identity("GameServerToken has no `exp` claim"));
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
///
/// The guide does not list the `GameServerToken` claims. A real Minecraft
/// client (November 2026) sent a token issued by
/// `https://authorization.franchise.minecraft-services.net/` with these
/// claims: `ap`, `aud`, `cpk` (JWK, ES384), `exp`, `iat`, `ipt`, `iss`, `mid`,
/// `pfcd`, `sub`, `tid`, `xid` (XUID) and `xname` (gamertag). Use
/// [`Self::claim`] for any claim without a dedicated accessor.
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

    /// PlayFab ID (claim `PlayFabId` or `pfid`). Not present under these names
    /// in the tokens observed so far; which claim carries it is not documented.
    pub fn playfab_id(&self) -> Option<String> {
        self.first_claim(&["playfabid", "pfid", "playfab_id"])
    }

    /// Player UUID (claim `uuid` or `identity`).
    pub fn uuid(&self) -> Option<String> {
        self.first_claim(&["uuid", "identity"])
    }

    /// Display name / gamertag (claim `xname` in real tokens).
    pub fn display_name(&self) -> Option<String> {
        self.first_claim(&["xname", "displayName", "gamertag", "name"])
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
    fn token_without_exp_is_rejected_by_default() {
        let auth = SigningKey::generate();
        let token = jose::sign_jwt(&auth, &serde_json::json!({ "xid": "1" }));
        let strict = JwkSetVerifier::new().with_key(None, auth.verifying_key());
        assert!(strict.verify(&token).is_err());
        let lenient = strict.with_require_exp(false);
        assert!(lenient.verify(&token).is_ok());
        assert!(JwkSetVerifier::default().require_exp);
        assert_eq!(JwkSetVerifier::default().leeway_secs, 60);
    }

    #[test]
    fn real_token_claim_layout() {
        // Claim names of a real GameServerToken (values are made up).
        let claims = serde_json::json!({
            "ap": "x", "aud": "x", "exp": 1, "iat": 1, "ipt": "x", "iss": "x", "mid": "x",
            "pfcd": 1, "sub": "x", "tid": "x", "xid": "2535400000000042", "xname": "Steve",
            "cpk": SigningKey::generate().verifying_key().to_jwk(),
        });
        let id = ClientIdentity {
            domain: "https://authorization.franchise.minecraft-services.net/".into(),
            public_key: VerifyingKey::from_cpk_claim(&claims["cpk"]).unwrap(),
            claims,
        };
        assert_eq!(id.xuid().as_deref(), Some("2535400000000042"));
        assert_eq!(id.display_name().as_deref(), Some("Steve"));
        assert_eq!(id.claim("pfcd").as_deref(), Some("1"));
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
