//! Passkey ceremonies (S12): user verification always, discoverable credentials always (sign-in has
//! no username step), challenges single-use for 5 minutes, RP ID = the issuer's host.
//!
//! Options are emitted in the JSON shape @simplewebauthn/browser consumes, and credentials are
//! stored as before: the COSE public key bytes, the signature counter, the transports. Attestation
//! is requested as "none" and never trusted, so attestation statements are not evaluated.

use anyhow::{Result, anyhow, bail};
use aws_lc_rs::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use ciborium::value::Value as Cbor;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::crypto::{b64url, b64url_decode, random_token, sha256};

pub const CHALLENGE_TTL_SECONDS: i64 = 5 * 60;
const ES256: i64 = -7;
const EDDSA: i64 = -8;
const RS256: i64 = -257;
const ALGORITHMS: [i64; 3] = [ES256, EDDSA, RS256];

#[derive(Clone)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
    pub origin: String,
}

pub struct PasskeyUser<'a> {
    pub handle: &'a str,
    pub display_name: &'a str,
    pub email: Option<&'a str>,
    pub username: Option<&'a str>,
}

/// The account label password managers show under the item title. Prefer a real identifier; with
/// neither, pair the name with this instance's host so the passkey says where it signs in.
pub fn passkey_user_name(rp: &RelyingParty, user: &PasskeyUser) -> String {
    user.email
        .filter(|e| !e.is_empty())
        .or(user.username.filter(|u| !u.is_empty()))
        .map(str::to_string)
        .unwrap_or_else(|| format!("{} ({})", user.display_name, rp.id))
}

pub struct Existing {
    pub credential_id: String,
    pub transports: Vec<String>,
}

pub fn registration_options(rp: &RelyingParty, user: &PasskeyUser, existing: &[Existing]) -> Value {
    json!({
        "challenge": random_token(32),
        "rp": { "name": rp.name, "id": rp.id },
        "user": {
            "id": user.handle,
            "name": passkey_user_name(rp, user),
            "displayName": user.display_name,
        },
        "pubKeyCredParams": ALGORITHMS.iter().map(|alg| json!({ "alg": alg, "type": "public-key" })).collect::<Vec<_>>(),
        "timeout": 60000,
        "attestation": "none",
        "excludeCredentials": existing.iter().map(|c| json!({
            "id": c.credential_id,
            "type": "public-key",
            "transports": c.transports,
        })).collect::<Vec<_>>(),
        "authenticatorSelection": {
            "residentKey": "required",
            "userVerification": "required",
            "requireResidentKey": true,
        },
        "extensions": { "credProps": true },
        "hints": [],
    })
}

/// Empty allowCredentials: the browser offers every passkey it has for this site.
pub fn authentication_options(rp: &RelyingParty) -> Value {
    json!({
        "challenge": random_token(32),
        "timeout": 60000,
        "rpId": rp.id,
        "allowCredentials": [],
        "userVerification": "required",
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum PasskeyError {
    Invalid(String),
    Counter,
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasskeyError::Invalid(m) => write!(f, "{m}"),
            PasskeyError::Counter => write!(f, "This passkey reported an out-of-order counter."),
        }
    }
}

/// What the browser sent back, as @simplewebauthn/browser serialises it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialResponse {
    pub id: String,
    #[serde(default)]
    pub raw_id: Option<String>,
    pub response: AuthenticatorResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(default)]
    pub attestation_object: Option<String>,
    #[serde(default)]
    pub authenticator_data: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub transports: Option<Vec<String>>,
}

impl CredentialResponse {
    pub fn parse(value: Option<&Value>) -> Option<Self> {
        serde_json::from_value(value?.clone()).ok()
    }

    /// The challenge the browser signed, read from clientDataJSON, to find its stored record.
    pub fn challenge(&self) -> Option<String> {
        let data: Value = serde_json::from_slice(&b64url_decode(&self.response.client_data_json)?).ok()?;
        data["challenge"].as_str().map(str::to_string)
    }
}

pub struct VerifiedRegistration {
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub aaguid: Option<uuid::Uuid>,
    pub device_type: &'static str,
    pub backed_up: bool,
}

pub struct VerifiedAuthentication {
    pub sign_count: i64,
    pub backed_up: bool,
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

fn invalid(message: &str) -> PasskeyError {
    PasskeyError::Invalid(message.to_string())
}

fn check_client_data(rp: &RelyingParty, encoded: &str, kind: &str, challenge: &str) -> Result<Vec<u8>, PasskeyError> {
    let raw = b64url_decode(encoded).ok_or_else(|| invalid("clientDataJSON is not base64url"))?;
    let data: Value = serde_json::from_slice(&raw).map_err(|_| invalid("clientDataJSON is not JSON"))?;
    if data["type"] != kind {
        return Err(invalid("Unexpected ceremony type"));
    }
    if data["challenge"] != challenge {
        return Err(invalid("Unexpected challenge"));
    }
    if data["origin"] != rp.origin.as_str() {
        return Err(invalid("Unexpected origin"));
    }
    Ok(raw)
}

struct AuthData<'a> {
    flags: u8,
    counter: u32,
    rest: &'a [u8],
}

fn parse_auth_data<'a>(rp: &RelyingParty, data: &'a [u8]) -> Result<AuthData<'a>, PasskeyError> {
    if data.len() < 37 {
        return Err(invalid("authenticatorData is too short"));
    }
    if data[..32] != sha256(rp.id.as_bytes()) {
        return Err(invalid("Unexpected RP ID hash"));
    }
    let flags = data[32];
    if flags & FLAG_UP == 0 {
        return Err(invalid("User was not present"));
    }
    if flags & FLAG_UV == 0 {
        return Err(invalid("User verification was required"));
    }
    let counter = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    Ok(AuthData { flags, counter, rest: &data[37..] })
}

fn cbor_get<'a>(map: &'a Cbor, key: &Cbor) -> Option<&'a Cbor> {
    map.as_map()?.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn int(value: i64) -> Cbor {
    Cbor::Integer(value.into())
}

fn cose_alg(key: &Cbor) -> Option<i64> {
    i64::try_from(cbor_get(key, &int(3))?.as_integer()?).ok()
}

pub fn verify_registration(
    rp: &RelyingParty,
    response: &CredentialResponse,
    expected_challenge: &str,
) -> Result<VerifiedRegistration, PasskeyError> {
    check_client_data(rp, &response.response.client_data_json, "webauthn.create", expected_challenge)?;
    let attestation = b64url_decode(response.response.attestation_object.as_deref().unwrap_or_default())
        .ok_or_else(|| invalid("attestationObject is missing"))?;
    let object: Cbor = ciborium::from_reader(attestation.as_slice()).map_err(|_| invalid("attestationObject is not CBOR"))?;
    let auth_data = cbor_get(&object, &Cbor::Text("authData".into()))
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| invalid("authData is missing"))?;
    let parsed = parse_auth_data(rp, auth_data)?;
    if parsed.flags & FLAG_AT == 0 || parsed.rest.len() < 18 {
        return Err(invalid("No attested credential data"));
    }
    let aaguid = &parsed.rest[..16];
    let id_len = u16::from_be_bytes([parsed.rest[16], parsed.rest[17]]) as usize;
    if parsed.rest.len() < 18 + id_len {
        return Err(invalid("Credential ID is truncated"));
    }
    let credential_id = &parsed.rest[18..18 + id_len];
    let key_bytes = &parsed.rest[18 + id_len..];
    let mut reader = key_bytes;
    let key: Cbor = ciborium::from_reader(&mut reader).map_err(|_| invalid("Public key is not COSE"))?;
    let public_key = key_bytes[..key_bytes.len() - reader.len()].to_vec();
    let alg = cose_alg(&key).ok_or_else(|| invalid("Public key has no algorithm"))?;
    if !ALGORITHMS.contains(&alg) {
        return Err(invalid("Unsupported public key algorithm"));
    }
    // Fails early on a key we could never verify with.
    verifier(&key).map_err(|e| invalid(&e.to_string()))?;
    if response.id != b64url(credential_id) {
        return Err(invalid("Credential ID mismatch"));
    }
    let aaguid = uuid::Uuid::from_slice(aaguid).ok().filter(|u| !u.is_nil());
    Ok(VerifiedRegistration {
        credential_id: b64url(credential_id),
        public_key,
        sign_count: parsed.counter as i64,
        transports: response.response.transports.clone().unwrap_or_default(),
        aaguid,
        device_type: if parsed.flags & FLAG_BE != 0 { "multiDevice" } else { "singleDevice" },
        backed_up: parsed.flags & FLAG_BS != 0,
    })
}

enum Verifier {
    Ecdsa(Vec<u8>),
    Ed25519(Vec<u8>),
    Rsa(Vec<u8>, Vec<u8>),
}

fn verifier(key: &Cbor) -> Result<Verifier> {
    let bytes = |label: i64| cbor_get(key, &int(label)).and_then(Cbor::as_bytes).cloned().ok_or_else(|| anyhow!("missing {label}"));
    match cose_alg(key) {
        Some(ES256) => {
            let mut point = vec![0x04];
            point.extend(bytes(-2)?);
            point.extend(bytes(-3)?);
            if point.len() != 65 {
                bail!("Unexpected P-256 key size");
            }
            Ok(Verifier::Ecdsa(point))
        }
        Some(EDDSA) => Ok(Verifier::Ed25519(bytes(-2)?)),
        Some(RS256) => Ok(Verifier::Rsa(bytes(-1)?, bytes(-2)?)),
        _ => bail!("Unsupported public key algorithm"),
    }
}

impl Verifier {
    fn verify(&self, message: &[u8], sig: &[u8]) -> bool {
        match self {
            Verifier::Ecdsa(point) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point).verify(message, sig).is_ok()
            }
            Verifier::Ed25519(x) => UnparsedPublicKey::new(&signature::ED25519, x).verify(message, sig).is_ok(),
            Verifier::Rsa(n, e) => {
                RsaPublicKeyComponents { n, e }.verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, sig).is_ok()
            }
        }
    }
}

pub struct StoredPasskey<'a> {
    pub credential_id: &'a str,
    pub public_key: &'a [u8],
    pub sign_count: i64,
}

pub fn verify_authentication(
    rp: &RelyingParty,
    response: &CredentialResponse,
    expected_challenge: &str,
    stored: &StoredPasskey,
) -> Result<VerifiedAuthentication, PasskeyError> {
    let client_data = check_client_data(rp, &response.response.client_data_json, "webauthn.get", expected_challenge)?;
    if response.id != stored.credential_id {
        return Err(invalid("Credential ID mismatch"));
    }
    let auth_data = b64url_decode(response.response.authenticator_data.as_deref().unwrap_or_default())
        .ok_or_else(|| invalid("authenticatorData is missing"))?;
    let parsed = parse_auth_data(rp, &auth_data)?;
    let sig = b64url_decode(response.response.signature.as_deref().unwrap_or_default())
        .ok_or_else(|| invalid("signature is missing"))?;
    let key: Cbor = ciborium::from_reader(stored.public_key).map_err(|_| invalid("Stored key is not COSE"))?;
    let verifier = verifier(&key).map_err(|e| invalid(&e.to_string()))?;
    let mut message = auth_data.clone();
    message.extend_from_slice(&sha256(&client_data));
    if !verifier.verify(&message, &sig) {
        return Err(invalid("Signature verification failed"));
    }
    let new_counter = parsed.counter as i64;
    // Synced passkeys report 0 forever. A counter that goes backwards means a cloned authenticator.
    if (new_counter > 0 || stored.sign_count > 0) && new_counter <= stored.sign_count {
        return Err(PasskeyError::Counter);
    }
    Ok(VerifiedAuthentication { sign_count: new_counter, backed_up: parsed.flags & FLAG_BS != 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair},
    };

    fn rp() -> RelyingParty {
        RelyingParty { id: "localhost".into(), name: "Handstamp".into(), origin: "http://localhost:3000".into() }
    }

    fn cbor(value: &Cbor) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(value, &mut out).unwrap();
        out
    }

    struct Soft {
        pair: EcdsaKeyPair,
        id: Vec<u8>,
        counter: u32,
    }

    impl Soft {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
            Self { pair, id: vec![9; 16], counter: 0 }
        }

        fn auth_data(&self, flags: u8, counter: u32, attested: &[u8]) -> Vec<u8> {
            let mut data = sha256(b"localhost").to_vec();
            data.push(flags);
            data.extend(counter.to_be_bytes());
            data.extend(attested);
            data
        }

        fn create(&self, challenge: &str, origin: &str) -> Value {
            let point = self.pair.public_key().as_ref();
            let key = Cbor::Map(vec![
                (int(1), int(2)),
                (int(3), int(-7)),
                (int(-1), int(1)),
                (int(-2), Cbor::Bytes(point[1..33].to_vec())),
                (int(-3), Cbor::Bytes(point[33..].to_vec())),
            ]);
            let mut attested = vec![0u8; 16];
            attested.extend((self.id.len() as u16).to_be_bytes());
            attested.extend(&self.id);
            attested.extend(cbor(&key));
            let auth = self.auth_data(0x45, 0, &attested);
            let object = Cbor::Map(vec![
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
                (Cbor::Text("authData".into()), Cbor::Bytes(auth)),
            ]);
            let client = json!({ "type": "webauthn.create", "challenge": challenge, "origin": origin }).to_string();
            json!({
                "id": b64url(&self.id), "rawId": b64url(&self.id), "type": "public-key",
                "response": {
                    "clientDataJSON": b64url(client.as_bytes()),
                    "attestationObject": b64url(&cbor(&object)),
                    "transports": ["internal"],
                },
            })
        }

        fn get(&mut self, challenge: &str) -> Value {
            self.counter += 1;
            let auth = self.auth_data(0x05, self.counter, &[]);
            let client = json!({ "type": "webauthn.get", "challenge": challenge, "origin": "http://localhost:3000" }).to_string();
            let mut message = auth.clone();
            message.extend(sha256(client.as_bytes()));
            let sig = self.pair.sign(&SystemRandom::new(), &message).unwrap();
            json!({
                "id": b64url(&self.id), "rawId": b64url(&self.id), "type": "public-key",
                "response": {
                    "clientDataJSON": b64url(client.as_bytes()),
                    "authenticatorData": b64url(&auth),
                    "signature": b64url(sig.as_ref()),
                },
            })
        }
    }

    #[test]
    fn registers_and_signs_in_with_a_soft_authenticator() {
        let mut soft = Soft::new();
        let created = CredentialResponse::parse(Some(&soft.create("abc", "http://localhost:3000"))).unwrap();
        assert_eq!(created.challenge().as_deref(), Some("abc"));
        let registered = verify_registration(&rp(), &created, "abc").unwrap();
        assert_eq!(registered.credential_id, b64url(&soft.id));
        assert_eq!(registered.transports, ["internal"]);
        assert_eq!(registered.device_type, "singleDevice");

        let assertion = CredentialResponse::parse(Some(&soft.get("xyz"))).unwrap();
        let stored = StoredPasskey {
            credential_id: &registered.credential_id,
            public_key: &registered.public_key,
            sign_count: 0,
        };
        assert_eq!(verify_authentication(&rp(), &assertion, "xyz", &stored).unwrap().sign_count, 1);
        assert!(verify_authentication(&rp(), &assertion, "other", &stored).is_err());
        let replayed = StoredPasskey { sign_count: 5, ..stored };
        assert_eq!(verify_authentication(&rp(), &assertion, "xyz", &replayed).err(), Some(PasskeyError::Counter));
    }

    #[test]
    fn refuses_another_origin() {
        let soft = Soft::new();
        let phished = CredentialResponse::parse(Some(&soft.create("abc", "https://handstamp-login.evil"))).unwrap();
        assert!(verify_registration(&rp(), &phished, "abc").is_err());
    }

    #[test]
    fn options_match_simplewebauthn() {
        let user = PasskeyUser { handle: "aGFuZGxl", display_name: "Ada", email: None, username: None };
        let options = registration_options(&rp(), &user, &[]);
        assert_eq!(options["user"]["id"], "aGFuZGxl");
        assert_eq!(options["user"]["name"], "Ada (localhost)");
        assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
        assert_eq!(options["authenticatorSelection"]["userVerification"], "required");
        assert_eq!(b64url_decode(options["challenge"].as_str().unwrap()).unwrap().len(), 32);
        assert_eq!(authentication_options(&rp())["userVerification"], "required");
    }
}
