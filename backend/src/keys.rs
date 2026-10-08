//! Signing keys: RS256, kid = RFC 7638 thumbprint, private JWK sealed with the signing-keys subkey
//! and the kid as AAD. Lifecycle: staged (published, not signing) → active (signs) → retiring
//! (published) → retired (private key wiped).
//!
//! Every process reads the published set from Postgres. A cheap fingerprint query per use picks up
//! changes made by the scheduler, the CLI or another replica immediately.

use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeyPair, KeySize},
    signature::{self, RsaPublicKeyComponents},
};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use rsa::{
    BigUint, RsaPrivateKey,
    pkcs1::EncodeRsaPrivateKey,
    pkcs8::DecodePrivateKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use serde_json::{Map, Value, json};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    audit::{Actor, Entry},
    config::RotationPolicy,
    crypto::{self, Purpose, b64url, b64url_decode},
};

pub const ALG: &str = "RS256";

fn b64(n: &BigUint) -> String {
    b64url(&n.to_bytes_be())
}

/// RFC 7638 §3: required members in lexicographic order, no whitespace.
pub fn thumbprint(e: &str, n: &str) -> String {
    b64url(&crypto::sha256(format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)))
}

pub struct GeneratedKey {
    pub kid: String,
    pub private_jwk: Value,
    pub public_jwk: Value,
}

pub fn generate() -> Result<GeneratedKey> {
    let pair = KeyPair::generate(KeySize::Rsa2048).map_err(|_| anyhow!("RSA key generation failed"))?;
    let der = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&pair).map_err(|_| anyhow!("RSA export failed"))?;
    let key = RsaPrivateKey::from_pkcs8_der(der.as_ref())?;
    let primes = key.primes();
    let (n, e) = (b64(key.n()), b64(key.e()));
    let kid = thumbprint(&e, &n);
    let private_jwk = json!({
        "kty": "RSA",
        "n": n,
        "e": e,
        "d": b64(key.d()),
        "p": b64(&primes[0]),
        "q": b64(&primes[1]),
        "dp": key.dp().map(b64).unwrap_or_default(),
        "dq": key.dq().map(b64).unwrap_or_default(),
        "qi": key.crt_coefficient().map(|c| b64(&c)).unwrap_or_default(),
        "kid": kid,
        "alg": ALG,
        "use": "sig",
    });
    let public_jwk = json!({ "kty": "RSA", "n": n, "e": e, "kid": kid, "alg": ALG, "use": "sig" });
    Ok(GeneratedKey { kid, private_jwk, public_jwk })
}

fn jwk_int(jwk: &Value, member: &str) -> Result<BigUint> {
    let raw = jwk[member].as_str().ok_or_else(|| anyhow!("JWK is missing {member}"))?;
    Ok(BigUint::from_bytes_be(&b64url_decode(raw).ok_or_else(|| anyhow!("JWK {member} is not base64url"))?))
}

/// A private JWK as an aws-lc key pair (signing goes through aws-lc, not the `rsa` crate).
fn key_pair(jwk: &Value) -> Result<KeyPair> {
    let key = RsaPrivateKey::from_components(
        jwk_int(jwk, "n")?,
        jwk_int(jwk, "e")?,
        jwk_int(jwk, "d")?,
        vec![jwk_int(jwk, "p")?, jwk_int(jwk, "q")?],
    )?;
    let der = key.to_pkcs1_der()?;
    KeyPair::from_der(der.as_bytes()).map_err(|e| anyhow!("unusable RSA key: {e}"))
}

pub struct Signer {
    pub kid: String,
    pair: KeyPair,
}

impl Signer {
    pub fn sign(&self, header: &Value, payload: &Value) -> Result<String> {
        let input = format!(
            "{}.{}",
            b64url(serde_json::to_string(header)?.as_bytes()),
            b64url(serde_json::to_string(payload)?.as_bytes())
        );
        let mut signature = vec![0u8; self.pair.public_modulus_len()];
        self.pair
            .sign(&signature::RSA_PKCS1_SHA256, &aws_lc_rs::rand::SystemRandom::new(), input.as_bytes(), &mut signature)
            .map_err(|_| anyhow!("signing failed"))?;
        Ok(format!("{input}.{}", b64url(&signature)))
    }
}

/// The published key set and the signer, as of one fingerprint.
pub struct Snapshot {
    pub fingerprint: String,
    pub jwks: Value,
    pub signer: Option<Arc<Signer>>,
    verifiers: HashMap<String, (Vec<u8>, Vec<u8>)>,
}

impl Snapshot {
    /// Verifies an RS256 JWT signed by any published key. Returns header and payload.
    pub fn verify(&self, jwt: &str) -> Result<(Value, Map<String, Value>)> {
        let mut parts = jwt.split('.');
        let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            bail!("not a JWS");
        };
        let header: Value = serde_json::from_slice(&b64url_decode(h).context("header")?)?;
        if header["alg"] != ALG {
            bail!("unexpected alg");
        }
        let kid = header["kid"].as_str().unwrap_or_default();
        let (n, e) = self.verifiers.get(kid).ok_or_else(|| anyhow!("unknown kid"))?;
        RsaPublicKeyComponents { n, e }
            .verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                format!("{h}.{p}").as_bytes(),
                &b64url_decode(s).context("signature")?,
            )
            .map_err(|_| anyhow!("signature mismatch"))?;
        let payload: Map<String, Value> = serde_json::from_slice(&b64url_decode(p).context("payload")?)?;
        Ok((header, payload))
    }
}

pub struct Keys {
    pool: Pool,
    signing_key: [u8; 32],
    cache: RwLock<Option<Arc<Snapshot>>>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub kid: String,
    pub alg: String,
    pub state: String,
    #[serde(serialize_with = "ser_iso")]
    pub created_at: DateTime<Utc>,
    #[serde(serialize_with = "ser_iso_opt")]
    pub activated_at: Option<DateTime<Utc>>,
    #[serde(serialize_with = "ser_iso_opt")]
    pub retire_after: Option<DateTime<Utc>>,
}

fn ser_iso<S: serde::Serializer>(at: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&crate::db::iso(*at))
}
fn ser_iso_opt<S: serde::Serializer>(at: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
    match at {
        Some(at) => s.serialize_str(&crate::db::iso(*at)),
        None => s.serialize_none(),
    }
}

const PUBLISHED: &str = "SELECT kid, state, public_jwk, private_jwk_enc FROM signing_keys \
     WHERE state IN ('active', 'staged', 'retiring') \
     ORDER BY array_position(ARRAY['active', 'staged', 'retiring'], state), created_at";

impl Keys {
    pub fn new(pool: Pool, root: &[u8]) -> Self {
        Self { pool, signing_key: crypto::derive_key(root, Purpose::SigningKeys), cache: RwLock::new(None) }
    }

    async fn insert(&self, state: &str) -> Result<String> {
        let key = tokio::task::spawn_blocking(generate).await??;
        let sealed = crypto::seal(&self.signing_key, key.private_jwk.to_string().as_bytes(), &key.kid);
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO signing_keys (kid, alg, private_jwk_enc, public_jwk, state, activated_at) \
                 VALUES ($1, $2, $3, $4, $5, CASE WHEN $5 = 'active' THEN now() END)",
                &[&key.kid, &ALG, &sealed, &key.public_jwk, &state],
            )
            .await?;
        Ok(key.kid)
    }

    /// First boot: nobody has cached a JWKS yet, so the first key can sign immediately.
    pub async fn ensure(&self) -> Result<Option<String>> {
        let client = self.pool.get().await?;
        let active =
            client.query_opt("SELECT kid FROM signing_keys WHERE alg = $1 AND state = 'active'", &[&ALG]).await?;
        drop(client);
        if active.is_some() {
            return Ok(None);
        }
        let kid = self.insert("active").await?;
        Entry::new("key.activated", Actor::System).target("signing_key", &kid).write(&self.pool.get().await?).await?;
        Ok(Some(kid))
    }

    pub async fn stage(&self, actor: Actor, user: Option<Uuid>) -> Result<String> {
        let kid = self.insert("staged").await?;
        Entry::new("key.staged", actor).by(user).target("signing_key", &kid).write(&self.pool.get().await?).await?;
        Ok(kid)
    }

    /// Promotes the oldest staged key; the previous active key stays published until retire_after.
    pub async fn promote(&self, policy: &RotationPolicy, actor: Actor, user: Option<Uuid>) -> Result<Option<String>> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let staged = tx
            .query_opt(
                "SELECT kid FROM signing_keys WHERE alg = $1 AND state = 'staged' ORDER BY created_at LIMIT 1 FOR UPDATE",
                &[&ALG],
            )
            .await?;
        let Some(staged) = staged else { return Ok(None) };
        let kid: String = staged.get(0);
        let retire = policy.retire_after_seconds as f64;
        tx.execute(
            "UPDATE signing_keys SET state = 'retiring', retire_after = now() + make_interval(secs => $2) \
             WHERE alg = $1 AND state = 'active'",
            &[&ALG, &retire],
        )
        .await?;
        tx.execute("UPDATE signing_keys SET state = 'active', activated_at = now() WHERE kid = $1", &[&kid]).await?;
        Entry::new("key.activated", actor).by(user).target("signing_key", &kid).write(&tx).await?;
        tx.commit().await?;
        Ok(Some(kid))
    }

    /// Scheduled transitions. Returns true when the published key set changed.
    pub async fn tick(&self, policy: &RotationPolicy) -> Result<bool> {
        let mut changed = false;
        let client = self.pool.get().await?;
        let retired = client
            .query(
                "UPDATE signing_keys SET state = 'retired', retired_at = now(), private_jwk_enc = NULL \
                 WHERE state = 'retiring' AND retire_after <= now() RETURNING kid",
                &[],
            )
            .await?;
        for row in &retired {
            let kid: String = row.get(0);
            Entry::new("key.retired", Actor::System).target("signing_key", kid).write(&client).await?;
            changed = true;
        }
        let stage_hours = policy.stage_hours as i32;
        let ready = client
            .query_opt(
                "SELECT kid FROM signing_keys WHERE state = 'staged' \
                 AND created_at <= now() - make_interval(hours => $1) LIMIT 1",
                &[&stage_hours],
            )
            .await?;
        drop(client);
        if ready.is_some() && self.promote(policy, Actor::System, None).await?.is_some() {
            changed = true;
        }
        if policy.rotation_days > 0 {
            let client = self.pool.get().await?;
            let days = policy.rotation_days as i32;
            let due = client
                .query_opt(
                    "SELECT kid FROM signing_keys WHERE state = 'active' \
                     AND activated_at <= now() - make_interval(days => $1)",
                    &[&days],
                )
                .await?;
            let pending = client.query_opt("SELECT kid FROM signing_keys WHERE state = 'staged' LIMIT 1", &[]).await?;
            drop(client);
            if due.is_some() && pending.is_none() {
                self.stage(Actor::System, None).await?;
                changed = true;
            }
        }
        Ok(changed)
    }

    pub async fn list(&self) -> Result<Vec<KeyInfo>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT kid, alg, state, created_at, activated_at, retire_after FROM signing_keys ORDER BY created_at",
                &[],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| KeyInfo {
                kid: r.get(0),
                alg: r.get(1),
                state: r.get(2),
                created_at: r.get(3),
                activated_at: r.get(4),
                retire_after: r.get(5),
            })
            .collect())
    }

    /// The current published set and signer. Rebuilt only when the fingerprint changes.
    pub async fn snapshot(&self) -> Result<Arc<Snapshot>> {
        let client = self.pool.get().await?;
        let states = client
            .query(
                "SELECT kid, state FROM signing_keys WHERE state IN ('active', 'staged', 'retiring') \
                 ORDER BY array_position(ARRAY['active', 'staged', 'retiring'], state), created_at",
                &[],
            )
            .await?;
        let fingerprint = states
            .iter()
            .map(|r| format!("{}:{}", r.get::<_, String>(0), r.get::<_, String>(1)))
            .collect::<Vec<_>>()
            .join(",");
        if let Some(cached) = self.cache.read().await.as_ref()
            && cached.fingerprint == fingerprint
        {
            return Ok(cached.clone());
        }
        let rows = client.query(PUBLISHED, &[]).await?;
        let mut keys = Vec::new();
        let mut verifiers = HashMap::new();
        let mut signer = None;
        for row in &rows {
            let (kid, state, public_jwk): (String, String, Value) = (row.get(0), row.get(1), row.get(2));
            let n = b64url_decode(public_jwk["n"].as_str().unwrap_or_default()).unwrap_or_default();
            let e = b64url_decode(public_jwk["e"].as_str().unwrap_or_default()).unwrap_or_default();
            verifiers.insert(kid.clone(), (n, e));
            if state == "active" && signer.is_none() {
                let sealed: Vec<u8> = row.get(3);
                let jwk: Value = serde_json::from_slice(&crypto::open(&self.signing_key, &sealed, &kid)?)?;
                let pair = tokio::task::spawn_blocking(move || key_pair(&jwk)).await??;
                signer = Some(Arc::new(Signer { kid: kid.clone(), pair }));
            }
            keys.push(public_jwk);
        }
        let snapshot = Arc::new(Snapshot { fingerprint, jwks: json!({ "keys": keys }), signer, verifiers });
        *self.cache.write().await = Some(snapshot.clone());
        Ok(snapshot)
    }

    pub async fn signer(&self) -> Result<Arc<Signer>> {
        self.snapshot().await?.signer.clone().ok_or_else(|| anyhow!("no active signing key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_sign_and_verify_like_node_wrote_them() {
        let key = generate().unwrap();
        assert_eq!(key.public_jwk["kid"], key.kid);
        assert_eq!(
            key.kid,
            thumbprint(key.public_jwk["e"].as_str().unwrap(), key.public_jwk["n"].as_str().unwrap())
        );
        for member in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(!key.private_jwk[member].as_str().unwrap().is_empty(), "{member}");
            assert!(key.public_jwk.get(member).is_none(), "{member} leaked into the public JWK");
        }
        let signer = Signer { kid: key.kid.clone(), pair: key_pair(&key.private_jwk).unwrap() };
        let jwt = signer.sign(&json!({ "alg": ALG, "kid": key.kid }), &json!({ "sub": "x" })).unwrap();
        let n = b64url_decode(key.public_jwk["n"].as_str().unwrap()).unwrap();
        let e = b64url_decode(key.public_jwk["e"].as_str().unwrap()).unwrap();
        let snapshot = Snapshot {
            fingerprint: String::new(),
            jwks: json!({}),
            signer: None,
            verifiers: HashMap::from([(key.kid.clone(), (n, e))]),
        };
        let (_, payload) = snapshot.verify(&jwt).unwrap();
        assert_eq!(payload["sub"], "x");
        let tampered = format!("{}x", &jwt[..jwt.len() - 1]);
        assert!(snapshot.verify(&tampered).is_err());
    }

    #[test]
    fn thumbprint_matches_rfc7638_example() {
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        assert_eq!(thumbprint("AQAB", n), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }
}
