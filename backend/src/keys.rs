//! Signing keys in the same rows and format as apps/server/src/keys.ts: RS256, kid = RFC 7638
//! thumbprint, private JWK sealed with the signing-keys subkey and the kid as AAD.

use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use deadpool_postgres::Pool;
use rsa::{
    RsaPrivateKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::crypto::{self, Purpose};

const ALG: &str = "RS256";

fn b64(n: &rsa::BigUint) -> String {
    B64.encode(n.to_bytes_be())
}

pub fn thumbprint(e: &str, n: &str) -> String {
    // Members in lexicographic order, no whitespace (RFC 7638 §3).
    let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    B64.encode(Sha256::digest(canonical.as_bytes()))
}

pub struct GeneratedKey {
    pub kid: String,
    pub private_jwk: Value,
    pub public_jwk: Value,
}

pub fn generate() -> Result<GeneratedKey> {
    let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)?;
    let primes = key.primes();
    let (n, e) = (b64(key.n()), b64(key.e()));
    let kid = thumbprint(&e, &n);
    let dp = key.dp().map(b64).unwrap_or_default();
    let dq = key.dq().map(b64).unwrap_or_default();
    let qi = key.crt_coefficient().map(|c| b64(&c)).unwrap_or_default();
    let private_jwk = json!({
        "kty": "RSA", "n": n, "e": e, "d": b64(key.d()), "p": b64(&primes[0]), "q": b64(&primes[1]),
        "dp": dp, "dq": dq, "qi": qi, "kid": kid, "alg": ALG, "use": "sig",
    });
    let public_jwk = json!({ "kty": "RSA", "n": n, "e": e, "kid": kid, "alg": ALG, "use": "sig" });
    Ok(GeneratedKey {
        kid,
        private_jwk,
        public_jwk,
    })
}

pub struct Keys {
    pool: Pool,
    signing_key: [u8; 32],
}

impl Keys {
    pub fn new(pool: Pool, root: &[u8]) -> Self {
        Self {
            pool,
            signing_key: crypto::derive_key(root, Purpose::SigningKeys),
        }
    }

    // First boot: nobody has cached a JWKS yet, so the first key can sign immediately.
    pub async fn ensure_active(&self) -> Result<Option<String>> {
        let client = self.pool.get().await?;
        let active = client
            .query_opt(
                "SELECT kid FROM signing_keys WHERE alg = $1 AND state = 'active'",
                &[&ALG],
            )
            .await?;
        if active.is_some() {
            return Ok(None);
        }
        let key = tokio::task::spawn_blocking(generate).await??;
        let sealed = crypto::seal(&self.signing_key, key.private_jwk.to_string().as_bytes(), &key.kid);
        let inserted = client
            .execute(
                "INSERT INTO signing_keys (kid, alg, private_jwk_enc, public_jwk, state, activated_at) \
                 VALUES ($1, $2, $3, $4, 'active', now()) ON CONFLICT DO NOTHING",
                &[&key.kid, &ALG, &sealed, &key.public_jwk],
            )
            .await?;
        Ok((inserted == 1).then_some(key.kid))
    }

    // Published keys, in the order oidc-provider uses: active, staged, retiring; oldest first.
    pub async fn public_jwks(&self) -> Result<Value> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT public_jwk FROM signing_keys WHERE state IN ('active', 'staged', 'retiring') \
                 ORDER BY array_position(ARRAY['active', 'staged', 'retiring'], state), created_at",
                &[],
            )
            .await?;
        Ok(json!({ "keys": rows.iter().map(|row| row.get::<_, Value>(0)).collect::<Vec<_>>() }))
    }

    // Proves the sealed private keys written by either runtime open here. Signing comes later.
    pub async fn open_active(&self) -> Result<Value> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "SELECT kid, private_jwk_enc FROM signing_keys WHERE alg = $1 AND state = 'active'",
                &[&ALG],
            )
            .await?;
        let (kid, sealed): (String, Vec<u8>) = (row.get(0), row.get(1));
        Ok(serde_json::from_slice(&crypto::open(
            &self.signing_key,
            &sealed,
            &kid,
        )?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_match_node_format() {
        let key = generate().unwrap();
        assert_eq!(key.public_jwk["kid"], key.kid);
        assert_eq!(
            key.kid,
            thumbprint(
                key.public_jwk["e"].as_str().unwrap(),
                key.public_jwk["n"].as_str().unwrap()
            )
        );
        assert_eq!(key.public_jwk["e"], "AQAB");
        for member in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(!key.private_jwk[member].as_str().unwrap().is_empty(), "{member}");
            assert!(
                key.public_jwk.get(member).is_none(),
                "{member} leaked into the public JWK"
            );
        }
    }

    #[test]
    fn thumbprint_matches_rfc7638_example() {
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        assert_eq!(thumbprint("AQAB", n), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }
}
