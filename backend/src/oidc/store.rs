//! Protocol state in `oidc_payloads`: one generic table with extracted columns for the lookups the
//! provider and the console need. Kinds are lowercase (`session`, `grant`, `code`, …) so rows the
//! Node server left behind (`Session`, `Grant`, …) are simply never read and expire on their own.
//! Codes and tokens are stored under the SHA-256 of their value, never the value itself.

use anyhow::Result;
use chrono::Utc;
use deadpool_postgres::{GenericClient, Pool};
use serde::{Serialize, de::DeserializeOwned};

use crate::crypto::{b64url, sha256};

pub const SESSION: &str = "session";
pub const INTERACTION: &str = "interaction";
pub const GRANT: &str = "grant";
pub const CODE: &str = "code";
pub const ACCESS_TOKEN: &str = "access_token";
pub const REFRESH_TOKEN: &str = "refresh_token";

/// The storage key for a bearer value (code, access token, refresh token).
pub fn token_id(value: &str) -> String {
    b64url(&sha256(value.as_bytes()))
}

pub fn now() -> i64 {
    Utc::now().timestamp()
}

#[derive(Default)]
pub struct Columns<'a> {
    pub uid: Option<&'a str>,
    pub grant_id: Option<&'a str>,
    pub account_id: Option<&'a str>,
}

pub struct Found<T> {
    pub value: T,
    pub consumed: bool,
}

#[derive(Clone)]
pub struct Store {
    pool: Pool,
}

impl Store {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub async fn save<T: Serialize>(&self, kind: &str, id: &str, value: &T, columns: Columns<'_>, exp: i64) -> Result<()> {
        let db = self.pool.get().await?;
        save(&db, kind, id, value, columns, exp).await
    }

    /// Live rows only (unexpired). Rows that no longer parse are treated as missing.
    pub async fn find<T: DeserializeOwned>(&self, kind: &str, id: &str) -> Result<Option<Found<T>>> {
        let db = self.pool.get().await?;
        let row = db
            .query_opt(
                "SELECT payload, consumed_at IS NOT NULL FROM oidc_payloads \
                 WHERE kind = $1 AND id = $2 AND (expires_at IS NULL OR expires_at > now())",
                &[&kind, &id],
            )
            .await?;
        Ok(row.and_then(|r| {
            let consumed = r.get(1);
            serde_json::from_value(r.get(0)).ok().map(|value| Found { value, consumed })
        }))
    }

    pub async fn find_by_uid<T: DeserializeOwned>(&self, kind: &str, uid: &str) -> Result<Option<(String, T)>> {
        let db = self.pool.get().await?;
        let row = db
            .query_opt(
                "SELECT id, payload FROM oidc_payloads \
                 WHERE kind = $1 AND uid = $2 AND (expires_at IS NULL OR expires_at > now()) LIMIT 1",
                &[&kind, &uid],
            )
            .await?;
        Ok(row.and_then(|r| serde_json::from_value(r.get(1)).ok().map(|v| (r.get(0), v))))
    }

    /// Marks a single-use row consumed. False when someone else got there first.
    pub async fn consume(&self, kind: &str, id: &str) -> Result<bool> {
        let db = self.pool.get().await?;
        Ok(db
            .execute(
                "UPDATE oidc_payloads SET consumed_at = now() WHERE kind = $1 AND id = $2 AND consumed_at IS NULL",
                &[&kind, &id],
            )
            .await?
            > 0)
    }

    pub async fn destroy(&self, kind: &str, id: &str) -> Result<()> {
        let db = self.pool.get().await?;
        db.execute("DELETE FROM oidc_payloads WHERE kind = $1 AND id = $2", &[&kind, &id]).await?;
        Ok(())
    }

    /// Everything issued under a grant, and the grant itself (its grant_id column is its own id).
    pub async fn revoke_grant(&self, grant_id: &str) -> Result<()> {
        let db = self.pool.get().await?;
        revoke_grant(&db, grant_id).await
    }
}

pub async fn save<T: Serialize>(
    db: &impl GenericClient,
    kind: &str,
    id: &str,
    value: &T,
    columns: Columns<'_>,
    exp: i64,
) -> Result<()> {
    let payload = serde_json::to_value(value)?;
    let exp = exp as f64;
    db.execute(
        "INSERT INTO oidc_payloads (kind, id, payload, uid, grant_id, account_id, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7)) \
         ON CONFLICT (kind, id) DO UPDATE SET payload = $3, uid = $4, grant_id = $5, account_id = $6, expires_at = to_timestamp($7)",
        &[&kind, &id, &payload, &columns.uid, &columns.grant_id, &columns.account_id, &exp],
    )
    .await?;
    Ok(())
}

pub async fn revoke_grant(db: &impl GenericClient, grant_id: &str) -> Result<()> {
    db.execute("DELETE FROM oidc_payloads WHERE grant_id = $1", &[&grant_id]).await?;
    Ok(())
}

pub async fn delete_expired(pool: &Pool) -> Result<u64> {
    let db = pool.get().await?;
    let mut removed = db.execute("DELETE FROM oidc_payloads WHERE expires_at < now()", &[]).await?;
    removed += db.execute("DELETE FROM webauthn_challenges WHERE expires_at < now() - interval '1 day'", &[]).await?;
    Ok(removed)
}
