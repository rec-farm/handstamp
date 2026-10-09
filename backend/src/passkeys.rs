//! Storage for passkeys and their single-use WebAuthn challenges.

use anyhow::Result;
use chrono::{DateTime, Utc};
use deadpool_postgres::{GenericClient, Pool};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    accounts,
    db::{iso, iso_opt},
    webauthn::{CHALLENGE_TTL_SECONDS, Existing, PasskeyError, VerifiedRegistration},
};

pub struct Passkey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub backed_up: bool,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

const COLUMNS: &str =
    "id, user_id, credential_id, public_key, sign_count, transports, backed_up, name, created_at, last_used_at";

fn row(r: &tokio_postgres::Row) -> Passkey {
    Passkey {
        id: r.get(0),
        user_id: r.get(1),
        credential_id: r.get(2),
        public_key: r.get(3),
        sign_count: r.get(4),
        transports: r.get(5),
        backed_up: r.get(6),
        name: r.get(7),
        created_at: r.get(8),
        last_used_at: r.get(9),
    }
}

impl Passkey {
    pub fn view(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "createdAt": iso(self.created_at),
            "lastUsedAt": iso_opt(self.last_used_at),
            "synced": self.backed_up,
        })
    }
}

pub struct Challenge {
    pub user_id: Option<Uuid>,
    pub pending: Value,
}

#[derive(Debug, thiserror::Error)]
#[error("this is the last way to sign in")]
pub struct LastMethod;

pub struct Passkeys {
    pool: Pool,
}

impl Passkeys {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub async fn save_challenge(
        &self,
        purpose: &str,
        binding: &str,
        challenge: &str,
        user_id: Option<Uuid>,
        pending: Value,
    ) -> Result<()> {
        let db = self.pool.get().await?;
        db.execute(
            "INSERT INTO webauthn_challenges (purpose, binding, challenge, user_id, pending, expires_at) \
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
            &[
                &purpose,
                &binding,
                &challenge,
                &user_id,
                &pending,
                &(CHALLENGE_TTL_SECONDS as f64),
            ],
        )
        .await?;
        Ok(())
    }

    /// Single use: the first caller gets the row, everyone after gets nothing.
    pub async fn consume_challenge(&self, purpose: &str, binding: &str, challenge: &str) -> Result<Option<Challenge>> {
        let db = self.pool.get().await?;
        let row = db
            .query_opt(
                "UPDATE webauthn_challenges SET consumed_at = now() \
                 WHERE challenge = $1 AND purpose = $2 AND binding = $3 AND consumed_at IS NULL AND expires_at > now() \
                 RETURNING user_id, pending",
                &[&challenge, &purpose, &binding],
            )
            .await?;
        Ok(row.map(|r| Challenge {
            user_id: r.get(0),
            pending: r.get(1),
        }))
    }

    pub async fn find_by_credential_id(&self, credential_id: &str) -> Result<Option<Passkey>> {
        let db = self.pool.get().await?;
        Ok(db
            .query_opt(
                &format!("SELECT {COLUMNS} FROM passkeys WHERE credential_id = $1"),
                &[&credential_id],
            )
            .await?
            .as_ref()
            .map(row))
    }

    pub async fn list_for_user(&self, user: Uuid) -> Result<Vec<Passkey>> {
        let db = self.pool.get().await?;
        Ok(db
            .query(
                &format!("SELECT {COLUMNS} FROM passkeys WHERE user_id = $1 ORDER BY created_at"),
                &[&user],
            )
            .await?
            .iter()
            .map(row)
            .collect())
    }

    pub async fn existing(&self, user: Uuid) -> Result<Vec<Existing>> {
        Ok(self
            .list_for_user(user)
            .await?
            .into_iter()
            .map(|p| Existing {
                credential_id: p.credential_id,
                transports: p.transports,
            })
            .collect())
    }

    pub async fn record_use(&self, id: Uuid, sign_count: i64, backed_up: bool) -> Result<()> {
        let db = self.pool.get().await?;
        db.execute(
            "UPDATE passkeys SET sign_count = $2, backed_up = $3, last_used_at = now() WHERE id = $1",
            &[&id, &sign_count, &backed_up],
        )
        .await?;
        Ok(())
    }

    pub async fn rename(&self, user: Uuid, id: Uuid, name: &str) -> Result<bool> {
        let db = self.pool.get().await?;
        Ok(db
            .execute(
                "UPDATE passkeys SET name = $3 WHERE id = $1 AND user_id = $2",
                &[&id, &user, &name],
            )
            .await?
            > 0)
    }

    /// Nobody can remove their last way in: passkeys and linked identities both count.
    pub async fn remove(&self, user: Uuid, id: Uuid) -> Result<Option<String>> {
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        accounts::lock_user(&tx, user).await?;
        let Some(target) = tx
            .query_opt(
                "SELECT name FROM passkeys WHERE id = $1 AND user_id = $2",
                &[&id, &user],
            )
            .await?
        else {
            return Ok(None);
        };
        if accounts::sign_in_method_count(&tx, user).await? <= 1 {
            return Err(LastMethod.into());
        }
        tx.execute("DELETE FROM passkeys WHERE id = $1", &[&id]).await?;
        tx.commit().await?;
        Ok(Some(target.get(0)))
    }
}

pub async fn add(db: &impl GenericClient, user: Uuid, passkey: &VerifiedRegistration, name: &str) -> Result<Uuid> {
    Ok(db
        .query_one(
            "INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, transports, aaguid, device_type, backed_up, name) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
            &[
                &user,
                &passkey.credential_id,
                &passkey.public_key,
                &passkey.sign_count,
                &passkey.transports,
                &passkey.aaguid,
                &passkey.device_type,
                &passkey.backed_up,
                &name,
            ],
        )
        .await?
        .get(0))
}

pub fn clean_name(name: Option<&Value>, taken: &[String]) -> String {
    let trimmed: String = name
        .and_then(Value::as_str)
        .map(|n| {
            n.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(56)
                .collect()
        })
        .unwrap_or_default();
    let base = if trimmed.is_empty() {
        "Passkey".to_string()
    } else {
        trimmed
    };
    // Two "Passkey on Mac"s are indistinguishable on the account page; number the newcomer.
    let mut candidate = base.clone();
    let mut n = 2;
    while taken.contains(&candidate) {
        candidate = format!("{base} {n}");
        n += 1;
    }
    candidate
}

pub fn passkey_message(error: &PasskeyError) -> &'static str {
    match error {
        PasskeyError::Counter => {
            "This passkey looks like a copy of another one, so we stopped. Use a different passkey or ask your admin."
        }
        PasskeyError::Invalid(_) => "We couldn't verify that passkey. Try again, or use a different one.",
    }
}

pub fn new_user_handle() -> String {
    crate::crypto::random_token(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_and_numbers_names() {
        assert_eq!(clean_name(Some(&json!("  Backup   key ")), &[]), "Backup key");
        assert_eq!(clean_name(None, &[]), "Passkey");
        assert_eq!(
            clean_name(Some(&json!("Mac")), &["Mac".into(), "Mac 2".into()]),
            "Mac 3"
        );
        assert_eq!(clean_name(Some(&json!("x".repeat(80))), &[]).len(), 56);
    }
}
