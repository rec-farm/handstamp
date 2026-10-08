//! Linked upstream identities. Identity is (issuer, subject); never the email (S13).

use anyhow::Result;
use deadpool_postgres::{GenericClient, Pool};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    accounts,
    audit::{Actor, Entry},
    db::{iso, iso_opt},
    passkeys::LastMethod,
    upstream::providers::{Provider, UpstreamIdentity},
};

#[derive(Debug, thiserror::Error)]
#[error("this identity belongs to another account")]
pub struct IdentityTaken;

pub struct Linked {
    pub id: Uuid,
    pub user_id: Uuid,
}

pub struct Identities {
    pool: Pool,
}

impl Identities {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// The only lookup used for sign-in: (issuer, subject).
    pub async fn find(&self, issuer: &str, subject: &str) -> Result<Option<Linked>> {
        let db = self.pool.get().await?;
        Ok(db
            .query_opt("SELECT id, user_id FROM identities WHERE issuer = $1 AND subject = $2", &[&issuer, &subject])
            .await?
            .map(|r| Linked { id: r.get(0), user_id: r.get(1) }))
    }

    pub async fn list_for_user(&self, user: Uuid) -> Result<Vec<Value>> {
        let db = self.pool.get().await?;
        Ok(db
            .query(
                "SELECT i.id, p.slug, p.display_name, i.login_hint, i.email::text, i.linked_at, i.last_used_at \
                 FROM identities i JOIN upstream_providers p ON p.id = i.provider_id \
                 WHERE i.user_id = $1 ORDER BY i.linked_at",
                &[&user],
            )
            .await?
            .iter()
            .map(|r| {
                json!({
                    "id": r.get::<_, Uuid>(0),
                    "provider": r.get::<_, String>(1),
                    "providerName": r.get::<_, String>(2),
                    "loginHint": r.get::<_, Option<String>>(3),
                    "email": r.get::<_, Option<String>>(4),
                    "linkedAt": iso(r.get(5)),
                    "lastUsedAt": iso_opt(r.get(6)),
                })
            })
            .collect())
    }

    pub async fn touch(&self, id: Uuid, identity: &UpstreamIdentity) -> Result<()> {
        let db = self.pool.get().await?;
        db.execute(
            "UPDATE identities SET last_used_at = now(), email = $2, email_verified = $3, login_hint = $4 WHERE id = $1",
            &[&id, &identity.email, &identity.email_verified, &identity.login_hint],
        )
        .await?;
        Ok(())
    }

    pub async fn unlink(&self, user: Uuid, id: Uuid) -> Result<bool> {
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        accounts::lock_user(&tx, user).await?;
        if tx.query_opt("SELECT id FROM identities WHERE id = $1 AND user_id = $2", &[&id, &user]).await?.is_none() {
            return Ok(false);
        }
        if accounts::sign_in_method_count(&tx, user).await? <= 1 {
            return Err(LastMethod.into());
        }
        tx.execute("UPDATE users SET email_identity_id = NULL WHERE email_identity_id = $1", &[&id]).await?;
        tx.execute("DELETE FROM identities WHERE id = $1", &[&id]).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// A new person arriving through an upstream provider (sign-up allowed, or an invite). Their
    /// email is only kept when it's trustworthy and no other user already holds it verified, so a
    /// relying party keyed on email can never see two people with one address (§2.1).
    pub async fn create_user(&self, provider: &Provider, identity: &UpstreamIdentity, via: &str) -> Result<Uuid> {
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        let email = provider.trusted_email(identity);
        let holder: Option<Uuid> = match &email {
            Some(email) => tx
                .query_opt("SELECT id FROM users WHERE lower(email) = $1 AND email_verified", &[email])
                .await?
                .map(|r| r.get(0)),
            None => None,
        };
        let display_name = identity
            .name
            .clone()
            .filter(|n| !n.is_empty())
            .or_else(|| identity.login_hint.clone().filter(|h| !h.is_empty()))
            .or_else(|| email.as_ref().and_then(|e| e.split('@').next().map(str::to_string)))
            .unwrap_or_else(|| "New user".into());
        let kept = if holder.is_some() { None } else { email.clone() };
        let user: Uuid = tx
            .query_one(
                "INSERT INTO users (display_name, email, email_verified) VALUES ($1, $2, $3) RETURNING id",
                &[&display_name, &kept, &kept.is_some()],
            )
            .await?
            .get(0);
        let identity_id = link(&tx, user, provider, identity).await?;
        if kept.is_some() {
            tx.execute("UPDATE users SET email_identity_id = $2 WHERE id = $1", &[&user, &identity_id]).await?;
        }
        Entry::new("user.created", Actor::User)
            .by(Some(user))
            .target("user", user)
            .meta(json!({ "via": via, "provider": provider.slug }))
            .write(&tx)
            .await?;
        if let Some(holder) = holder {
            Entry::new("user.email_conflict", Actor::System)
                .target("user", user)
                .meta(json!({ "provider": provider.slug, "held_by": holder.to_string() }))
                .write(&tx)
                .await?;
        }
        tx.commit().await?;
        Ok(user)
    }

    pub async fn link(&self, user: Uuid, provider: &Provider, identity: &UpstreamIdentity) -> Result<Uuid> {
        link(&self.pool.get().await?, user, provider, identity).await
    }
}

pub async fn link(db: &impl GenericClient, user: Uuid, provider: &Provider, identity: &UpstreamIdentity) -> Result<Uuid> {
    if let Some(existing) = db
        .query_opt("SELECT id, user_id FROM identities WHERE issuer = $1 AND subject = $2", &[&identity.issuer, &identity.subject])
        .await?
    {
        if existing.get::<_, Uuid>(1) != user {
            return Err(IdentityTaken.into());
        }
        return Ok(existing.get(0));
    }
    let row = db
        .query_opt(
            "INSERT INTO identities (user_id, provider_id, issuer, subject, email, email_verified, login_hint, last_used_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, now()) ON CONFLICT DO NOTHING RETURNING id",
            &[
                &user,
                &provider.id,
                &identity.issuer,
                &identity.subject,
                &identity.email,
                &identity.email_verified,
                &identity.login_hint,
            ],
        )
        .await?;
    // Lost a race to another account.
    row.map(|r| r.get(0)).ok_or_else(|| IdentityTaken.into())
}
