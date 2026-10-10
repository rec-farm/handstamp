//! First-run setup (docs/PLAN.md §1.4 C) and one-time links (§3.2). Opening a link never signs
//! anyone in by itself: a new sign-in method must be created first.

use anyhow::Result;
use chrono::{DateTime, Utc};
use deadpool_postgres::{GenericClient, Pool};
use serde_json::json;
use uuid::Uuid;

use crate::{
    audit::{Actor, Entry},
    crypto::{hash_setup_code, new_setup_code, random_token, sha256},
    passkeys,
    webauthn::VerifiedRegistration,
};

pub const SETUP_CODE_MINUTES: i32 = 60;
pub const INVITE_DAYS: i32 = 7;
pub const RECOVERY_MINUTES: i32 = 30;

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("This Handstamp instance already has an admin.")]
    AlreadyClaimed,
    #[error("Enter the setup code from the server logs first.")]
    CodeRequired,
}

impl SetupError {
    pub fn code(&self) -> &'static str {
        match self {
            SetupError::AlreadyClaimed => "already_claimed",
            SetupError::CodeRequired => "code_required",
        }
    }
}

pub struct Profile {
    pub display_name: String,
    pub email: Option<String>,
    pub handle: String,
}

pub struct Setup {
    pool: Pool,
}

/// What first-run setup did at boot.
pub enum BootCode {
    Issued(String),
    /// Another process printed a code within SETUP_CODE_KEEP_SECONDS; it still works.
    Recent,
    Claimed,
}

impl BootCode {
    fn code(self) -> Option<String> {
        match self {
            BootCode::Issued(code) => Some(code),
            _ => None,
        }
    }
}

const SETUP_LOCK: i64 = 4_26_19_79;
const SETUP_CODE_KEEP_SECONDS: f64 = 30.0;

impl Setup {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub async fn claimed(&self) -> Result<bool> {
        let db = self.pool.get().await?;
        Ok(db
            .query_opt("SELECT setup_completed_at FROM instance_settings WHERE id = 1", &[])
            .await?
            .and_then(|r| r.get::<_, Option<DateTime<Utc>>>(0))
            .is_some())
    }

    /// A fresh code from the CLI until someone claims the instance. Earlier unused codes stop
    /// working.
    pub async fn issue_code(&self) -> Result<Option<String>> {
        Ok(self.issue(false).await?.code())
    }

    /// A fresh code on boot, unless another replica printed one moments ago: replicas that start
    /// together would otherwise each print a code and cancel the others' (R5).
    pub async fn issue_boot_code(&self) -> Result<BootCode> {
        self.issue(true).await
    }

    async fn issue(&self, keep_recent: bool) -> Result<BootCode> {
        if self.claimed().await? {
            return Ok(BootCode::Claimed);
        }
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&SETUP_LOCK]).await?;
        if keep_recent
            && tx
                .query_opt(
                    "SELECT 1 FROM enrollment_tokens WHERE purpose = 'setup' AND consumed_at IS NULL \
                     AND expires_at > now() AND created_at > now() - make_interval(secs => $1)",
                    &[&SETUP_CODE_KEEP_SECONDS],
                )
                .await?
                .is_some()
        {
            return Ok(BootCode::Recent);
        }
        let code = new_setup_code();
        tx.execute(
            "DELETE FROM enrollment_tokens WHERE purpose = 'setup' AND consumed_at IS NULL",
            &[],
        )
        .await?;
        tx.execute(
            "INSERT INTO enrollment_tokens (token_hash, purpose, expires_at) \
             VALUES ($1, 'setup', now() + make_interval(mins => $2))",
            &[&hash_setup_code(&code).to_vec(), &SETUP_CODE_MINUTES],
        )
        .await?;
        tx.commit().await?;
        Ok(BootCode::Issued(code))
    }

    /// Binds a valid code to the interaction that proved it. The lookup is by hash.
    pub async fn verify_code(&self, code: &str, interaction_uid: &str) -> Result<bool> {
        let db = self.pool.get().await?;
        Ok(db
            .execute(
                "UPDATE enrollment_tokens SET bound_to = $2 \
                 WHERE token_hash = $1 AND purpose = 'setup' AND consumed_at IS NULL AND expires_at > now()",
                &[&hash_setup_code(code).to_vec(), &interaction_uid],
            )
            .await?
            > 0)
    }

    pub async fn is_verified(&self, interaction_uid: &str) -> Result<bool> {
        let db = self.pool.get().await?;
        Ok(db
            .query_opt(
                "SELECT 1 FROM enrollment_tokens \
                 WHERE bound_to = $1 AND purpose = 'setup' AND consumed_at IS NULL AND expires_at > now()",
                &[&interaction_uid],
            )
            .await?
            .is_some())
    }

    /// Creates the first admin with their passkey, in one transaction.
    pub async fn claim(
        &self,
        interaction_uid: &str,
        profile: &Profile,
        passkey: &VerifiedRegistration,
        passkey_name: &str,
    ) -> Result<Uuid> {
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        // Serialises concurrent claims: only the first one sees an unclaimed instance.
        let settings = tx
            .query_one(
                "SELECT setup_completed_at FROM instance_settings WHERE id = 1 FOR UPDATE",
                &[],
            )
            .await?;
        if settings.get::<_, Option<DateTime<Utc>>>(0).is_some() {
            return Err(SetupError::AlreadyClaimed.into());
        }
        let token = tx
            .query_opt(
                "UPDATE enrollment_tokens SET consumed_at = now() \
                 WHERE bound_to = $1 AND purpose = 'setup' AND consumed_at IS NULL AND expires_at > now() RETURNING id",
                &[&interaction_uid],
            )
            .await?
            .ok_or(SetupError::CodeRequired)?;
        let token_id: Uuid = token.get(0);
        let email = profile.email.as_deref().filter(|e| !e.is_empty());
        let user: Uuid = tx
            .query_one(
                "INSERT INTO users (display_name, email, email_verified, is_admin, webauthn_user_handle) \
                 VALUES ($1, $2, false, true, $3) RETURNING id",
                &[&profile.display_name, &email, &profile.handle],
            )
            .await?
            .get(0);
        passkeys::add(&tx, user, passkey, passkey_name).await?;
        tx.execute(
            "UPDATE enrollment_tokens SET consumed_by_user_id = $2 WHERE id = $1",
            &[&token_id, &user],
        )
        .await?;
        tx.execute(
            "UPDATE instance_settings SET setup_completed_at = now(), updated_at = now() WHERE id = 1",
            &[],
        )
        .await?;
        Entry::new("instance.claimed", Actor::User)
            .by(Some(user))
            .target("user", user)
            .write(&tx)
            .await?;
        tx.commit().await?;
        Ok(user)
    }
}

#[derive(Clone)]
pub struct Enrollment {
    pub id: Uuid,
    pub purpose: String,
    pub user_id: Option<Uuid>,
    pub revoke_other_methods: bool,
}

fn token_hash(token: &str) -> Vec<u8> {
    sha256(format!("enroll:{}", token.trim())).to_vec()
}

pub struct Link {
    pub token: String,
    pub link: String,
}

pub struct Enrollments {
    pool: Pool,
    issuer: String,
}

const ENROLLMENT: &str = "SELECT id, purpose, user_id, revoke_other_methods FROM enrollment_tokens";

fn enrollment(r: &tokio_postgres::Row) -> Enrollment {
    Enrollment {
        id: r.get(0),
        purpose: r.get(1),
        user_id: r.get(2),
        revoke_other_methods: r.get(3),
    }
}

impl Enrollments {
    pub fn new(pool: Pool, issuer: String) -> Self {
        Self { pool, issuer }
    }

    /// The token rides in the fragment, so it never reaches server logs or Referer headers.
    fn link(&self, token: &str) -> String {
        format!("{}/enroll#{token}", self.issuer)
    }

    pub async fn create_invite(&self, actor: Actor, created_by: Option<Uuid>) -> Result<Link> {
        let token = random_token(32);
        let db = self.pool.get().await?;
        let id: Uuid = db
            .query_one(
                "INSERT INTO enrollment_tokens (token_hash, purpose, created_by, expires_at) \
                 VALUES ($1, 'invite', $2, now() + make_interval(days => $3)) RETURNING id",
                &[&token_hash(&token), &created_by, &INVITE_DAYS],
            )
            .await?
            .get(0);
        Entry::new("invite.created", actor)
            .by(created_by)
            .target("enrollment", id)
            .write(&db)
            .await?;
        Ok(Link {
            link: self.link(&token),
            token,
        })
    }

    pub async fn create_recovery(
        &self,
        user: Uuid,
        revoke_other_methods: bool,
        actor: Actor,
        created_by: Option<Uuid>,
    ) -> Result<Link> {
        let token = random_token(32);
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        // Only the newest recovery link for a user works.
        tx.execute(
            "UPDATE enrollment_tokens SET expires_at = now() WHERE user_id = $1 AND purpose = 'recovery' AND consumed_at IS NULL",
            &[&user],
        )
        .await?;
        tx.execute(
            "INSERT INTO enrollment_tokens (token_hash, purpose, user_id, created_by, revoke_other_methods, expires_at) \
             VALUES ($1, 'recovery', $2, $3, $4, now() + make_interval(mins => $5))",
            &[&token_hash(&token), &user, &created_by, &revoke_other_methods, &RECOVERY_MINUTES],
        )
        .await?;
        Entry::new("recovery.issued", actor)
            .by(created_by)
            .target("user", user)
            .meta(json!({ "revoke_other_methods": revoke_other_methods }))
            .write(&tx)
            .await?;
        tx.commit().await?;
        Ok(Link {
            link: self.link(&token),
            token,
        })
    }

    pub async fn find(&self, token: &str) -> Result<Option<Enrollment>> {
        let db = self.pool.get().await?;
        Ok(db
            .query_opt(
                &format!(
                    "{ENROLLMENT} WHERE token_hash = $1 AND purpose IN ('invite', 'recovery') \
                     AND consumed_at IS NULL AND expires_at > now()"
                ),
                &[&token_hash(token)],
            )
            .await?
            .as_ref()
            .map(enrollment))
    }

    pub async fn by_id(&self, id: Uuid) -> Result<Option<Enrollment>> {
        let db = self.pool.get().await?;
        Ok(db
            .query_opt(
                &format!("{ENROLLMENT} WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()"),
                &[&id],
            )
            .await?
            .as_ref()
            .map(enrollment))
    }

    /// Records who used an invite (consumed before the account existed).
    pub async fn record_consumer(&self, id: Uuid, user: Uuid) -> Result<()> {
        let db = self.pool.get().await?;
        db.execute(
            "UPDATE enrollment_tokens SET consumed_by_user_id = $2 WHERE id = $1",
            &[&id, &user],
        )
        .await?;
        Ok(())
    }
}

/// Single use: inside the caller's transaction, so a failed enrollment leaves the link usable.
pub async fn consume(db: &impl GenericClient, id: Uuid, user: Option<Uuid>) -> Result<bool> {
    Ok(db
        .execute(
            "UPDATE enrollment_tokens SET consumed_at = now(), consumed_by_user_id = $2 \
             WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()",
            &[&id, &user],
        )
        .await?
        > 0)
}

/// "I lost my device": a recovery link can take every old passkey with it.
pub async fn revoke_other_passkeys(db: &impl GenericClient, user: Uuid) -> Result<()> {
    db.execute("DELETE FROM passkeys WHERE user_id = $1", &[&user]).await?;
    Ok(())
}
