//! Accounts as the protocol sees them: claims by scope, groups, and the dev test user.

use std::collections::BTreeSet;

use anyhow::Result;
use chrono::{DateTime, Utc};
use deadpool_postgres::{GenericClient, Pool};
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// Which claims each scope releases (DESIGN D6). `groups` and `amr` ride under openid so they can
/// appear in the ID token; `groups` is only produced when the groups scope was granted.
/// `actor_type` (`person` or `agent`) rides under openid too, so every app can tell agents apart
/// from userinfo; the ID token has it only when the claims parameter asks (`id_token`).
pub fn scope_claims(scope: &str) -> &'static [&'static str] {
    match scope {
        "openid" => &["sub", "groups", "amr", "actor_type"],
        "profile" => &["name", "preferred_username", "updated_at"],
        "email" => &["email", "email_verified"],
        "groups" => &["groups"],
        _ => &[],
    }
}

/// Every claim discovery advertises.
pub const CLAIMS_SUPPORTED: [&str; 13] = [
    "sub",
    "groups",
    "actor_type",
    "acr",
    "amr",
    "name",
    "preferred_username",
    "updated_at",
    "email",
    "email_verified",
    "sid",
    "auth_time",
    "iss",
];

pub struct Account {
    pub id: Uuid,
    pub display_name: String,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub updated_at: DateTime<Utc>,
    /// `person`, or `agent` for accounts made through AgentID. The `actor_type` claim.
    pub kind: String,
}

/// Disabled users simply stop existing for the provider: no tokens, no userinfo (S18).
pub async fn find(db: &impl GenericClient, sub: &str) -> Result<Option<Account>> {
    let Ok(id) = Uuid::parse_str(sub) else { return Ok(None) };
    let row = db
        .query_opt(
            "SELECT id, display_name, preferred_username::text, email::text, email_verified, updated_at, kind \
             FROM users WHERE id = $1 AND status = 'active'",
            &[&id],
        )
        .await?;
    Ok(row.map(|r| Account {
        id: r.get(0),
        display_name: r.get(1),
        preferred_username: r.get(2),
        email: r.get(3),
        email_verified: r.get(4),
        updated_at: r.get(5),
        kind: r.get(6),
    }))
}

/// The `groups` claim: the slugs of every group the user belongs to, sorted.
pub async fn group_slugs(db: &impl GenericClient, user: Uuid) -> Result<Vec<String>> {
    let rows = db
        .query(
            "SELECT g.slug FROM group_members m JOIN groups g ON g.id = m.group_id WHERE m.user_id = $1 ORDER BY g.slug",
            &[&user],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

pub async fn is_member(db: &impl GenericClient, user: Uuid, group: Uuid) -> Result<bool> {
    Ok(db
        .query_opt(
            "SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2",
            &[&group, &user],
        )
        .await?
        .is_some())
}

impl Account {
    /// Everything this account can say about itself for the granted scopes.
    pub async fn available(&self, db: &impl GenericClient, granted: &BTreeSet<String>) -> Result<Map<String, Value>> {
        let mut claims = Map::new();
        claims.insert("sub".into(), json!(self.id.to_string()));
        claims.insert("name".into(), json!(self.display_name));
        if let Some(username) = &self.preferred_username {
            claims.insert("preferred_username".into(), json!(username));
        }
        if let Some(email) = &self.email {
            claims.insert("email".into(), json!(email));
            claims.insert("email_verified".into(), json!(self.email_verified));
        }
        claims.insert("updated_at".into(), json!(self.updated_at.timestamp()));
        claims.insert("actor_type".into(), json!(self.kind));
        if granted.contains("groups") {
            claims.insert("groups".into(), json!(group_slugs(db, self.id).await?));
        }
        Ok(claims)
    }
}

pub const TEST_USERNAME: &str = "test";

/// The account behind "Continue as test user". Only reachable when HANDSTAMP_DEV_LOGIN passes the
/// checks in config.rs (S17). It has no credential of any kind.
pub async fn ensure_test_user(pool: &Pool) -> Result<Uuid> {
    let db = pool.get().await?;
    if let Some(row) = db
        .query_opt("SELECT id FROM users WHERE preferred_username = $1", &[&TEST_USERNAME])
        .await?
    {
        return Ok(row.get(0));
    }
    Ok(db
        .query_one(
            "INSERT INTO users (display_name, preferred_username, email, email_verified) \
             VALUES ('Test User', $1, 'test@handstamp.test', true) RETURNING id",
            &[&TEST_USERNAME],
        )
        .await?
        .get(0))
}

/// Every way a user can sign in. Nobody may remove their last one (docs/PLAN.md §3.2).
pub async fn sign_in_method_count(db: &impl GenericClient, user: Uuid) -> Result<i64> {
    Ok(db
        .query_one(
            "SELECT (SELECT count(*) FROM passkeys WHERE user_id = $1) + (SELECT count(*) FROM identities WHERE user_id = $1)",
            &[&user],
        )
        .await?
        .get(0))
}

/// Locks the user row so two concurrent removals can't both see "one more left".
pub async fn lock_user(db: &impl GenericClient, user: Uuid) -> Result<()> {
    db.execute("SELECT id FROM users WHERE id = $1 FOR UPDATE", &[&user])
        .await?;
    Ok(())
}

pub fn is_agent(kind: &str) -> bool {
    kind == "agent"
}

/// The `actor_type` of the account with this `sub`, for introspection.
pub async fn actor_type(db: &impl GenericClient, sub: &str) -> Result<Option<String>> {
    let Ok(id) = Uuid::parse_str(sub) else { return Ok(None) };
    Ok(db
        .query_opt("SELECT kind FROM users WHERE id = $1", &[&id])
        .await?
        .map(|r| r.get(0)))
}

pub async fn display_name(db: &impl GenericClient, user: Uuid) -> Result<Option<String>> {
    Ok(db
        .query_opt("SELECT display_name FROM users WHERE id = $1", &[&user])
        .await?
        .map(|r| r.get(0)))
}
