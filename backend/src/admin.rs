//! The admin console API (docs/PLAN.md M4). Every route needs a signed-in admin; every change also
//! needs a CSRF token, a recent passkey step-up, and leaves an audit row (S19).

use std::sync::LazyLock;

use axum::{
    Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    app::App,
    audit::{Actor, Entry, ip_prefix},
    clients::{ClientDefinition, GROUP_SLUG, ReadOnly as ReadOnlyClient},
    console::{Need, Signed},
    db::{iso, iso_opt, is_unique_violation},
    enrollment::{INVITE_DAYS, RECOVERY_MINUTES},
    http::{ApiError, ApiResult, Out, Req},
    passkeys::LastMethod,
    upstream::providers::{ReadOnly as ReadOnlyProvider, Seed, upstream_url_problem},
};

static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap());
static PROVIDER_SLUG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,31}$").unwrap());

fn reply(result: ApiResult<Out>) -> Response {
    match result {
        Ok(out) => out.into_response(),
        Err(error) => error.into_response(),
    }
}

fn invalid(field: &str, message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid", message).with(json!({ "field": field }))
}

fn conflict(code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, code, message)
}

fn read_only(what: &str, where_: &str) -> ApiError {
    conflict("read_only", format!("This {what} comes from {where_}, so it can only be changed there."))
}

fn id(raw: &str, what: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(raw).map_err(|_| ApiError::not_found(what))
}

async fn read(app: &App, req: &Req) -> ApiResult<Signed> {
    app.signed_in(req, Need { admin: true, ..Default::default() }).await
}

async fn write(app: &App, req: &Req) -> ApiResult<Signed> {
    app.signed_in(req, Need { admin: true, write: true, step_up: true }).await
}

fn entry<'a>(req: &'a Req, admin: Uuid, action: &'a str) -> Entry<'a> {
    Entry::new(action, Actor::Admin).by(Some(admin)).from(ip_prefix(Some(req.ip)), req.user_agent())
}

fn ok(value: Value) -> ApiResult<Out> {
    Ok(Out::json(StatusCode::OK, &value))
}

// ── validation (the zod schemas, first problem wins) ──

fn trimmed(value: &Value, key: &str) -> Result<Option<String>, ApiError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim().to_string())),
        Some(_) => Err(invalid(key, "Some of the details sent were not valid.")),
    }
}

fn boolean(value: &Value, key: &str) -> Result<Option<bool>, ApiError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(invalid(key, "Some of the details sent were not valid.")),
    }
}

fn strings(value: &Value, key: &str) -> Result<Vec<String>, ApiError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(str::to_string).ok_or_else(|| invalid(key, "Some of the details sent were not valid.")))
            .collect(),
        Some(_) => Err(invalid(key, "Some of the details sent were not valid.")),
    }
}

#[derive(Debug, Default)]
pub struct UserPatch {
    display_name: Option<String>,
    email: Option<String>,
    is_admin: Option<bool>,
    status: Option<String>,
}

pub fn parse_user_patch(body: &Value) -> Result<UserPatch, ApiError> {
    let display_name = trimmed(body, "displayName")?;
    if let Some(name) = &display_name
        && (name.is_empty() || name.chars().count() > 80)
    {
        return Err(invalid("displayName", "Use 1 to 80 characters."));
    }
    let email = match body.get("email") {
        None | Some(Value::Null) => None,
        Some(Value::String(e)) if e.is_empty() => Some(String::new()),
        Some(Value::String(e)) if EMAIL.is_match(e) => Some(e.clone()),
        _ => return Err(invalid("email", "That email address needs an @ and a domain.")),
    };
    let is_admin = boolean(body, "isAdmin")?;
    let status = match body.get("status") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s == "active" || s == "disabled" => Some(s.clone()),
        _ => return Err(invalid("status", "Use active or disabled.")),
    };
    Ok(UserPatch { display_name, email, is_admin, status })
}

pub struct GroupInput {
    slug: String,
    name: String,
    description: String,
}

pub fn parse_group(body: &Value) -> Result<GroupInput, ApiError> {
    let slug = trimmed(body, "slug")?.unwrap_or_default();
    if !GROUP_SLUG.is_match(&slug) {
        return Err(invalid("slug", "Use lowercase letters, digits, dots, dashes, colons or underscores."));
    }
    let name = trimmed(body, "name")?.unwrap_or_default();
    if name.is_empty() {
        return Err(invalid("name", "Give the group a name."));
    }
    if name.chars().count() > 80 {
        return Err(invalid("name", "Use at most 80 characters."));
    }
    let description = trimmed(body, "description")?.unwrap_or_default();
    if description.chars().count() > 280 {
        return Err(invalid("description", "Use at most 280 characters."));
    }
    Ok(GroupInput { slug, name, description })
}

pub fn parse_provider(body: &Value) -> Result<Seed, ApiError> {
    let slug = body.get("slug").and_then(Value::as_str).unwrap_or_default().to_string();
    if !PROVIDER_SLUG.is_match(&slug) {
        return Err(invalid("slug", "Use lowercase letters, digits and dashes."));
    }
    let kind = body.get("kind").and_then(Value::as_str).unwrap_or_default().to_string();
    if !["github", "google", "oidc"].contains(&kind.as_str()) {
        return Err(invalid("kind", "Use github, google or oidc."));
    }
    let display_name = trimmed(body, "displayName")?.unwrap_or_default();
    if display_name.is_empty() || display_name.chars().count() > 40 {
        return Err(invalid("displayName", "Use 1 to 40 characters."));
    }
    let issuer_in = trimmed(body, "issuer")?.unwrap_or_default();
    let api_in = trimmed(body, "apiUrl")?.unwrap_or_default();
    let client_id = trimmed(body, "clientId")?.unwrap_or_default();
    if client_id.is_empty() {
        return Err(invalid("clientId", "Add the client ID from the provider."));
    }
    let client_secret = match body.get("clientSecret") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(invalid("clientSecret", "Some of the details sent were not valid.")),
    };
    let scopes = strings(body, "scopes")?;
    let allow_signup = boolean(body, "allowSignup")?.unwrap_or(false);
    let allowed_email_domains: Vec<String> =
        strings(body, "allowedEmailDomains")?.iter().map(|d| d.trim().to_lowercase()).collect();
    let github_allowed_orgs: Vec<String> = strings(body, "githubAllowedOrgs")?.iter().map(|o| o.trim().to_string()).collect();
    let trust = boolean(body, "trustEmailVerified")?.unwrap_or(false);

    let issuer = if kind == "google" {
        "https://accounts.google.com".to_string()
    } else {
        let raw = if issuer_in.is_empty() && kind == "github" { "https://github.com".to_string() } else { issuer_in.clone() };
        raw.trim_end_matches('/').to_string()
    };
    let api_url = (kind == "github").then(|| {
        if !api_in.is_empty() {
            api_in.clone()
        } else if !issuer_in.is_empty() && issuer_in != "https://github.com" {
            format!("{}/api/v3", issuer_in.trim_end_matches('/'))
        } else {
            "https://api.github.com".to_string()
        }
    });
    let scopes = if kind == "github" {
        vec![]
    } else if scopes.is_empty() {
        vec!["openid".into(), "email".into(), "profile".into()]
    } else {
        scopes
    };
    if let Some(problem) = upstream_url_problem(&issuer) {
        return Err(invalid("issuer", format!("The issuer {problem}.")));
    }
    Ok(Seed {
        trust_email_verified: if kind == "oidc" { trust } else { true },
        slug,
        kind,
        display_name,
        issuer,
        api_url,
        client_id,
        client_secret,
        scopes,
        allow_signup,
        allowed_email_domains,
        github_allowed_orgs,
    })
}

#[derive(Default)]
pub struct AuditQuery {
    action_exact: Option<String>,
    action_prefix: Option<String>,
    actor: Option<Uuid>,
    target: Option<String>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    before: Option<i64>,
}

pub fn parse_audit_query(pairs: &[(String, String)]) -> Result<AuditQuery, ApiError> {
    let get = |k: &str| pairs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
    let mut q = AuditQuery::default();
    if let Some(action) = get("action") {
        if action.chars().count() > 64 {
            return Err(invalid("action", "Use at most 64 characters."));
        }
        if action.ends_with('.') {
            q.action_prefix = Some(format!("{action}%"));
        } else {
            q.action_exact = Some(action);
        }
    }
    if let Some(actor) = get("actor") {
        q.actor = Some(Uuid::parse_str(&actor).map_err(|_| invalid("actor", "Invalid UUID"))?);
    }
    if let Some(target) = get("target") {
        if target.chars().count() > 200 {
            return Err(invalid("target", "Use at most 200 characters."));
        }
        q.target = Some(target);
    }
    let datetime = |field: &str, value: Option<String>| -> Result<Option<DateTime<Utc>>, ApiError> {
        value
            .map(|v| {
                DateTime::parse_from_rfc3339(&v).map(|d| d.with_timezone(&Utc)).map_err(|_| invalid(field, "Invalid ISO datetime"))
            })
            .transpose()
    };
    q.from = datetime("from", get("from"))?;
    q.to = datetime("to", get("to"))?;
    if let Some(before) = get("before") {
        match before.trim().parse::<f64>() {
            Ok(n) if n > 0.0 && n.fract() == 0.0 => q.before = Some(n as i64),
            _ => return Err(invalid("before", "Use a positive whole number.")),
        }
    }
    Ok(q)
}

/// Quote everything and neutralise spreadsheet formulas.
pub fn csv_cell(value: &Value) -> String {
    let text = match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Object(_) | Value::Array(_) => value.to_string(),
        other => other.to_string(),
    };
    let text = if text.starts_with(['=', '+', '-', '@']) { format!("'{text}") } else { text };
    format!("\"{}\"", text.replace('"', "\"\""))
}

// ── overview ──

async fn overview(State(app): State<App>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let db = app.pool.get().await?;
        let count = |sql: &'static str| {
            let db = &db;
            async move { db.query_one(sql, &[]).await.map(|r| r.get::<_, i64>(0)) }
        };
        let users = count("SELECT count(*) FROM users WHERE status = 'active'").await?;
        let disabled = count("SELECT count(*) FROM users WHERE status = 'disabled'").await?;
        let clients = count("SELECT count(*) FROM oidc_clients WHERE enabled").await?;
        let providers = count("SELECT count(*) FROM upstream_providers WHERE enabled").await?;
        let ok_24h =
            count("SELECT count(*) FROM audit_log WHERE action = 'auth.sign_in.succeeded' AND at >= now() - interval '24 hours'")
                .await?;
        let refused = count(
            "SELECT count(*) FROM audit_log WHERE action IN ('auth.sign_in.failed', 'auth.sign_in.refused') AND at >= now() - interval '24 hours'",
        )
        .await?;
        drop(db);
        let sessions = app.live_session_count().await?;
        let keys = app.keys.list().await?;
        let signing_key = keys.iter().find(|k| k.state == "active").map(|k| {
            json!({ "kid": k.kid, "activatedAt": iso_opt(k.activated_at), "staged": keys.iter().any(|k| k.state == "staged") })
        });
        ok(json!({
            "users": users,
            "disabledUsers": disabled,
            "sessions": sessions,
            "clients": clients,
            "providers": providers,
            "signIns24h": ok_24h,
            "refusals24h": refused,
            "signingKey": signing_key,
        }))
    }
    .await)
}

// ── users ──

async fn users(State(app): State<App>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let q = req.query_param("q").map(|q| q.trim().to_string()).filter(|q| !q.is_empty());
        let pattern = q.as_ref().map(|q| format!("%{q}%"));
        let db = app.pool.get().await?;
        let rows = db
            .query(
                "SELECT u.id, u.display_name, u.email::text, u.is_admin, u.status, u.created_at, u.last_sign_in_at, \
                   (SELECT count(*) FROM passkeys p WHERE p.user_id = u.id) + (SELECT count(*) FROM identities i WHERE i.user_id = u.id) \
                 FROM users u \
                 WHERE $1::text IS NULL OR u.display_name ILIKE $2 OR u.email::text ILIKE $2 OR u.id::text = $1 \
                 ORDER BY u.display_name LIMIT 500",
                &[&q, &pattern],
            )
            .await?;
        let list: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "id": r.get::<_, Uuid>(0),
                    "displayName": r.get::<_, String>(1),
                    "email": r.get::<_, Option<String>>(2),
                    "isAdmin": r.get::<_, bool>(3),
                    "status": r.get::<_, String>(4),
                    "createdAt": iso(r.get(5)),
                    "lastSignInAt": iso_opt(r.get(6)),
                    "methods": r.get::<_, i64>(7),
                })
            })
            .collect();
        ok(json!(list))
    }
    .await)
}

async fn user(State(app): State<App>, Path(raw): Path<String>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let user_id = id(&raw, "user")?;
        let db = app.pool.get().await?;
        let Some(r) = db
            .query_opt(
                "SELECT id, display_name, email::text, email_verified, is_admin, status, created_at, last_sign_in_at FROM users WHERE id = $1",
                &[&user_id],
            )
            .await?
        else {
            return Err(ApiError::not_found("user"));
        };
        let groups: Vec<Value> = db
            .query(
                "SELECT g.id, g.slug, g.name FROM group_members m JOIN groups g ON g.id = m.group_id WHERE m.user_id = $1 ORDER BY g.slug",
                &[&user_id],
            )
            .await?
            .iter()
            .map(|g| json!({ "id": g.get::<_, Uuid>(0), "slug": g.get::<_, String>(1), "name": g.get::<_, String>(2) }))
            .collect();
        drop(db);
        let passkeys: Vec<Value> = app.passkeys.list_for_user(user_id).await?.iter().map(|p| p.view()).collect();
        let identities = app.identities.list_for_user(user_id).await?;
        let sessions = app.list_sessions(&user_id.to_string()).await?;
        ok(json!({
            "user": {
                "id": r.get::<_, Uuid>(0),
                "displayName": r.get::<_, String>(1),
                "email": r.get::<_, Option<String>>(2),
                "emailVerified": r.get::<_, bool>(3),
                "isAdmin": r.get::<_, bool>(4),
                "status": r.get::<_, String>(5),
                "createdAt": iso(r.get(6)),
                "lastSignInAt": iso_opt(r.get(7)),
            },
            "passkeys": passkeys,
            "identities": identities,
            "groups": groups,
            "sessions": sessions,
        }))
    }
    .await)
}

async fn active_admins(app: &App) -> ApiResult<i64> {
    let db = app.pool.get().await?;
    Ok(db.query_one("SELECT count(*) FROM users WHERE is_admin AND status = 'active'", &[]).await?.get(0))
}

async fn patch_user(State(app): State<App>, Path(raw): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let patch = parse_user_patch(&req.json())?;
        let user_id = id(&raw, "user")?;
        let db = app.pool.get().await?;
        let Some(row) = db.query_opt("SELECT is_admin, status FROM users WHERE id = $1", &[&user_id]).await? else {
            return Err(ApiError::not_found("user"));
        };
        let (was_admin, status): (bool, String) = (row.get(0), row.get(1));
        drop(db);
        let demotes = patch.is_admin == Some(false) || patch.status.as_deref() == Some("disabled");
        if user_id == admin.id && demotes {
            return Err(conflict(
                "self",
                "You can't remove your own admin access or turn off your own account. Ask another admin.",
            ));
        }
        if was_admin && status == "active" && demotes && active_admins(&app).await? <= 1 {
            return Err(conflict("last_admin", "This is the last admin. Make someone else an admin first."));
        }
        let email_set = patch.email.is_some();
        let email = patch.email.clone().filter(|e| !e.is_empty());
        let db = app.pool.get().await?;
        // An admin-entered email is vouched for by the admin, so it counts as verified.
        let updated = db
            .execute(
                "UPDATE users SET updated_at = now(), display_name = COALESCE($2, display_name), \
                   email = CASE WHEN $3 THEN $4::text::citext ELSE email END, \
                   email_verified = CASE WHEN $3 THEN $5 ELSE email_verified END, \
                   email_identity_id = CASE WHEN $3 THEN NULL ELSE email_identity_id END, \
                   is_admin = COALESCE($6, is_admin), status = COALESCE($7, status) WHERE id = $1",
                &[&user_id, &patch.display_name, &email_set, &email, &email.is_some(), &patch.is_admin, &patch.status],
            )
            .await;
        if let Err(error) = updated {
            if is_unique_violation(&error) {
                return Err(conflict("email_taken", "Another user already has that email address."));
            }
            return Err(error.into());
        }
        if patch.display_name.is_some() || email_set {
            let mut fields = vec![];
            if patch.display_name.is_some() {
                fields.push("displayName");
            }
            if email_set {
                fields.push("email");
            }
            entry(&req, admin.id, "user.updated").target("user", user_id).meta(json!({ "fields": fields })).write(&db).await?;
        }
        if let Some(is_admin) = patch.is_admin
            && is_admin != was_admin
        {
            let action = if is_admin { "user.admin_granted" } else { "user.admin_revoked" };
            entry(&req, admin.id, action).target("user", user_id).write(&db).await?;
        }
        if let Some(next) = &patch.status
            && *next != status
        {
            let action = if next == "disabled" { "user.disabled" } else { "user.enabled" };
            entry(&req, admin.id, action).target("user", user_id).write(&db).await?;
            drop(db);
            // Disabling ends everything at once: sessions, tokens, and a back-channel logout to apps.
            if next == "disabled" {
                app.end_sessions(&user_id.to_string(), None).await?;
            }
        }
        ok(json!({ "ok": true }))
    }
    .await)
}

async fn recovery(State(app): State<App>, Path(raw): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let user_id = id(&raw, "user")?;
        let db = app.pool.get().await?;
        let Some(row) = db.query_opt("SELECT status FROM users WHERE id = $1", &[&user_id]).await? else {
            return Err(ApiError::not_found("user"));
        };
        drop(db);
        if row.get::<_, String>(0) != "active" {
            return Err(conflict("disabled", "Turn this account back on before sending a recovery link."));
        }
        let revoke = req.json().get("revokeOtherMethods") == Some(&Value::Bool(true));
        let link = app.enrollments.create_recovery(user_id, revoke, Actor::Admin, Some(admin.id)).await?;
        ok(json!({ "token": link.token, "link": link.link, "expiresInMinutes": RECOVERY_MINUTES }))
    }
    .await)
}

async fn revoke_sessions(State(app): State<App>, Path(raw): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let ended = match Uuid::parse_str(&raw) {
            Ok(user) => app.end_sessions(&user.to_string(), None).await?,
            Err(_) => 0,
        };
        entry(&req, admin.id, "admin.sessions_revoked")
            .target("user", &raw)
            .meta(json!({ "sessions": ended }))
            .write(&app.pool.get().await?)
            .await?;
        ok(json!({ "ended": ended }))
    }
    .await)
}

fn their_last_method() -> ApiError {
    conflict(
        "last_method",
        "This is their only way to sign in. Send a recovery link, or turn the account off instead.",
    )
}

async fn remove_passkey(State(app): State<App>, Path((user, passkey)): Path<(String, String)>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let user_id = id(&user, "passkey")?;
        let passkey_id = id(&passkey, "passkey")?;
        match app.passkeys.remove(user_id, passkey_id).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err(ApiError::not_found("passkey")),
            Err(error) if error.is::<LastMethod>() => return Err(their_last_method()),
            Err(error) => return Err(error.into()),
        }
        entry(&req, admin.id, "passkey.removed")
            .target("passkey", passkey_id)
            .meta(json!({ "user": user }))
            .write(&app.pool.get().await?)
            .await?;
        Ok(Out::new(StatusCode::NO_CONTENT))
    }
    .await)
}

async fn unlink_identity(State(app): State<App>, Path((user, identity)): Path<(String, String)>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let user_id = id(&user, "linked account")?;
        let identity_id = id(&identity, "linked account")?;
        match app.identities.unlink(user_id, identity_id).await {
            Ok(true) => {}
            Ok(false) => return Err(ApiError::not_found("linked account")),
            Err(error) if error.is::<LastMethod>() => return Err(their_last_method()),
            Err(error) => return Err(error.into()),
        }
        entry(&req, admin.id, "identity.unlinked")
            .target("identity", identity_id)
            .meta(json!({ "user": user }))
            .write(&app.pool.get().await?)
            .await?;
        Ok(Out::new(StatusCode::NO_CONTENT))
    }
    .await)
}

// ── invites ──

async fn invites(State(app): State<App>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let db = app.pool.get().await?;
        let rows = db
            .query(
                "SELECT t.id, t.created_at, t.expires_at, u.display_name FROM enrollment_tokens t \
                 LEFT JOIN users u ON u.id = t.created_by \
                 WHERE t.purpose = 'invite' AND t.consumed_at IS NULL AND t.expires_at > now() ORDER BY t.created_at DESC",
                &[],
            )
            .await?;
        let list: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "id": r.get::<_, Uuid>(0),
                    "createdAt": iso(r.get(1)),
                    "expiresAt": iso(r.get(2)),
                    "createdBy": r.get::<_, Option<String>>(3),
                })
            })
            .collect();
        ok(json!(list))
    }
    .await)
}

async fn create_invite(State(app): State<App>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let link = app.enrollments.create_invite(Actor::Admin, Some(admin.id)).await?;
        ok(json!({ "token": link.token, "link": link.link, "expiresInDays": INVITE_DAYS }))
    }
    .await)
}

async fn revoke_invite(State(app): State<App>, Path(raw): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let invite = id(&raw, "invite")?;
        let db = app.pool.get().await?;
        let n = db
            .execute(
                "UPDATE enrollment_tokens SET expires_at = now() WHERE id = $1 AND purpose = 'invite' AND consumed_at IS NULL",
                &[&invite],
            )
            .await?;
        if n == 0 {
            return Err(ApiError::not_found("invite"));
        }
        entry(&req, admin.id, "invite.revoked").target("enrollment", invite).write(&db).await?;
        Ok(Out::new(StatusCode::NO_CONTENT))
    }
    .await)
}

// ── groups ──

async fn groups(State(app): State<App>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let db = app.pool.get().await?;
        let rows = db
            .query(
                "SELECT g.id, g.slug, g.name, g.description, \
                   (SELECT count(*) FROM group_members m WHERE m.group_id = g.id), \
                   (SELECT count(*) FROM oidc_clients c WHERE c.required_group_id = g.id) \
                 FROM groups g ORDER BY g.slug",
                &[],
            )
            .await?;
        let list: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "id": r.get::<_, Uuid>(0),
                    "slug": r.get::<_, String>(1),
                    "name": r.get::<_, String>(2),
                    "description": r.get::<_, String>(3),
                    "members": r.get::<_, i64>(4),
                    "apps": r.get::<_, i64>(5),
                })
            })
            .collect();
        ok(json!(list))
    }
    .await)
}

async fn create_group(State(app): State<App>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let input = parse_group(&req.json())?;
        let db = app.pool.get().await?;
        let row = db
            .query_opt(
                "INSERT INTO groups (slug, name, description) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING id",
                &[&input.slug, &input.name, &input.description],
            )
            .await?;
        let Some(row) = row else {
            return Err(conflict("exists", format!("A group called {} already exists.", input.slug)));
        };
        let group: Uuid = row.get(0);
        entry(&req, admin.id, "group.created").target("group", group).meta(json!({ "slug": input.slug })).write(&db).await?;
        Ok(Out::json(StatusCode::CREATED, &json!({ "id": group })))
    }
    .await)
}

async fn group(State(app): State<App>, Path(raw): Path<String>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let group_id = id(&raw, "group")?;
        let db = app.pool.get().await?;
        let Some(g) =
            db.query_opt("SELECT id, slug, name, description, created_at FROM groups WHERE id = $1", &[&group_id]).await?
        else {
            return Err(ApiError::not_found("group"));
        };
        let members: Vec<Value> = db
            .query(
                "SELECT u.id, u.display_name, u.email::text, m.added_at FROM group_members m JOIN users u ON u.id = m.user_id \
                 WHERE m.group_id = $1 ORDER BY u.display_name",
                &[&group_id],
            )
            .await?
            .iter()
            .map(|r| {
                json!({
                    "id": r.get::<_, Uuid>(0),
                    "displayName": r.get::<_, String>(1),
                    "email": r.get::<_, Option<String>>(2),
                    "addedAt": iso(r.get(3)),
                })
            })
            .collect();
        let apps: Vec<Value> = db
            .query("SELECT client_id, name FROM oidc_clients WHERE required_group_id = $1", &[&group_id])
            .await?
            .iter()
            .map(|r| json!({ "clientId": r.get::<_, String>(0), "name": r.get::<_, String>(1) }))
            .collect();
        ok(json!({
            "group": {
                "id": g.get::<_, Uuid>(0),
                "slug": g.get::<_, String>(1),
                "name": g.get::<_, String>(2),
                "description": g.get::<_, String>(3),
                "createdAt": iso(g.get(4)),
            },
            "members": members,
            "apps": apps,
        }))
    }
    .await)
}

async fn update_group(State(app): State<App>, Path(raw): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let input = parse_group(&req.json())?;
        let group_id = id(&raw, "group")?;
        let db = app.pool.get().await?;
        match db
            .execute(
                "UPDATE groups SET slug = $2, name = $3, description = $4 WHERE id = $1",
                &[&group_id, &input.slug, &input.name, &input.description],
            )
            .await
        {
            Ok(0) => return Err(ApiError::not_found("group")),
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => {
                return Err(conflict("exists", format!("A group called {} already exists.", input.slug)));
            }
            Err(error) => return Err(error.into()),
        }
        entry(&req, admin.id, "group.updated").target("group", group_id).meta(json!({ "slug": input.slug })).write(&db).await?;
        ok(json!({ "ok": true }))
    }
    .await)
}

async fn delete_group(State(app): State<App>, Path(raw): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let group_id = id(&raw, "group")?;
        let db = app.pool.get().await?;
        let used: i64 =
            db.query_one("SELECT count(*) FROM oidc_clients WHERE required_group_id = $1", &[&group_id]).await?.get(0);
        if used > 0 {
            return Err(conflict("in_use", "Apps require this group. Change their access settings first."));
        }
        let Some(row) = db.query_opt("DELETE FROM groups WHERE id = $1 RETURNING slug", &[&group_id]).await? else {
            return Err(ApiError::not_found("group"));
        };
        let slug: String = row.get(0);
        entry(&req, admin.id, "group.deleted").target("group", group_id).meta(json!({ "slug": slug })).write(&db).await?;
        Ok(Out::new(StatusCode::NO_CONTENT))
    }
    .await)
}

async fn add_member(State(app): State<App>, Path((group, user)): Path<(String, String)>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let group_id = id(&group, "group")?;
        let user_id = id(&user, "user")?;
        let db = app.pool.get().await?;
        let added = db
            .query_opt(
                "INSERT INTO group_members (group_id, user_id, added_by) \
                 SELECT $1, $2, $3 WHERE EXISTS (SELECT 1 FROM groups WHERE id = $1) AND EXISTS (SELECT 1 FROM users WHERE id = $2) \
                 ON CONFLICT DO NOTHING RETURNING user_id",
                &[&group_id, &user_id, &admin.id],
            )
            .await?;
        if added.is_some() {
            entry(&req, admin.id, "group.member_added")
                .target("group", group_id)
                .meta(json!({ "user": user }))
                .write(&db)
                .await?;
        }
        Ok(Out::new(StatusCode::NO_CONTENT))
    }
    .await)
}

async fn remove_member(State(app): State<App>, Path((group, user)): Path<(String, String)>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let group_id = id(&group, "group")?;
        let user_id = id(&user, "user")?;
        let db = app.pool.get().await?;
        let removed = db
            .execute("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2", &[&group_id, &user_id])
            .await?;
        if removed > 0 {
            entry(&req, admin.id, "group.member_removed")
                .target("group", group_id)
                .meta(json!({ "user": user }))
                .write(&db)
                .await?;
        }
        Ok(Out::new(StatusCode::NO_CONTENT))
    }
    .await)
}

// ── clients ("apps") ──

async fn group_slug(app: &App, group: Option<Uuid>) -> ApiResult<Option<String>> {
    let Some(group) = group else { return Ok(None) };
    let db = app.pool.get().await?;
    Ok(db.query_opt("SELECT slug FROM groups WHERE id = $1", &[&group]).await?.map(|r| r.get(0)))
}

async fn clients(State(app): State<App>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let mut list = Vec::new();
        for row in app.clients.list().await? {
            let slug = group_slug(&app, row.required_group_id).await?;
            list.push(row.view(slug));
        }
        ok(json!(list))
    }
    .await)
}

async fn client(State(app): State<App>, Path(client_id): Path<String>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let Some(row) = app.clients.get(&client_id).await? else { return Err(ApiError::not_found("app")) };
        let slug = group_slug(&app, row.required_group_id).await?;
        ok(row.view(slug))
    }
    .await)
}

fn parse_client(value: &Value) -> ApiResult<ClientDefinition> {
    ClientDefinition::parse(value).map_err(|p| invalid(&p.field, p.message))
}

async fn require_group_exists(app: &App, def: &ClientDefinition) -> ApiResult<()> {
    if let Some(slug) = &def.required_group {
        let db = app.pool.get().await?;
        if db.query_opt("SELECT 1 FROM groups WHERE slug = $1", &[slug]).await?.is_none() {
            return Err(invalid("requiredGroup", format!("There is no group called {slug}.")));
        }
    }
    Ok(())
}

fn client_read_only() -> ApiError {
    read_only("app", "the clients file or Handstamp itself")
}

async fn create_client(State(app): State<App>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let def = parse_client(&req.json())?;
        require_group_exists(&app, &def).await?;
        let Some(secret) = app.clients.create(&def).await? else {
            return Err(conflict("exists", format!("An app with the client ID {} already exists.", def.client_id)));
        };
        entry(&req, admin.id, "client.created")
            .target("client", &def.client_id)
            .client(&def.client_id)
            .write(&app.pool.get().await?)
            .await?;
        // The secret is shown exactly once, here.
        Ok(Out::json(StatusCode::CREATED, &json!({ "clientId": def.client_id, "secret": secret })))
    }
    .await)
}

async fn update_client(State(app): State<App>, Path(client_id): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let mut body = req.json();
        if !body.is_object() {
            body = json!({});
        }
        body["clientId"] = json!(client_id);
        let def = parse_client(&body)?;
        require_group_exists(&app, &def).await?;
        let result = match app.clients.update(&def).await {
            Ok(result) => result,
            Err(error) if error.is::<ReadOnlyClient>() => return Err(client_read_only()),
            Err(error) => return Err(error.into()),
        };
        let Some(secret) = result else { return Err(ApiError::not_found("app")) };
        entry(&req, admin.id, "client.updated")
            .target("client", &def.client_id)
            .client(&def.client_id)
            .write(&app.pool.get().await?)
            .await?;
        ok(json!({ "secret": secret }))
    }
    .await)
}

async fn rotate_secret(State(app): State<App>, Path(client_id): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let secret = match app.clients.rotate_secret(&client_id).await {
            Ok(secret) => secret,
            Err(error) if error.is::<ReadOnlyClient>() => return Err(client_read_only()),
            Err(error) => return Err(error.into()),
        };
        let Some(secret) = secret else { return Err(conflict("no_secret", "This app has no secret to rotate.")) };
        entry(&req, admin.id, "client.secret_rotated")
            .target("client", &client_id)
            .client(&client_id)
            .write(&app.pool.get().await?)
            .await?;
        ok(json!({ "secret": secret }))
    }
    .await)
}

async fn client_enabled(State(app): State<App>, Path(client_id): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let enabled = req.json().get("enabled") == Some(&Value::Bool(true));
        match app.clients.set_enabled(&client_id, enabled).await {
            Ok(true) => {}
            Ok(false) => return Err(ApiError::not_found("app")),
            Err(error) if error.is::<ReadOnlyClient>() => return Err(client_read_only()),
            Err(error) => return Err(error.into()),
        }
        let action = if enabled { "client.enabled" } else { "client.disabled" };
        entry(&req, admin.id, action).target("client", &client_id).client(&client_id).write(&app.pool.get().await?).await?;
        ok(json!({ "enabled": enabled }))
    }
    .await)
}

// ── upstream providers ──

async fn providers(State(app): State<App>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        ok(json!(app.providers.list().await?))
    }
    .await)
}

async fn create_provider(State(app): State<App>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let input = parse_provider(&req.json())?;
        if input.client_secret.is_none() {
            return Err(invalid("clientSecret", "Add the client secret from the provider."));
        }
        if !app.providers.create(&input).await? {
            return Err(conflict("exists", format!("A provider called {} already exists.", input.slug)));
        }
        entry(&req, admin.id, "provider.created")
            .target("provider", &input.slug)
            .meta(json!({ "kind": input.kind }))
            .write(&app.pool.get().await?)
            .await?;
        Ok(Out::json(StatusCode::CREATED, &json!({ "slug": input.slug })))
    }
    .await)
}

fn provider_read_only() -> ApiError {
    read_only("provider", "environment variables")
}

async fn update_provider(State(app): State<App>, Path(slug): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let mut body = req.json();
        if !body.is_object() {
            body = json!({});
        }
        body["slug"] = json!(slug);
        let input = parse_provider(&body)?;
        match app.providers.update(&input).await {
            Ok(true) => {}
            Ok(false) => return Err(ApiError::not_found("provider")),
            Err(error) if error.is::<ReadOnlyProvider>() => return Err(provider_read_only()),
            Err(error) => return Err(error.into()),
        }
        entry(&req, admin.id, "provider.updated")
            .target("provider", &input.slug)
            .meta(json!({ "secret_changed": input.client_secret.is_some() }))
            .write(&app.pool.get().await?)
            .await?;
        ok(json!({ "ok": true }))
    }
    .await)
}

async fn provider_enabled(State(app): State<App>, Path(slug): Path<String>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let enabled = req.json().get("enabled") == Some(&Value::Bool(true));
        match app.providers.set_enabled(&slug, enabled).await {
            Ok(true) => {}
            Ok(false) => return Err(ApiError::not_found("provider")),
            Err(error) if error.is::<ReadOnlyProvider>() => return Err(provider_read_only()),
            Err(error) => return Err(error.into()),
        }
        let action = if enabled { "provider.enabled" } else { "provider.disabled" };
        entry(&req, admin.id, action).target("provider", &slug).write(&app.pool.get().await?).await?;
        ok(json!({ "enabled": enabled }))
    }
    .await)
}

// ── signing keys ──

async fn keys(State(app): State<App>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        ok(json!({ "keys": app.keys.list().await?, "policy": app.config.rotation() }))
    }
    .await)
}

async fn rotate_key(State(app): State<App>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let kid = app.keys.stage(Actor::Admin, Some(admin.id)).await?;
        ok(json!({ "kid": kid }))
    }
    .await)
}

async fn promote_key(State(app): State<App>, req: Req) -> Response {
    reply(async {
        let Signed { user: admin, .. } = write(&app, &req).await?;
        let Some(kid) = app.keys.promote(&app.config.rotation(), Actor::Admin, Some(admin.id)).await? else {
            return Err(conflict("nothing_staged", "There is no new key waiting. Rotate first."));
        };
        ok(json!({ "kid": kid }))
    }
    .await)
}

// ── audit log ──

const AUDIT_COLUMNS: [&str; 12] = [
    "id",
    "at",
    "action",
    "actorType",
    "actorUserId",
    "actorName",
    "targetType",
    "targetId",
    "clientId",
    "ipPrefix",
    "userAgent",
    "metadata",
];

async fn audit_rows(app: &App, q: &AuditQuery, limit: i64) -> ApiResult<Vec<Value>> {
    let db = app.pool.get().await?;
    let rows = db
        .query(
            "SELECT a.id, a.at, a.action, a.actor_type, a.actor_user_id, u.display_name, a.target_type, a.target_id, \
               a.client_id, abbrev(a.ip_prefix), a.user_agent, a.metadata \
             FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id \
             WHERE ($1::text IS NULL OR a.action = $1) AND ($2::text IS NULL OR a.action LIKE $2) \
               AND ($3::uuid IS NULL OR a.actor_user_id = $3) \
               AND ($4::text IS NULL OR a.target_id = $4 OR a.client_id = $4) \
               AND ($5::timestamptz IS NULL OR a.at >= $5) AND ($6::timestamptz IS NULL OR a.at <= $6) \
               AND ($7::bigint IS NULL OR a.id < $7) \
             ORDER BY a.id DESC LIMIT $8",
            &[&q.action_exact, &q.action_prefix, &q.actor, &q.target, &q.from, &q.to, &q.before, &limit],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<_, i64>(0),
                "at": iso(r.get(1)),
                "action": r.get::<_, String>(2),
                "actorType": r.get::<_, String>(3),
                "actorUserId": r.get::<_, Option<Uuid>>(4),
                "actorName": r.get::<_, Option<String>>(5),
                "targetType": r.get::<_, Option<String>>(6),
                "targetId": r.get::<_, Option<String>>(7),
                "clientId": r.get::<_, Option<String>>(8),
                "ipPrefix": r.get::<_, Option<String>>(9),
                "userAgent": r.get::<_, Option<String>>(10),
                "metadata": r.get::<_, Value>(11),
            })
        })
        .collect())
}

async fn audit(State(app): State<App>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let q = parse_audit_query(&req.query_pairs())?;
        let mut rows = audit_rows(&app, &q, 51).await?;
        let next = if rows.len() > 50 { rows[49]["id"].clone() } else { Value::Null };
        rows.truncate(50);
        ok(json!({ "entries": rows, "next": next }))
    }
    .await)
}

async fn audit_csv(State(app): State<App>, req: Req) -> Response {
    reply(async {
        read(&app, &req).await?;
        let q = parse_audit_query(&req.query_pairs())?;
        let rows = audit_rows(&app, &q, 10_000).await?;
        let mut csv = AUDIT_COLUMNS.join(",");
        csv.push('\n');
        let body: Vec<String> = rows
            .iter()
            .map(|r| AUDIT_COLUMNS.iter().map(|k| csv_cell(&r[*k])).collect::<Vec<_>>().join(","))
            .collect();
        csv.push_str(&body.join("\n"));
        csv.push('\n');
        let filename = format!("handstamp-audit-{}.csv", Utc::now().format("%Y-%m-%d"));
        let mut out = Out::new(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/csv; charset=utf-8")
            .header(header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{filename}\""))
            .no_store();
        out.body = csv.into();
        Ok(out)
    }
    .await)
}

pub fn routes() -> Router<App> {
    Router::new()
        .route("/api/admin/overview", get(overview))
        .route("/api/admin/users", get(users))
        .route("/api/admin/users/{id}", get(user).patch(patch_user))
        .route("/api/admin/users/{id}/recovery", post(recovery))
        .route("/api/admin/users/{id}/sessions", axum::routing::delete(revoke_sessions))
        .route("/api/admin/users/{id}/passkeys/{passkey}", axum::routing::delete(remove_passkey))
        .route("/api/admin/users/{id}/identities/{identity}", axum::routing::delete(unlink_identity))
        .route("/api/admin/invites", get(invites).post(create_invite))
        .route("/api/admin/invites/{id}", axum::routing::delete(revoke_invite))
        .route("/api/admin/groups", get(groups).post(create_group))
        .route("/api/admin/groups/{id}", get(group).patch(update_group).delete(delete_group))
        .route("/api/admin/groups/{id}/members/{user}", put(add_member).delete(remove_member))
        .route("/api/admin/clients", get(clients).post(create_client))
        .route("/api/admin/clients/{id}", get(client).put(update_client))
        .route("/api/admin/clients/{id}/secret", post(rotate_secret))
        .route("/api/admin/clients/{id}/enabled", post(client_enabled))
        .route("/api/admin/providers", get(providers).post(create_provider))
        .route("/api/admin/providers/{slug}", put(update_provider))
        .route("/api/admin/providers/{slug}/enabled", post(provider_enabled))
        .route("/api/admin/keys", get(keys))
        .route("/api/admin/keys/rotate", post(rotate_key))
        .route("/api/admin/keys/promote", post(promote_key))
        .route("/api/admin/audit", get(audit))
        .route("/api/admin/audit.csv", get(audit_csv))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(error: ApiError) -> (String, String) {
        (error.extra["field"].as_str().unwrap_or_default().to_string(), error.message)
    }

    #[test]
    fn csv_cells_are_quoted_and_defused() {
        assert_eq!(csv_cell(&json!("=HYPERLINK(\"https://evil\")")), "\"'=HYPERLINK(\"\"https://evil\"\")\"");
        assert_eq!(csv_cell(&json!("plain")), "\"plain\"");
        assert_eq!(csv_cell(&Value::Null), "\"\"");
        assert_eq!(csv_cell(&json!(42)), "\"42\"");
        assert_eq!(csv_cell(&json!({ "a": 1 })), "\"{\"\"a\"\":1}\"");
        assert_eq!(csv_cell(&json!("-1")), "\"'-1\"");
    }

    #[test]
    fn validation_messages() {
        let e = parse_user_patch(&json!({ "email": "nope" })).err().unwrap();
        assert_eq!(field(e), ("email".into(), "That email address needs an @ and a domain.".into()));
        assert!(parse_user_patch(&json!({ "email": "" })).unwrap().email == Some(String::new()));
        let e = parse_group(&json!({ "slug": "Bad Slug", "name": "x" })).err().unwrap();
        assert_eq!(field(e).0, "slug");
        let e = parse_group(&json!({ "slug": "staff", "name": "  " })).err().unwrap();
        assert_eq!(field(e), ("name".into(), "Give the group a name.".into()));
        let e = parse_provider(&json!({
            "slug": "plain", "kind": "oidc", "displayName": "Plain", "issuer": "http://sso.example.com", "clientId": "x"
        }))
        .err()
        .unwrap();
        assert_eq!(field(e), ("issuer".into(), "The issuer must use https://.".into()));
    }

    #[test]
    fn provider_transforms() {
        let gh = parse_provider(&json!({ "slug": "gh", "kind": "github", "displayName": "GH", "clientId": "x" })).unwrap();
        assert_eq!(gh.issuer, "https://github.com");
        assert_eq!(gh.api_url.as_deref(), Some("https://api.github.com"));
        assert!(gh.trust_email_verified && gh.scopes.is_empty());
        let ghe = parse_provider(
            &json!({ "slug": "ghe", "kind": "github", "displayName": "GHE", "clientId": "x", "issuer": "https://ghe.example.com/" }),
        )
        .unwrap();
        assert_eq!(ghe.api_url.as_deref(), Some("https://ghe.example.com/api/v3"));
        let oidc = parse_provider(
            &json!({ "slug": "corp", "kind": "oidc", "displayName": "Corp", "clientId": "x", "issuer": "https://sso.corp.example" }),
        )
        .unwrap();
        assert!(!oidc.trust_email_verified);
        assert_eq!(oidc.scopes, ["openid", "email", "profile"]);
    }

    #[test]
    fn audit_query_parsing() {
        let q = parse_audit_query(&[("action".into(), "group.".into()), ("before".into(), "10".into())]).unwrap();
        assert_eq!(q.action_prefix.as_deref(), Some("group.%"));
        assert_eq!(q.before, Some(10));
        assert!(parse_audit_query(&[("actor".into(), "x".into())]).is_err());
        assert!(parse_audit_query(&[("from".into(), "2026-01-01T00:00:00Z".into())]).unwrap().from.is_some());
    }
}
