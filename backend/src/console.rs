//! Handstamp's own account and admin UI signs in through Handstamp (docs/PLAN.md §1.3), as the
//! first-party client `handstamp-console`. The code exchange happens in-process, so it works even
//! where the container can't reach its own public hostname. Also: the account API behind /account.

use std::collections::BTreeMap;

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    app::App,
    audit::{Actor, Entry, ip_prefix},
    clients::CONSOLE_CLIENT_ID,
    crypto::{b64url, b64url_decode, csrf_token, csrf_valid, random_token, sha256},
    db::iso,
    http::{ApiError, ApiResult, CSRF_HEADER, Limit, Out, Req},
    oidc::{store::now, token::exchange_code},
    passkeys::{self, LastMethod, clean_name, passkey_message},
    webauthn::{self, CredentialResponse, PasskeyUser},
};

pub const STEP_UP_SECONDS: i64 = 5 * 60;
const SESSION_HOURS: i64 = 12;
const STATE_MINUTES: i64 = 10;
const SESSION_COOKIE: &str = "hs_console";
const STATE_COOKIE: &str = "hs_console_state";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleSession {
    pub sub: String,
    /// The SSO session this console session rides on.
    pub uid: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingLogin {
    state: String,
    nonce: String,
    verifier: String,
    return_to: String,
}

pub fn recently_authenticated(session: &ConsoleSession, at: i64) -> bool {
    at - session.auth_time <= STEP_UP_SECONDS
}

/// The only way an internal `returnTo` may become a redirect target: same-origin paths only.
pub fn safe_return_path(value: Option<&str>, fallback: &str) -> String {
    let Some(value) = value.filter(|v| !v.is_empty() && v.len() <= 2048) else {
        return fallback.into();
    };
    if !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.chars().any(|c| c.is_control())
    {
        return fallback.into();
    }
    let base = url::Url::parse("http://handstamp.invalid").unwrap();
    match base.join(value) {
        Ok(url) if url.origin() == base.origin() => {
            let mut out = url.path().to_string();
            if let Some(q) = url.query() {
                out.push('?');
                out.push_str(q);
            }
            if let Some(f) = url.fragment() {
                out.push('#');
                out.push_str(f);
            }
            out
        }
        _ => fallback.into(),
    }
}

pub struct User {
    pub id: Uuid,
    pub display_name: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub is_admin: bool,
    pub preferred_username: Option<String>,
    pub webauthn_user_handle: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub struct Signed {
    pub session: ConsoleSession,
    pub user: User,
}

#[derive(Default, Clone, Copy)]
pub struct Need {
    pub write: bool,
    pub step_up: bool,
    pub admin: bool,
}

impl App {
    pub fn console_session(&self, req: &Req) -> Option<ConsoleSession> {
        self.read_sealed(req, SESSION_COOKIE)
    }

    /// The signed-in console user, if its SSO session still exists: signing out anywhere (or
    /// "sign out everywhere") ends the console session immediately.
    pub async fn current(&self, req: &Req) -> ApiResult<Option<Signed>> {
        let Some(session) = self.console_session(req) else {
            return Ok(None);
        };
        if !self.session_exists(&session.sub, &session.uid).await? {
            return Ok(None);
        }
        let Ok(id) = Uuid::parse_str(&session.sub) else {
            return Ok(None);
        };
        let db = self.pool.get().await?;
        let row = db
            .query_opt(
                "SELECT id, display_name, email::text, email_verified, is_admin, preferred_username::text, webauthn_user_handle, created_at \
                 FROM users WHERE id = $1 AND status = 'active'",
                &[&id],
            )
            .await?;
        Ok(row.map(|r| Signed {
            session,
            user: User {
                id: r.get(0),
                display_name: r.get(1),
                email: r.get(2),
                email_verified: r.get(3),
                is_admin: r.get(4),
                preferred_username: r.get(5),
                webauthn_user_handle: r.get(6),
                created_at: r.get(7),
            },
        }))
    }

    /// Who is signed in to the console, and may they do this? Shared by /api/me and /api/admin.
    pub async fn signed_in(&self, req: &Req, need: Need) -> ApiResult<Signed> {
        let Some(found) = self.current(req).await? else {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "signed_out",
                "Sign in to continue.",
            ));
        };
        if need.admin && !found.user.is_admin {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "not_admin",
                "Only Handstamp admins can do this.",
            ));
        }
        if need.write
            && (!req.same_origin(&self.issuer)
                || !csrf_valid(
                    &self.csrf_key,
                    &format!("console:{}", found.session.uid),
                    req.header(CSRF_HEADER),
                ))
        {
            return Err(ApiError::csrf());
        }
        if need.step_up {
            // A passkey holder confirms with a passkey: a hijacked GitHub account can't stand in for
            // them when it comes to changing how they sign in, or anything an admin does (§3.3).
            let has_passkey = !self.passkeys.list_for_user(found.user.id).await?.is_empty();
            let fresh = recently_authenticated(&found.session, now());
            if !fresh || (has_passkey && !found.session.amr.iter().any(|m| m == "pop")) {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "step_up_required",
                    "For your safety, confirm it is you first.",
                )
                .with(json!({ "method": if has_passkey { "passkey" } else { "any" } })));
            }
        }
        Ok(found)
    }

    pub fn clear_console_session(&self) -> String {
        self.clear_sealed(SESSION_COOKIE)
    }
}

fn reply(result: ApiResult<Out>) -> Response {
    match result {
        Ok(out) => out.into_response(),
        Err(error) => error.into_response(),
    }
}

// ── sign-in for the console itself ──

async fn login(State(app): State<App>, req: Req) -> Response {
    let verifier = random_token(32);
    let pending = PendingLogin {
        state: random_token(32),
        nonce: random_token(32),
        verifier: verifier.clone(),
        return_to: safe_return_path(req.query_param("returnTo").as_deref(), "/account"),
    };
    let mut url = url::Url::parse(&format!("{}/auth", app.issuer)).expect("issuer URL");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", CONSOLE_CLIENT_ID)
            .append_pair("redirect_uri", &format!("{}/console/callback", app.issuer))
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile email groups")
            .append_pair("state", &pending.state)
            .append_pair("nonce", &pending.nonce)
            .append_pair("code_challenge", &b64url(&sha256(verifier.as_bytes())))
            .append_pair("code_challenge_method", "S256")
            // sid finds the SSO session; auth_time drives step-up.
            .append_pair(
                "claims",
                &json!({ "id_token": { "sid": { "essential": true }, "auth_time": { "essential": true }, "amr": null } }).to_string(),
            );
        if req.query_param("fresh").is_some_and(|v| !v.is_empty()) {
            q.append_pair("max_age", "0");
        }
        if req.query_param("passkey").is_some_and(|v| !v.is_empty()) {
            q.append_pair("acr_values", crate::oidc::acr::PHR);
        }
    }
    let cookie = app.write_sealed(STATE_COOKIE, &pending, STATE_MINUTES * 60);
    Out::see_other(url.as_str()).cookie(cookie).into_response()
}

async fn callback(State(app): State<App>, req: Req) -> Response {
    let pending: Option<PendingLogin> = app.read_sealed(&req, STATE_COOKIE);
    let clear = app.clear_sealed(STATE_COOKIE);
    let back = |location: &str| Out::see_other(location).cookie(clear.clone()).into_response();
    if req.query_param("error").as_deref() == Some("access_denied") {
        return back("/signed-out");
    }
    let Some(pending) = pending else {
        return back("/console/login");
    };
    let result: anyhow::Result<Option<(ConsoleSession, String)>> = async {
        anyhow::ensure!(
            req.query_param("state").as_deref() == Some(pending.state.as_str()),
            "state mismatch"
        );
        anyhow::ensure!(
            req.query_param("iss").is_none_or(|iss| iss == app.issuer),
            "issuer mismatch"
        );
        let code = req.query_param("code").ok_or_else(|| anyhow::anyhow!("no code"))?;
        let client = app
            .clients
            .load(CONSOLE_CLIENT_ID)
            .await?
            .ok_or_else(|| anyhow::anyhow!("console client missing"))?;
        let form = BTreeMap::from([
            ("code".to_string(), code),
            ("redirect_uri".to_string(), format!("{}/console/callback", app.issuer)),
            ("code_verifier".to_string(), pending.verifier.clone()),
        ]);
        let exchanged = exchange_code(&app, &client, &form)
            .await
            .map_err(|e| anyhow::anyhow!("{}: {}", e.error, e.description))?;
        let id_token = exchanged.body["id_token"].as_str().unwrap_or_default();
        let payload: Value = id_token
            .split('.')
            .nth(1)
            .and_then(b64url_decode)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| anyhow::anyhow!("no ID token"))?;
        anyhow::ensure!(payload["nonce"] == pending.nonce.as_str(), "nonce mismatch");
        let sub = exchanged.account.id.to_string();
        let Some(sid) = exchanged.sid else { return Ok(None) };
        let Some(uid) = app.session_uid_for_sid(&sub, CONSOLE_CLIENT_ID, &sid).await? else {
            return Ok(None);
        };
        Ok(Some((
            ConsoleSession {
                sub,
                uid,
                auth_time: exchanged.auth_time,
                amr: exchanged.amr.unwrap_or_default(),
            },
            pending.return_to.clone(),
        )))
    }
    .await;
    match result {
        Ok(Some((session, return_to))) => Out::see_other(&safe_return_path(Some(&return_to), "/account"))
            .cookie(clear.clone())
            .cookie(app.write_sealed(SESSION_COOKIE, &session, SESSION_HOURS * 3600))
            .into_response(),
        Ok(None) => back("/console/login"),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "console sign-in failed");
            back("/error?code=invalid_request")
        }
    }
}

async fn logout(State(app): State<App>) -> Response {
    let mut url = url::Url::parse(&format!("{}/session/end", app.issuer)).expect("issuer URL");
    url.query_pairs_mut()
        .append_pair("client_id", CONSOLE_CLIENT_ID)
        .append_pair("post_logout_redirect_uri", &format!("{}/signed-out", app.issuer));
    let location = format!("{}?{}", url.path(), url.query().unwrap_or_default());
    Out::see_other(&location)
        .cookie(app.clear_console_session())
        .into_response()
}

// ── account API ──

async fn instance(State(app): State<App>) -> Response {
    reply(
        async {
            Ok(Out::json(
                StatusCode::OK,
                &json!({ "claimed": app.setup.claimed().await?, "instanceName": app.config.instance_name }),
            )
            .no_store())
        }
        .await,
    )
}

async fn me(State(app): State<App>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, session } = app.signed_in(&req, Need::default()).await?;
            let auth_time = Utc.timestamp_opt(session.auth_time, 0).single().map(iso);
            Ok(Out::json(
                StatusCode::OK,
                &json!({
                    "user": {
                        "sub": user.id,
                        "displayName": user.display_name,
                        "email": user.email,
                        "emailVerified": user.email_verified,
                        "isAdmin": user.is_admin,
                        "createdAt": iso(user.created_at),
                    },
                    "session": {
                        "uid": session.uid,
                        "authTime": auth_time,
                        "recentlyAuthenticated": recently_authenticated(&session, now()),
                    },
                    "instance": { "name": app.config.instance_name, "issuer": format!("{}/", app.issuer) },
                    "csrf": csrf_token(&app.csrf_key, &format!("console:{}", session.uid)),
                }),
            )
            .no_store())
        }
        .await,
    )
}

async fn list_passkeys(State(app): State<App>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, .. } = app.signed_in(&req, Need::default()).await?;
            let keys: Vec<Value> = app
                .passkeys
                .list_for_user(user.id)
                .await?
                .iter()
                .map(|p| p.view())
                .collect();
            Ok(Out::json(StatusCode::OK, &json!(keys)))
        }
        .await,
    )
}

async fn passkey_options(State(app): State<App>, req: Req) -> Response {
    reply(
        async {
            app.limits.guard(Limit::Interaction, &req.path, req.ip).await?;
            let Signed { user, session } = app
                .signed_in(
                    &req,
                    Need {
                        write: true,
                        step_up: true,
                        admin: false,
                    },
                )
                .await?;
            let handle = match &user.webauthn_user_handle {
                Some(handle) => handle.clone(),
                None => {
                    let handle = random_token(32);
                    app.pool
                        .get()
                        .await?
                        .execute(
                            "UPDATE users SET webauthn_user_handle = $2 WHERE id = $1",
                            &[&user.id, &handle],
                        )
                        .await?;
                    handle
                }
            };
            let existing = app.passkeys.existing(user.id).await?;
            let options = webauthn::registration_options(
                &app.rp,
                &PasskeyUser {
                    handle: &handle,
                    display_name: &user.display_name,
                    email: user.email.as_deref(),
                    username: user.preferred_username.as_deref(),
                },
                &existing,
            );
            let challenge = options["challenge"].as_str().unwrap_or_default();
            app.passkeys
                .save_challenge(
                    "register",
                    &format!("console:{}", session.uid),
                    challenge,
                    Some(user.id),
                    json!({}),
                )
                .await?;
            Ok(Out::json(StatusCode::OK, &options))
        }
        .await,
    )
}

async fn add_passkey(State(app): State<App>, req: Req) -> Response {
    reply(
        async {
            app.limits.guard(Limit::Interaction, &req.path, req.ip).await?;
            let Signed { user, session } = app
                .signed_in(
                    &req,
                    Need {
                        write: true,
                        step_up: true,
                        admin: false,
                    },
                )
                .await?;
            let body = req.json();
            let response = CredentialResponse::parse(body.get("response"));
            let challenge = response.as_ref().and_then(|r| r.challenge());
            let stored = match &challenge {
                Some(c) => {
                    app.passkeys
                        .consume_challenge("register", &format!("console:{}", session.uid), c)
                        .await?
                }
                None => None,
            };
            let (Some(response), Some(challenge), Some(stored)) = (response, challenge, stored) else {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "challenge_expired",
                    "That took too long. Try adding the passkey again.",
                ));
            };
            if stored.user_id != Some(user.id) {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "challenge_expired",
                    "That took too long. Try adding the passkey again.",
                ));
            }
            let verified = webauthn::verify_registration(&app.rp, &response, &challenge)
                .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "passkey_invalid", passkey_message(&e)))?;
            if app
                .passkeys
                .find_by_credential_id(&verified.credential_id)
                .await?
                .is_some()
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "passkey_exists",
                    "This passkey is already registered.",
                ));
            }
            let taken: Vec<String> = app
                .passkeys
                .list_for_user(user.id)
                .await?
                .into_iter()
                .map(|p| p.name)
                .collect();
            let db = app.pool.get().await?;
            let id = passkeys::add(&db, user.id, &verified, &clean_name(body.get("name"), &taken)).await?;
            Entry::new("passkey.added", Actor::User)
                .by(Some(user.id))
                .target("passkey", id)
                .from(ip_prefix(Some(req.ip)), req.user_agent())
                .meta(json!({ "synced": verified.backed_up }))
                .write(&db)
                .await?;
            Ok(Out::json(StatusCode::CREATED, &json!({ "id": id })))
        }
        .await,
    )
}

fn uuid_or_404(id: &str, what: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| ApiError::not_found(what))
}

async fn rename_passkey(State(app): State<App>, Path(id): Path<String>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, .. } = app
                .signed_in(
                    &req,
                    Need {
                        write: true,
                        ..Default::default()
                    },
                )
                .await?;
            let name = clean_name(req.json().get("name"), &[]);
            let id = uuid_or_404(&id, "passkey")?;
            if !app.passkeys.rename(user.id, id, &name).await? {
                return Err(ApiError::not_found("passkey"));
            }
            Entry::new("passkey.renamed", Actor::User)
                .by(Some(user.id))
                .target("passkey", id)
                .write(&app.pool.get().await?)
                .await?;
            Ok(Out::json(StatusCode::OK, &json!({ "name": name })))
        }
        .await,
    )
}

async fn remove_passkey(State(app): State<App>, Path(id): Path<String>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, .. } = app
                .signed_in(
                    &req,
                    Need {
                        write: true,
                        step_up: true,
                        admin: false,
                    },
                )
                .await?;
            let id = uuid_or_404(&id, "passkey")?;
            match app.passkeys.remove(user.id, id).await {
                Ok(Some(_)) => {}
                Ok(None) => return Err(ApiError::not_found("passkey")),
                Err(error) if error.is::<LastMethod>() => {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "last_method",
                        "This is your only passkey. Add another one first, so you can't get locked out.",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
            Entry::new("passkey.removed", Actor::User)
                .by(Some(user.id))
                .target("passkey", id)
                .from(ip_prefix(Some(req.ip)), None)
                .write(&app.pool.get().await?)
                .await?;
            Ok(Out::new(StatusCode::NO_CONTENT))
        }
        .await,
    )
}

async fn sessions(State(app): State<App>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, session } = app.signed_in(&req, Need::default()).await?;
            let list: Vec<Value> = app
                .list_sessions(&user.id.to_string())
                .await?
                .into_iter()
                .map(|mut s| {
                    s["current"] = json!(s["uid"] == session.uid.as_str());
                    s
                })
                .collect();
            Ok(Out::json(StatusCode::OK, &json!(list)))
        }
        .await,
    )
}

async fn end_session(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, session } = app
                .signed_in(
                    &req,
                    Need {
                        write: true,
                        ..Default::default()
                    },
                )
                .await?;
            if app.end_sessions(&user.id.to_string(), Some(&uid)).await? == 0 {
                return Err(ApiError::new(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "That session has already ended.",
                ));
            }
            Entry::new("session.revoked", Actor::User)
                .by(Some(user.id))
                .target("session", &uid)
                .write(&app.pool.get().await?)
                .await?;
            let mut out = Out::new(StatusCode::NO_CONTENT);
            if uid == session.uid {
                out = out.cookie(app.clear_console_session());
            }
            Ok(out)
        }
        .await,
    )
}

/// The escape hatch: deliberately no step-up, so it works even with a stolen passkey's session.
async fn sign_out_everywhere(State(app): State<App>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, .. } = app
                .signed_in(
                    &req,
                    Need {
                        write: true,
                        ..Default::default()
                    },
                )
                .await?;
            let ended = app.end_sessions(&user.id.to_string(), None).await?;
            Entry::new("session.revoked_all", Actor::User)
                .by(Some(user.id))
                .from(ip_prefix(Some(req.ip)), None)
                .meta(json!({ "sessions": ended }))
                .write(&app.pool.get().await?)
                .await?;
            Ok(Out::json(StatusCode::OK, &json!({ "ended": ended })).cookie(app.clear_console_session()))
        }
        .await,
    )
}

async fn identities(State(app): State<App>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, .. } = app.signed_in(&req, Need::default()).await?;
            let linked = app.identities.list_for_user(user.id).await?;
            // One identity per provider keeps the account page simple.
            let available: Vec<Value> = app
                .providers
                .list_enabled()
                .await?
                .into_iter()
                .filter(|p| !linked.iter().any(|l| l["provider"] == p["slug"]))
                .collect();
            Ok(Out::json(
                StatusCode::OK,
                &json!({ "linked": linked, "available": available }),
            ))
        }
        .await,
    )
}

async fn link_identity(State(app): State<App>, Path(slug): Path<String>, req: Req) -> Response {
    reply(
        async {
            app.limits.guard(Limit::Interaction, &req.path, req.ip).await?;
            let Signed { session, .. } = app
                .signed_in(
                    &req,
                    Need {
                        write: true,
                        step_up: true,
                        admin: false,
                    },
                )
                .await?;
            let Some((url, cookie)) =
                crate::upstream::routes::start_link(&app, &slug, &session.sub, &session.uid).await?
            else {
                return Err(ApiError::new(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "That sign-in provider is not available.",
                ));
            };
            Ok(Out::json(StatusCode::OK, &json!({ "redirectTo": url })).cookie(cookie))
        }
        .await,
    )
}

async fn unlink_identity(State(app): State<App>, Path(id): Path<String>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, .. } = app
                .signed_in(
                    &req,
                    Need {
                        write: true,
                        step_up: true,
                        admin: false,
                    },
                )
                .await?;
            let id = Uuid::parse_str(&id)
                .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "not_found", "That account is no longer linked."))?;
            match app.identities.unlink(user.id, id).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(ApiError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "That account is no longer linked.",
                    ));
                }
                Err(error) if error.is::<LastMethod>() => {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "last_method",
                        "This is your only way to sign in. Add a passkey first, so you can't get locked out.",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
            Entry::new("identity.unlinked", Actor::User)
                .by(Some(user.id))
                .target("identity", id)
                .from(ip_prefix(Some(req.ip)), None)
                .write(&app.pool.get().await?)
                .await?;
            Ok(Out::new(StatusCode::NO_CONTENT))
        }
        .await,
    )
}

const ACTIVITY: [&str; 10] = [
    "auth.sign_in.succeeded",
    "auth.sign_in.failed",
    "passkey.added",
    "passkey.removed",
    "identity.linked",
    "identity.unlinked",
    "recovery.issued",
    "recovery.used",
    "session.revoked_all",
    "instance.claimed",
];

/// Security activity on the account page: what changed, when, from roughly where.
async fn activity(State(app): State<App>, req: Req) -> Response {
    reply(
        async {
            let Signed { user, .. } = app.signed_in(&req, Need::default()).await?;
            let actions: Vec<&str> = ACTIVITY.to_vec();
            let db = app.pool.get().await?;
            let rows = db
                .query(
                    "SELECT at, action, metadata, abbrev(ip_prefix), client_id FROM audit_log \
                 WHERE (actor_user_id = $1 OR (target_type = 'user' AND target_id = $1::text)) AND action = ANY($2) \
                 ORDER BY at DESC LIMIT 20",
                    &[&user.id, &actions],
                )
                .await?;
            let list: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "at": iso(r.get(0)),
                        "action": r.get::<_, String>(1),
                        "metadata": r.get::<_, Value>(2),
                        "ipPrefix": r.get::<_, Option<String>>(3),
                        "clientId": r.get::<_, Option<String>>(4),
                    })
                })
                .collect();
            Ok(Out::json(StatusCode::OK, &json!(list)))
        }
        .await,
    )
}

pub fn routes() -> Router<App> {
    Router::new()
        .route("/console/login", get(login))
        .route("/console/callback", get(callback))
        .route("/console/logout", get(logout))
        .route("/api/instance", get(instance))
        .route("/api/me", get(me))
        .route("/api/me/passkeys", get(list_passkeys).post(add_passkey))
        .route("/api/me/passkeys/options", post(passkey_options))
        .route("/api/me/passkeys/{id}", patch(rename_passkey).delete(remove_passkey))
        .route("/api/me/sessions", get(sessions))
        .route("/api/me/sessions/{uid}", delete(end_session))
        .route("/api/me/sign-out-everywhere", post(sign_out_everywhere))
        .route("/api/me/identities", get(identities))
        .route("/api/me/identities/link/{slug}", post(link_identity))
        .route("/api/me/identities/{id}", delete(unlink_identity))
        .route("/api/me/activity", get(activity))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_paths_stay_on_this_origin() {
        assert_eq!(
            safe_return_path(Some("/admin/users?q=a#x"), "/account"),
            "/admin/users?q=a#x"
        );
        for bad in [
            "//evil.example",
            "/\\evil.example",
            "https://evil.example",
            "javascript:alert(1)",
            "/a\u{7}b",
            "",
        ] {
            assert_eq!(safe_return_path(Some(bad), "/account"), "/account", "{bad}");
        }
        assert_eq!(safe_return_path(None, "/account"), "/account");
    }

    #[test]
    fn step_up_window_is_five_minutes() {
        let session = ConsoleSession {
            sub: "s".into(),
            uid: "u".into(),
            auth_time: 1_000,
            amr: vec![],
        };
        assert!(recently_authenticated(&session, 1_000 + 300));
        assert!(!recently_authenticated(&session, 1_000 + 301));
    }
}
