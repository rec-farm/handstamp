//! Sign-in and linking through GitHub, Google or a generic OIDC issuer (docs/PLAN.md §1.4 B).
//! The provider calls back to a fixed URL, which can't see the path-scoped interaction cookie, so
//! the result is parked in a sealed cookie and finished under /interaction/:uid (M1-2).

use std::collections::HashMap;

use axum::{
    Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::{
    client::{self, Pending},
    providers::UpstreamIdentity,
};
use crate::{
    app::App,
    audit::{Actor, Entry},
    enrollment,
    http::{ApiError, Limit, Out, Req},
    identities::IdentityTaken,
    interaction::{ENROLL_COOKIE, EnrollState, complete_sign_in, record_refusal},
    oidc::{models::Interaction, store::INTERACTION},
};

const STATE_COOKIE: &str = "hs_upstream";
const STATE_SECONDS: i64 = 10 * 60;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamState {
    #[serde(flatten)]
    pending: Pending,
    /// "login" or "link".
    purpose: String,
    slug: String,
    /// login: the interaction to resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uid: Option<String>,
    /// link: the signed-in user…
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    /// …and their console session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    console_uid: Option<String>,
    /// Set once the provider answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<UpstreamIdentity>,
}

fn callback_url(app: &App, slug: &str) -> String {
    format!("{}/upstream/{slug}/callback", app.issuer)
}

/// Redirects to the provider, remembering the flow in the state cookie. None: no such provider.
async fn begin(
    app: &App,
    slug: &str,
    purpose: &str,
    uid: Option<String>,
    sub: Option<String>,
    console_uid: Option<String>,
) -> anyhow::Result<Option<(String, String)>> {
    let Some(provider) = app.providers.load(slug).await? else {
        return Ok(None);
    };
    let (url, pending) = client::begin(&provider, &callback_url(app, slug)).await?;
    let state = UpstreamState {
        pending,
        purpose: purpose.into(),
        slug: slug.into(),
        uid,
        sub,
        console_uid,
        identity: None,
    };
    Ok(Some((url, app.write_sealed(STATE_COOKIE, &state, STATE_SECONDS))))
}

/// Starts linking another identity to a signed-in user: the provider URL and the state cookie.
pub async fn start_link(
    app: &App,
    slug: &str,
    sub: &str,
    console_uid: &str,
) -> anyhow::Result<Option<(String, String)>> {
    begin(app, slug, "link", None, Some(sub.into()), Some(console_uid.into())).await
}

fn back(uid: &str, error: &str) -> String {
    format!("/interaction/{uid}?error={error}")
}

fn see_other(location: &str, cookies: Vec<String>) -> Response {
    Out::see_other(location).cookies(cookies).into_response()
}

/// The interaction this browser is in, by its path-scoped cookie.
async fn interaction_of(app: &App, req: &Req) -> anyhow::Result<Option<Interaction>> {
    let Some(cookie) = req.cookie(app.cookie_names().interaction) else {
        return Ok(None);
    };
    Ok(app
        .store
        .find::<Interaction>(INTERACTION, cookie)
        .await?
        .map(|f| f.value))
}

/// GET /interaction/:uid/upstream/:slug
async fn start(State(app): State<App>, Path((uid, slug)): Path<(String, String)>, req: Req) -> Response {
    if !app.limits.check(Limit::Authorization, &req.path, req.ip) {
        return ApiError::rate_limited().into_response();
    }
    let interaction = match interaction_of(&app, &req).await {
        Ok(Some(i)) => i,
        Ok(None) => return see_other("/error?code=session_not_found", vec![]),
        Err(e) => return ApiError::from(e).into_response(),
    };
    if interaction.uid != uid || interaction.prompt.name != "login" {
        return see_other(&format!("/interaction/{}", interaction.uid), vec![]);
    }
    if crate::oidc::acr::needs_passkey(&interaction.params) {
        return see_other(&back(&interaction.uid, "passkey_required"), vec![]);
    }
    match begin(&app, &slug, "login", Some(interaction.uid.clone()), None, None).await {
        Ok(Some((url, cookie))) => see_other(&url, vec![cookie]),
        Ok(None) => see_other(&back(&interaction.uid, "provider_unavailable"), vec![]),
        Err(error) => {
            tracing::warn!(provider = %slug, error = %format!("{error:#}"), "upstream sign-in could not start");
            see_other(&back(&interaction.uid, "upstream_failed"), vec![])
        }
    }
}

/// GET /upstream/:slug/callback
async fn callback(State(app): State<App>, Path(slug): Path<String>, req: Req) -> Response {
    if !app.limits.check(Limit::Authorization, &req.path, req.ip) {
        return ApiError::rate_limited().into_response();
    }
    match callback_inner(&app, &slug, &req).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn callback_inner(app: &App, slug: &str, req: &Req) -> Result<Response, ApiError> {
    let pending: Option<UpstreamState> = app.read_sealed(req, STATE_COOKIE);
    let clear = app.clear_sealed(STATE_COOKIE);
    let Some(pending) = pending.filter(|p| p.slug == slug) else {
        return Ok(see_other("/error?code=session_not_found", vec![clear]));
    };
    let fail = |code: &str| {
        let location = if pending.purpose == "link" {
            format!("/account?error={code}")
        } else {
            back(pending.uid.as_deref().unwrap_or_default(), code)
        };
        see_other(&location, vec![clear.clone()])
    };
    let Some(provider) = app.providers.load(&pending.slug).await? else {
        return Ok(fail("provider_unavailable"));
    };
    let query: HashMap<String, String> = req.query_pairs().into_iter().collect();
    let identity = match client::finish(&provider, &query, &callback_url(app, slug), &pending.pending).await {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(provider = %provider.slug, error = %error, "upstream sign-in failed");
            return Ok(fail(error.code));
        }
    };

    if pending.purpose == "link" {
        // Linking needs the same signed-in console session that started it (S14).
        let session = app.console_session(req);
        let same = match &session {
            Some(s) => {
                Some(&s.sub) == pending.sub.as_ref()
                    && Some(&s.uid) == pending.console_uid.as_ref()
                    && app.session_exists(&s.sub, &s.uid).await?
            }
            None => false,
        };
        let (Some(session), true) = (session, same) else {
            return Ok(fail("link_expired"));
        };
        let user = Uuid::parse_str(&session.sub).map_err(|_| ApiError::server())?;
        if let Err(error) = app.identities.link(user, &provider, &identity).await {
            if !error.is::<IdentityTaken>() {
                return Err(error.into());
            }
            Entry::new("identity.link_refused", Actor::User)
                .by(Some(user))
                .meta(json!({ "provider": provider.slug, "reason": "identity_taken" }))
                .write(&app.pool.get().await?)
                .await?;
            return Ok(fail("identity_taken"));
        }
        Entry::new("identity.linked", Actor::User)
            .by(Some(user))
            .target("identity", format!("{}#{}", identity.issuer, identity.subject))
            .meta(json!({ "provider": provider.slug }))
            .write(&app.pool.get().await?)
            .await?;
        return Ok(see_other(&format!("/account?linked={}", provider.slug), vec![clear]));
    }

    let uid = pending.uid.clone().unwrap_or_default();
    let done = UpstreamState {
        identity: Some(identity),
        ..pending
    };
    Ok(see_other(
        &format!("/interaction/{uid}/upstream/complete"),
        vec![app.write_sealed(STATE_COOKIE, &done, STATE_SECONDS)],
    ))
}

/// GET /interaction/:uid/upstream/complete
async fn complete(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    match complete_inner(&app, &uid, &req).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn complete_inner(app: &App, path_uid: &str, req: &Req) -> Result<Response, ApiError> {
    let done: Option<UpstreamState> = app.read_sealed(req, STATE_COOKIE);
    let mut cookies = vec![app.clear_sealed(STATE_COOKIE)];
    let Some(interaction) = interaction_of(app, req).await? else {
        return Ok(see_other("/error?code=session_not_found", cookies));
    };
    let uid = interaction.uid.clone();
    let Some((done, identity)) = done
        .filter(|d| d.uid.as_deref() == Some(uid.as_str()) && uid == path_uid)
        .and_then(|d| d.identity.clone().map(|i| (d, i)))
    else {
        return Ok(see_other(&back(&uid, "upstream_expired"), cookies));
    };
    let Some(provider) = app.providers.load(&done.slug).await? else {
        return Ok(see_other(&back(&uid, "provider_unavailable"), cookies));
    };
    let client_id = interaction.client_id().to_string();
    macro_rules! refuse {
        ($reason:expr, $user:expr) => {{
            record_refusal(app, req, &client_id, &provider.slug, $reason, $user).await?;
            return Ok(see_other(&back(&uid, $reason), cookies));
        }};
    }

    let enroll: Option<EnrollState> = app.read_sealed(req, ENROLL_COOKIE);
    let enrollment = match enroll {
        Some(state) => app.enrollments.by_id(state.enrollment_id).await?,
        None => None,
    };
    let existing = app.identities.find(&identity.issuer, &identity.subject).await?;
    let mut method = provider.slug.clone();
    let recovery = enrollment.as_ref().filter(|e| e.purpose == "recovery");
    let account: Uuid = if let Some(existing) = existing {
        // A recovery link for one person can't be finished with someone else's identity.
        if let Some(recovery) = recovery {
            if Some(existing.user_id) != recovery.user_id {
                refuse!("identity_taken", Some(existing.user_id));
            }
            if !finish_recovery(app, recovery.id, existing.user_id, recovery.revoke_other_methods).await? {
                refuse!("enrollment_expired", Some(existing.user_id));
            }
            cookies.push(app.clear_sealed(ENROLL_COOKIE));
            method = format!("{}_recovery", provider.slug);
        }
        app.identities.touch(existing.id, &identity).await?;
        existing.user_id
    } else if let Some(invite) = enrollment.as_ref().filter(|e| e.purpose == "invite") {
        let consumed = {
            let mut db = app.pool.get().await?;
            let tx = db.transaction().await?;
            let consumed = enrollment::consume(&tx, invite.id, None).await?;
            tx.commit().await?;
            consumed
        };
        if !consumed {
            refuse!("enrollment_expired", None);
        }
        let user = app.identities.create_user(&provider, &identity, "invite").await?;
        app.enrollments.record_consumer(invite.id, user).await?;
        Entry::new("invite.used", Actor::User)
            .by(Some(user))
            .target("enrollment", invite.id)
            .write(&app.pool.get().await?)
            .await?;
        cookies.push(app.clear_sealed(ENROLL_COOKIE));
        user
    } else if let Some(recovery) = recovery {
        let user = recovery.user_id.ok_or_else(ApiError::server)?;
        if let Err(error) = app.identities.link(user, &provider, &identity).await {
            if error.is::<IdentityTaken>() {
                refuse!("identity_taken", None);
            }
            return Err(error.into());
        }
        if !finish_recovery(app, recovery.id, user, recovery.revoke_other_methods).await? {
            refuse!("enrollment_expired", Some(user));
        }
        cookies.push(app.clear_sealed(ENROLL_COOKIE));
        method = format!("{}_recovery", provider.slug);
        user
    } else {
        // Unknown identity, no invite: only the provider's sign-up policy can let them in. The
        // answer is the same whether or not someone already uses that email here (§3.3).
        if let Err(reason) = provider.signup_decision(&identity) {
            refuse!(
                if reason == "signup_closed" {
                    "unlinked_identity"
                } else {
                    reason
                },
                None
            );
        }
        app.identities.create_user(&provider, &identity, "signup").await?
    };

    let active = app
        .pool
        .get()
        .await?
        .query_opt("SELECT 1 FROM users WHERE id = $1 AND status = 'active'", &[&account])
        .await?
        .is_some();
    if !active {
        refuse!("account_disabled", Some(account));
    }
    let redirect = complete_sign_in(app, req, &interaction, account, &method, None).await?;
    Ok(see_other(&redirect, cookies))
}

/// Recovery: consume the link, and on "I lost my device" drop every old passkey and session.
/// False when the link was already used (two tabs racing): the second one gets nothing.
async fn finish_recovery(app: &App, enrollment_id: Uuid, user: Uuid, revoke_others: bool) -> Result<bool, ApiError> {
    {
        let mut db = app.pool.get().await?;
        let tx = db.transaction().await?;
        if !enrollment::consume(&tx, enrollment_id, Some(user)).await? {
            return Ok(false);
        }
        if revoke_others {
            enrollment::revoke_other_passkeys(&tx, user).await?;
        }
        tx.commit().await?;
    }
    if revoke_others {
        app.end_sessions(&user.to_string(), None).await?;
    }
    Entry::new("recovery.used", Actor::User)
        .by(Some(user))
        .target("user", user)
        .meta(json!({ "revoked_other_methods": revoke_others }))
        .write(&app.pool.get().await?)
        .await?;
    Ok(true)
}

pub fn routes() -> Router<App> {
    Router::new()
        .route("/interaction/{uid}/upstream/complete", get(complete))
        .route("/interaction/{uid}/upstream/{slug}", get(start))
        .route("/upstream/{slug}/callback", get(callback))
}
