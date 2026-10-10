//! The JSON API behind the sign-in card. It lives under /interaction/:uid because that is the path
//! the interaction cookie is scoped to. The SPA page itself is GET /interaction/:uid.

use std::sync::LazyLock;

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use regex::Regex;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    accounts,
    app::App,
    audit::{Actor, Entry, ip_prefix},
    clients::CONSOLE_CLIENT_ID,
    crypto::{csrf_token, csrf_valid},
    enrollment::{self, Enrollment, Profile, SetupError},
    http::{ApiError, ApiResult, CSRF_HEADER, Limit, Out, Req},
    oidc::{
        acr,
        authorize::save_grant,
        models::{ConsentResult, Grant, Interaction, InteractionResult, LoginResult},
        store::{GRANT, INTERACTION, now},
    },
    passkeys::{self, clean_name, new_user_handle, passkey_message},
    webauthn::{self, CredentialResponse, PasskeyUser},
};

/// Passkey sign-ins prove possession (pop) and user verification (user): RFC 8176.
pub const PASSKEY_AMR: [&str; 3] = ["pop", "user", "mfa"];
pub const ENROLL_COOKIE: &str = "hs_enroll";
static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap());

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollState {
    pub enrollment_id: Uuid,
}

fn problem(status: StatusCode, code: &'static str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}

pub fn passkey_required() -> ApiError {
    problem(
        StatusCode::FORBIDDEN,
        "passkey_required",
        "This sign-in needs your passkey. Use it to continue.",
    )
}

fn expired() -> ApiError {
    problem(
        StatusCode::GONE,
        "interaction_expired",
        "This sign-in request has expired. Go back to the app and start again.",
    )
}

/// The interaction this browser is in, by its path-scoped cookie (oidc-provider's interactionDetails).
pub async fn load(app: &App, req: &Req, uid: &str) -> ApiResult<Interaction> {
    let Some(cookie) = req.cookie(app.cookie_names().interaction) else {
        return Err(expired());
    };
    let Some(found) = app.store.find::<Interaction>(INTERACTION, cookie).await? else {
        return Err(expired());
    };
    if found.value.uid != uid {
        return Err(problem(
            StatusCode::CONFLICT,
            "interaction_mismatch",
            "This sign-in page belongs to a different request. Go back to the app and start again.",
        ));
    }
    Ok(found.value)
}

/// Records the outcome and returns where the browser goes next (/auth/:uid).
pub async fn interaction_result(
    app: &App,
    req: &Req,
    interaction: &Interaction,
    result: InteractionResult,
    merge: bool,
) -> ApiResult<String> {
    let mut interaction = interaction.clone();
    let mut merged = if merge {
        interaction.last_submission.clone().unwrap_or_default()
    } else {
        InteractionResult::default()
    };
    if result.login.is_some() {
        merged.login = result.login;
    }
    if result.consent.is_some() {
        merged.consent = result.consent;
    }
    if result.error.is_some() {
        merged.error = result.error;
        merged.error_description = result.error_description;
    }
    interaction.result = Some(merged);
    app.store
        .save(
            INTERACTION,
            &interaction.uid,
            &interaction,
            crate::oidc::store::Columns {
                uid: Some(&interaction.uid),
                ..Default::default()
            },
            interaction.exp,
        )
        .await?;
    let _ = req;
    Ok(format!("{}/auth/{}", app.issuer, interaction.uid))
}

/// Ends an interaction with a signed-in account and records it.
pub async fn complete_sign_in(
    app: &App,
    req: &Req,
    interaction: &Interaction,
    account_id: Uuid,
    method: &str,
    amr: Option<&[&str]>,
) -> ApiResult<String> {
    // The card only offers a passkey then; this holds even for a hand-made request (R11).
    if amr.is_none() && acr::needs_passkey(&interaction.params) {
        return Err(passkey_required());
    }
    let login = LoginResult {
        account_id: account_id.to_string(),
        amr: amr.map(|a| a.iter().map(|s| s.to_string()).collect()),
        ts: now(),
    };
    let redirect = interaction_result(
        app,
        req,
        interaction,
        InteractionResult {
            login: Some(login),
            ..Default::default()
        },
        true,
    )
    .await?;
    let db = app.pool.get().await?;
    db.execute("UPDATE users SET last_sign_in_at = now() WHERE id = $1", &[&account_id])
        .await?;
    Entry::new("auth.sign_in.succeeded", Actor::User)
        .by(Some(account_id))
        .client(interaction.client_id())
        .from(ip_prefix(Some(req.ip)), req.user_agent())
        .meta(json!({ "method": method }))
        .write(&db)
        .await?;
    Ok(redirect)
}

pub async fn record_refusal(
    app: &App,
    req: &Req,
    client_id: &str,
    method: &str,
    reason: &str,
    user: Option<Uuid>,
) -> ApiResult<()> {
    let action = if method == "passkey" {
        "auth.sign_in.failed"
    } else {
        "auth.sign_in.refused"
    };
    Entry::new(action, Actor::User)
        .by(user)
        .client(client_id)
        .from(ip_prefix(Some(req.ip)), req.user_agent())
        .meta(json!({ "method": method, "reason": reason }))
        .write(&app.pool.get().await?)
        .await?;
    Ok(())
}

fn conformance_form(app: &App, req: &Req) -> bool {
    app.config.conformance_mode && req.is_form()
}

fn guard(app: &App, req: &Req, uid: &str) -> ApiResult<()> {
    let form = conformance_form(app, req);
    let token = if form {
        req.form_pairs().into_iter().find(|(k, _)| k == "csrf").map(|(_, v)| v)
    } else {
        req.header(CSRF_HEADER).map(str::to_string)
    };
    // The conformance browser may send neither Origin nor Sec-Fetch-Site; its forms still carry the token.
    let origin_ok = req.same_origin(&app.issuer) || (form && req.header("origin").is_none());
    if !origin_ok || !csrf_valid(&app.csrf_key, &format!("interaction:{uid}"), token.as_deref()) {
        return Err(ApiError::csrf());
    }
    Ok(())
}

fn finish(app: &App, req: &Req, redirect: String) -> Out {
    if conformance_form(app, req) {
        return Out::see_other(&redirect);
    }
    Out::json(StatusCode::OK, &json!({ "redirectTo": redirect }))
}

fn require_login_step(interaction: &Interaction) -> ApiResult<()> {
    if interaction.prompt.name != "login" {
        return Err(problem(
            StatusCode::CONFLICT,
            "wrong_step",
            "You are already signed in. Reload the page to continue.",
        ));
    }
    Ok(())
}

/// An invite or recovery link in progress, for the console's own sign-in only.
pub async fn pending_enrollment(app: &App, req: &Req, client_id: &str) -> ApiResult<Option<Enrollment>> {
    if client_id != CONSOLE_CLIENT_ID {
        return Ok(None);
    }
    let Some(state) = app.read_sealed::<EnrollState>(req, ENROLL_COOKIE) else {
        return Ok(None);
    };
    Ok(app.enrollments.by_id(state.enrollment_id).await?)
}

fn limited(app: &App, req: &Req, limit: Limit) -> ApiResult<()> {
    app.limits.guard(limit, &req.path, req.ip)
}

fn reply(result: ApiResult<Out>) -> Response {
    match result {
        Ok(out) => out.into_response(),
        Err(error) => error.into_response(),
    }
}

/// Plain no-JS forms the conformance suite's browser automation can click (S17).
async fn conformance_page(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(async {
        limited(&app, &req, Limit::Interaction)?;
        let interaction = load(&app, &req, &uid).await?;
        let csrf = csrf_token(&app.csrf_key, &format!("interaction:{}", interaction.uid));
        let action = if interaction.prompt.name == "login" { "dev-login" } else { "consent" };
        let (title, label) = if action == "dev-login" { ("Sign in", "Continue as test user") } else { ("Consent", "Allow") };
        let html = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Handstamp conformance</title></head><body>\n<h1>{title}</h1>\n<form method=\"post\" action=\"/interaction/{}/{action}\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\n<button id=\"hs-continue\" type=\"submit\">{label}</button></form></body></html>",
            interaction.uid
        );
        Ok(Out::html(StatusCode::OK, html).no_store())
    }
    .await)
}

async fn details(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Interaction)?;
            let interaction = load(&app, &req, &uid).await?;
            let client = app.clients.load(interaction.client_id()).await?;
            let client_id = client.as_ref().map(|c| c.client_id.clone());
            let enrollment = pending_enrollment(&app, &req, client_id.as_deref().unwrap_or_default()).await?;
            let mode = if client_id.as_deref() == Some(CONSOLE_CLIENT_ID) && !app.setup.claimed().await? {
                // The console's own sign-in doubles as first-run setup until someone claims the instance.
                "claim".to_string()
            } else {
                enrollment
                    .as_ref()
                    .map(|e| e.purpose.clone())
                    .unwrap_or_else(|| "sign-in".into())
            };
            let db = app.pool.get().await?;
            let enrolling_as = match &enrollment {
                Some(e) if e.purpose == "recovery" => match e.user_id {
                    Some(user) => accounts::display_name(&db, user).await?,
                    None => None,
                },
                _ => None,
            };
            // The app (or the console's step-up) asked for acr phr: only a passkey will do.
            let passkey_only = acr::needs_passkey(&interaction.params);
            let required_group = if interaction.prompt.name == "access" {
                match interaction
                    .prompt
                    .details
                    .get("requiredGroup")
                    .and_then(Value::as_str)
                    .and_then(|id| Uuid::parse_str(id).ok())
                {
                    Some(id) => db
                        .query_opt("SELECT slug, name FROM groups WHERE id = $1", &[&id])
                        .await?
                        .map(|r| json!({ "slug": r.get::<_, String>(0), "name": r.get::<_, String>(1) })),
                    None => None,
                }
            } else {
                None
            };
            drop(db);
            let mut body = json!({
                "uid": interaction.uid,
                "prompt": {
                    "name": interaction.prompt.name,
                    "reasons": interaction.prompt.reasons,
                    "missingScopes": interaction.prompt.details.get("missingOIDCScope").cloned().unwrap_or(json!([])),
                },
                "client": {
                    "clientId": client_id,
                    "name": client.as_ref().map(|c| c.display_name().to_string()),
                },
                "instanceName": app.config.instance_name,
                "issuer": app.issuer,
                "devLogin": app.test_user.is_some(),
                "mode": mode,
                "setupVerified": app.setup.is_verified(&interaction.uid).await?,
                "passkeyOnly": passkey_only,
                "stepUp": passkey_only && client_id.as_deref() == Some(CONSOLE_CLIENT_ID),
                "providers": if passkey_only { vec![] } else { app.providers.list_enabled().await? },
                "csrf": csrf_token(&app.csrf_key, &format!("interaction:{}", interaction.uid)),
            });
            if let Some(name) = enrolling_as {
                body["enrollingAs"] = json!(name);
            }
            if let Some(group) = required_group {
                body["requiredGroup"] = group;
            }
            Ok(Out::json(StatusCode::OK, &body).no_store())
        }
        .await,
    )
}

async fn dev_login(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Interaction)?;
            guard(&app, &req, &uid)?;
            let Some(test_user) = app.test_user else {
                return Err(problem(StatusCode::NOT_FOUND, "not_found", "Not found."));
            };
            let interaction = load(&app, &req, &uid).await?;
            require_login_step(&interaction)?;
            let redirect = complete_sign_in(&app, &req, &interaction, test_user, "dev_test_account", None).await?;
            Ok(finish(&app, &req, redirect))
        }
        .await,
    )
}

async fn consent(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Interaction)?;
            guard(&app, &req, &uid)?;
            let interaction = load(&app, &req, &uid).await?;
            let (Some(account), true) = (interaction.account_id.clone(), interaction.prompt.name == "consent") else {
                return Err(problem(
                    StatusCode::CONFLICT,
                    "wrong_step",
                    "There is nothing to approve. Reload the page to continue.",
                ));
            };
            let mut grant = match &interaction.grant_id {
                Some(id) => app
                    .store
                    .find::<Grant>(GRANT, id)
                    .await?
                    .map(|f| f.value)
                    .ok_or_else(|| {
                        problem(
                            StatusCode::GONE,
                            "grant_missing",
                            "This request expired. Go back to the app and start again.",
                        )
                    })?,
                None => Grant::new(&account, interaction.client_id(), app.session_ttl()),
            };
            let details = &interaction.prompt.details;
            let strings = |key: &str| -> Vec<String> {
                details
                    .get(key)
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default()
            };
            let scopes = strings("missingOIDCScope");
            grant.add_scopes(scopes.iter().map(String::as_str));
            grant.add_claims(strings("missingOIDCClaims").iter().map(String::as_str));
            grant.exp = now() + app.session_ttl();
            save_grant(&app, &grant).await?;
            let consent = ConsentResult {
                grant_id: interaction.grant_id.is_none().then(|| grant.jti.clone()),
            };
            let redirect = interaction_result(
                &app,
                &req,
                &interaction,
                InteractionResult {
                    consent: Some(consent),
                    ..Default::default()
                },
                true,
            )
            .await?;
            let user = Uuid::parse_str(&account).ok();
            Entry::new("auth.consent.granted", Actor::User)
                .by(user)
                .client(interaction.client_id())
                .meta(json!({ "scopes": scopes }))
                .write(&app.pool.get().await?)
                .await?;
            Ok(finish(&app, &req, redirect))
        }
        .await,
    )
}

async fn abort(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Interaction)?;
            guard(&app, &req, &uid)?;
            let interaction = load(&app, &req, &uid).await?;
            let result = InteractionResult {
                error: Some("access_denied".into()),
                error_description: Some("The user cancelled the sign-in.".into()),
                ..Default::default()
            };
            let redirect = interaction_result(&app, &req, &interaction, result, false).await?;
            Ok(Out::json(StatusCode::OK, &json!({ "redirectTo": redirect })))
        }
        .await,
    )
}

fn challenge_expired(message: &str) -> ApiError {
    problem(StatusCode::BAD_REQUEST, "challenge_expired", message)
}

// ── passkey sign-in ──

async fn passkey_options(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Interaction)?;
            guard(&app, &req, &uid)?;
            let interaction = load(&app, &req, &uid).await?;
            require_login_step(&interaction)?;
            let options = webauthn::authentication_options(&app.rp);
            let challenge = options["challenge"].as_str().unwrap_or_default();
            app.passkeys
                .save_challenge(
                    "authenticate",
                    &format!("interaction:{}", interaction.uid),
                    challenge,
                    None,
                    json!({}),
                )
                .await?;
            Ok(Out::json(StatusCode::OK, &options))
        }
        .await,
    )
}

async fn passkey_verify(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Interaction)?;
            guard(&app, &req, &uid)?;
            let interaction = load(&app, &req, &uid).await?;
            require_login_step(&interaction)?;
            let client_id = interaction.client_id().to_string();
            let body = req.json();
            let response = CredentialResponse::parse(body.get("response"));
            let challenge = response.as_ref().and_then(|r| r.challenge());
            let stored = match &challenge {
                Some(c) => {
                    app.passkeys
                        .consume_challenge("authenticate", &format!("interaction:{}", interaction.uid), c)
                        .await?
                }
                None => None,
            };
            let (Some(response), Some(challenge), Some(_)) = (response, challenge, stored) else {
                return Err(challenge_expired("That took too long. Try your passkey again."));
            };
            let Some(passkey) = app.passkeys.find_by_credential_id(&response.id).await? else {
                record_refusal(&app, &req, &client_id, "passkey", "unknown_credential", None).await?;
                return Err(problem(
                    StatusCode::UNAUTHORIZED,
                    "unknown_passkey",
                    "This passkey isn't registered with this Handstamp instance. Try another one, or ask your admin.",
                ));
            };
            let db = app.pool.get().await?;
            let active = db
                .query_opt(
                    "SELECT 1 FROM users WHERE id = $1 AND status = 'active'",
                    &[&passkey.user_id],
                )
                .await?
                .is_some();
            drop(db);
            if !active {
                record_refusal(
                    &app,
                    &req,
                    &client_id,
                    "passkey",
                    "user_disabled",
                    Some(passkey.user_id),
                )
                .await?;
                return Err(problem(
                    StatusCode::FORBIDDEN,
                    "account_disabled",
                    "This account is turned off. Ask your admin.",
                ));
            }
            let stored = webauthn::StoredPasskey {
                credential_id: &passkey.credential_id,
                public_key: &passkey.public_key,
                sign_count: passkey.sign_count,
            };
            let verified = match webauthn::verify_authentication(&app.rp, &response, &challenge, &stored) {
                Ok(v) => v,
                Err(error) => {
                    let reason = if error == webauthn::PasskeyError::Counter {
                        "counter"
                    } else {
                        "invalid"
                    };
                    record_refusal(&app, &req, &client_id, "passkey", reason, Some(passkey.user_id)).await?;
                    return Err(problem(
                        StatusCode::UNAUTHORIZED,
                        "passkey_invalid",
                        passkey_message(&error),
                    ));
                }
            };
            app.passkeys
                .record_use(passkey.id, verified.sign_count, verified.backed_up)
                .await?;
            let redirect =
                complete_sign_in(&app, &req, &interaction, passkey.user_id, "passkey", Some(&PASSKEY_AMR)).await?;
            Ok(Out::json(StatusCode::OK, &json!({ "redirectTo": redirect })))
        }
        .await,
    )
}

// ── first-run setup: claim the instance (docs/PLAN.md §1.4 C) ──

async fn require_claimable(app: &App, interaction: &Interaction) -> ApiResult<()> {
    if interaction.client_id() != CONSOLE_CLIENT_ID || app.setup.claimed().await? {
        return Err(problem(
            StatusCode::CONFLICT,
            "already_claimed",
            "This Handstamp instance already has an admin.",
        ));
    }
    Ok(())
}

async fn setup_verify(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(async {
        limited(&app, &req, Limit::Setup)?;
        guard(&app, &req, &uid)?;
        let interaction = load(&app, &req, &uid).await?;
        require_login_step(&interaction)?;
        require_claimable(&app, &interaction).await?;
        let code = req.json().get("code").and_then(Value::as_str).unwrap_or_default().to_string();
        if !app.setup.verify_code(&code, &interaction.uid).await? {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "code_invalid",
                "That setup code didn't match. Copy the latest one from the server logs (restarting prints a new one).",
            ));
        }
        Ok(Out::json(StatusCode::OK, &json!({ "verified": true })))
    }
    .await)
}

fn text(body: &Value, key: &str, max: usize) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .chars()
        .take(max)
        .collect()
}

async fn setup_passkey_options(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Interaction)?;
            guard(&app, &req, &uid)?;
            let interaction = load(&app, &req, &uid).await?;
            require_login_step(&interaction)?;
            require_claimable(&app, &interaction).await?;
            if !app.setup.is_verified(&interaction.uid).await? {
                return Err(problem(
                    StatusCode::FORBIDDEN,
                    "code_required",
                    "Enter the setup code from the server logs first.",
                ));
            }
            let body = req.json();
            let display_name = text(&body, "displayName", 80);
            let email = text(&body, "email", 254);
            if display_name.is_empty() {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "name_required",
                    "Add your name so people know who the admin is.",
                ));
            }
            if !email.is_empty() && !EMAIL.is_match(&email) {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "email_invalid",
                    "That email address needs an @ and a domain.",
                ));
            }
            let handle = new_user_handle();
            let user = PasskeyUser {
                handle: &handle,
                display_name: &display_name,
                email: Some(&email),
                username: None,
            };
            let options = webauthn::registration_options(&app.rp, &user, &[]);
            let challenge = options["challenge"].as_str().unwrap_or_default();
            app.passkeys
                .save_challenge(
                    "setup",
                    &format!("interaction:{}", interaction.uid),
                    challenge,
                    None,
                    json!({ "handle": handle, "displayName": display_name, "email": email }),
                )
                .await?;
            Ok(Out::json(StatusCode::OK, &options))
        }
        .await,
    )
}

async fn setup_passkey_verify(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Interaction)?;
            guard(&app, &req, &uid)?;
            let interaction = load(&app, &req, &uid).await?;
            require_login_step(&interaction)?;
            require_claimable(&app, &interaction).await?;
            let body = req.json();
            let response = CredentialResponse::parse(body.get("response"));
            let challenge = response.as_ref().and_then(|r| r.challenge());
            let stored = match &challenge {
                Some(c) => {
                    app.passkeys
                        .consume_challenge("setup", &format!("interaction:{}", interaction.uid), c)
                        .await?
                }
                None => None,
            };
            let (Some(response), Some(challenge), Some(stored)) = (response, challenge, stored) else {
                return Err(challenge_expired("That took too long. Create the passkey again."));
            };
            let verified = webauthn::verify_registration(&app.rp, &response, &challenge)
                .map_err(|e| problem(StatusCode::BAD_REQUEST, "passkey_invalid", passkey_message(&e)))?;
            let pending = |key: &str| {
                stored
                    .pending
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            let profile = Profile {
                display_name: pending("displayName"),
                email: Some(pending("email")).filter(|e| !e.is_empty()),
                handle: pending("handle"),
            };
            let user = match app
                .setup
                .claim(
                    &interaction.uid,
                    &profile,
                    &verified,
                    &clean_name(body.get("name"), &[]),
                )
                .await
            {
                Ok(user) => user,
                Err(error) => match error.downcast::<SetupError>() {
                    Ok(setup) => return Err(ApiError::new(StatusCode::CONFLICT, setup.code(), setup.to_string())),
                    Err(other) => return Err(other.into()),
                },
            };
            let redirect =
                complete_sign_in(&app, &req, &interaction, user, "passkey_setup", Some(&PASSKEY_AMR)).await?;
            Ok(Out::json(StatusCode::OK, &json!({ "redirectTo": redirect })))
        }
        .await,
    )
}

// ── invite and recovery links (docs/PLAN.md §3.2) ──

fn link_expired() -> ApiError {
    problem(
        StatusCode::GONE,
        "enrollment_expired",
        "This link has expired or was already used. Ask your admin for a new one.",
    )
}

/// The link page posts its token here; it's parked in a sealed cookie for the console sign-in.
async fn open_link(State(app): State<App>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Setup)?;
            if !req.same_origin(&app.issuer) {
                return Err(problem(
                    StatusCode::FORBIDDEN,
                    "csrf",
                    "Open the link in this browser and try again.",
                ));
            }
            let token = req
                .json()
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let Some(enrollment) = app.enrollments.find(&token).await? else {
                return Err(link_expired());
            };
            let name = match enrollment.user_id {
                Some(user) => accounts::display_name(&app.pool.get().await?, user).await?,
                None => None,
            };
            let mut body = json!({ "purpose": enrollment.purpose });
            if let Some(name) = name {
                body["name"] = json!(name);
            }
            Ok(Out::json(StatusCode::OK, &body).cookie(app.write_sealed(
                ENROLL_COOKIE,
                &EnrollState {
                    enrollment_id: enrollment.id,
                },
                15 * 60,
            )))
        }
        .await,
    )
}

async fn require_enrollment(app: &App, req: &Req, uid: &str) -> ApiResult<(Interaction, Enrollment)> {
    let interaction = load(app, req, uid).await?;
    require_login_step(&interaction)?;
    let Some(enrollment) = pending_enrollment(app, req, interaction.client_id()).await? else {
        return Err(link_expired());
    };
    Ok((interaction, enrollment))
}

async fn enroll_options(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(async {
        limited(&app, &req, Limit::Interaction)?;
        guard(&app, &req, &uid)?;
        let (interaction, enrollment) = require_enrollment(&app, &req, &uid).await?;
        let body = req.json();
        let (handle, display_name, email, username, existing) = if enrollment.purpose == "invite" {
            let display_name = text(&body, "displayName", 80);
            if display_name.is_empty() {
                return Err(problem(StatusCode::BAD_REQUEST, "name_required", "Add your name so people know who you are."));
            }
            (new_user_handle(), display_name, None, None, vec![])
        } else {
            let user = enrollment.user_id.unwrap_or_default();
            let db = app.pool.get().await?;
            let row = db
                .query_one(
                    "SELECT webauthn_user_handle, display_name, email::text, preferred_username::text FROM users WHERE id = $1",
                    &[&user],
                )
                .await?;
            let mut handle: Option<String> = row.get(0);
            if handle.is_none() {
                let fresh = new_user_handle();
                db.execute("UPDATE users SET webauthn_user_handle = $2 WHERE id = $1", &[&user, &fresh]).await?;
                handle = Some(fresh);
            }
            drop(db);
            let existing = if enrollment.revoke_other_methods { vec![] } else { app.passkeys.existing(user).await? };
            (handle.unwrap_or_default(), row.get::<_, String>(1), row.get::<_, Option<String>>(2), row.get::<_, Option<String>>(3), existing)
        };
        let user = PasskeyUser { handle: &handle, display_name: &display_name, email: email.as_deref(), username: username.as_deref() };
        let options = webauthn::registration_options(&app.rp, &user, &existing);
        let challenge = options["challenge"].as_str().unwrap_or_default();
        app.passkeys
            .save_challenge(
                "enroll",
                &format!("interaction:{}", interaction.uid),
                challenge,
                None,
                json!({ "handle": handle, "displayName": display_name }),
            )
            .await?;
        Ok(Out::json(StatusCode::OK, &options))
    }
    .await)
}

async fn enroll_verify(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    reply(
        async {
            limited(&app, &req, Limit::Interaction)?;
            guard(&app, &req, &uid)?;
            let (interaction, enrollment) = require_enrollment(&app, &req, &uid).await?;
            let body = req.json();
            let response = CredentialResponse::parse(body.get("response"));
            let challenge = response.as_ref().and_then(|r| r.challenge());
            let stored = match &challenge {
                Some(c) => {
                    app.passkeys
                        .consume_challenge("enroll", &format!("interaction:{}", interaction.uid), c)
                        .await?
                }
                None => None,
            };
            let (Some(response), Some(challenge), Some(stored)) = (response, challenge, stored) else {
                return Err(challenge_expired("That took too long. Create the passkey again."));
            };
            let verified = webauthn::verify_registration(&app.rp, &response, &challenge)
                .map_err(|e| problem(StatusCode::BAD_REQUEST, "passkey_invalid", passkey_message(&e)))?;
            let pending = |key: &str| {
                stored
                    .pending
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            let mut db = app.pool.get().await?;
            let tx = db.transaction().await?;
            if !enrollment::consume(&tx, enrollment.id, None).await? {
                return Err(problem(
                    StatusCode::GONE,
                    "enrollment_expired",
                    "This link was just used. Ask your admin for a new one.",
                ));
            }
            let user = if enrollment.purpose == "invite" {
                let user: Uuid = tx
                    .query_one(
                        "INSERT INTO users (display_name, webauthn_user_handle) VALUES ($1, $2) RETURNING id",
                        &[&pending("displayName"), &pending("handle")],
                    )
                    .await?
                    .get(0);
                Entry::new("user.created", Actor::User)
                    .by(Some(user))
                    .target("user", user)
                    .meta(json!({ "via": "invite" }))
                    .write(&tx)
                    .await?;
                user
            } else {
                let user = enrollment.user_id.unwrap_or_default();
                if enrollment.revoke_other_methods {
                    enrollment::revoke_other_passkeys(&tx, user).await?;
                }
                user
            };
            let taken: Vec<String> = tx
                .query("SELECT name FROM passkeys WHERE user_id = $1", &[&user])
                .await?
                .iter()
                .map(|r| r.get(0))
                .collect();
            passkeys::add(&tx, user, &verified, &clean_name(body.get("name"), &taken)).await?;
            tx.commit().await?;
            drop(db);
            app.enrollments.record_consumer(enrollment.id, user).await?;
            if enrollment.purpose == "recovery" && enrollment.revoke_other_methods {
                app.end_sessions(&user.to_string(), None).await?;
            }
            Entry::new(
                if enrollment.purpose == "invite" {
                    "invite.used"
                } else {
                    "recovery.used"
                },
                Actor::User,
            )
            .by(Some(user))
            .target("enrollment", enrollment.id)
            .meta(json!({ "method": "passkey", "revoked_other_methods": enrollment.revoke_other_methods }))
            .write(&app.pool.get().await?)
            .await?;
            let redirect = complete_sign_in(
                &app,
                &req,
                &interaction,
                user,
                &format!("passkey_{}", enrollment.purpose),
                Some(&PASSKEY_AMR),
            )
            .await?;
            Ok(Out::json(StatusCode::OK, &json!({ "redirectTo": redirect })).cookie(app.clear_sealed(ENROLL_COOKIE)))
        }
        .await,
    )
}

pub fn routes(app: &App) -> Router<App> {
    let mut router = Router::new()
        .route("/interaction/{uid}/details", get(details))
        .route("/interaction/{uid}/dev-login", post(dev_login))
        .route("/interaction/{uid}/consent", post(consent))
        .route("/interaction/{uid}/abort", post(abort))
        .route("/interaction/{uid}/passkey/options", post(passkey_options))
        .route("/interaction/{uid}/passkey/verify", post(passkey_verify))
        .route("/interaction/{uid}/setup/verify", post(setup_verify))
        .route("/interaction/{uid}/setup/passkey/options", post(setup_passkey_options))
        .route("/interaction/{uid}/setup/passkey/verify", post(setup_passkey_verify))
        .route("/interaction/{uid}/enroll/passkey/options", post(enroll_options))
        .route("/interaction/{uid}/enroll/passkey/verify", post(enroll_verify))
        .route("/api/enroll", post(open_link));
    if app.config.conformance_mode {
        router = router.route("/interaction/{uid}", get(conformance_page));
    }
    router
}
