//! The authorization endpoint (/auth) and its resume step (/auth/:uid), in oidc-provider's order:
//! validate the request, load the session and grant, run the interaction policy
//! (login → access → consent), then issue a code.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use regex::Regex;
use serde_json::{Map, Value, json};

use super::{
    OidcError, OidcResult, RequestedClaims, acr,
    models::{Code, Grant, Interaction, InteractionResult, Prompt, Session},
    respond,
    store::{self, CODE, Columns, GRANT, INTERACTION, now, token_id},
};
use crate::{
    accounts::{self, Account},
    app::App,
    clients::{Client, SUPPORTED_SCOPES},
    crypto::random_token,
    http::{Limit, Out, Req, clear_cookie, set_cookie},
};

/// Parameters the authorization endpoint reads. Anything else is ignored.
const PARAMS: [&str; 21] = [
    "acr_values",
    "claims",
    "claims_locales",
    "client_id",
    "code_challenge",
    "code_challenge_method",
    "display",
    "id_token_hint",
    "login_hint",
    "max_age",
    "nonce",
    "prompt",
    "redirect_uri",
    "registration",
    "request",
    "request_uri",
    "response_mode",
    "response_type",
    "scope",
    "state",
    "ui_locales",
];

const RESPONSE_MODES: [&str; 3] = ["query", "fragment", "form_post"];
const PROMPTS: [&str; 3] = ["none", "login", "consent"];
const INTERACTION_TTL: i64 = 60 * 60;
const CODE_TTL: i64 = 60;

static SCOPE_CHARS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*$").unwrap());
static PKCE_FORMAT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._~-]{43,128}$").unwrap());

struct Ctx {
    params: BTreeMap<String, String>,
    client: Option<Client>,
    redirect_checked: bool,
}

impl Ctx {
    fn get(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    fn prompts(&self) -> BTreeSet<String> {
        self.get("prompt")
            .map(|p| p.split(' ').filter(|s| !s.is_empty()).map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn scopes(&self) -> Vec<&str> {
        self.get("scope")
            .map(|s| s.split(' ').filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    }

    /// The requested scopes Handstamp knows (oidc-provider's requestParamOIDCScopes).
    fn oidc_scopes(&self) -> Vec<&str> {
        self.scopes()
            .into_iter()
            .filter(|s| SUPPORTED_SCOPES.contains(s))
            .collect()
    }

    fn claims(&self) -> RequestedClaims {
        RequestedClaims::from_value(
            self.get("claims")
                .and_then(|c| serde_json::from_str::<Value>(c).ok())
                .as_ref(),
        )
    }

    fn client(&self) -> &Client {
        self.client.as_ref().expect("client checked")
    }
}

fn missing(name: &str) -> OidcError {
    OidcError::invalid_request(format!("missing required parameter '{name}'"))
}

/// GET or POST /auth. POST is on for https issuers only (R16).
pub async fn authorization(State(app): State<App>, req: Req) -> Response {
    if !app.limits.check(Limit::Authorization, &req.path, req.ip) {
        return crate::http::ApiError::rate_limited().into_response();
    }
    if req.method == Method::POST && !app.config.https() {
        return Out::new(StatusCode::NOT_FOUND).into_response();
    }
    let pairs = if req.method == Method::POST {
        req.form_pairs()
    } else {
        req.query_pairs()
    };
    let mut params = BTreeMap::new();
    let mut duplicate = None;
    for (key, value) in pairs {
        if !PARAMS.contains(&key.as_str()) || value.is_empty() {
            continue;
        }
        if params.contains_key(&key) {
            duplicate.get_or_insert(key);
            continue;
        }
        params.insert(key, value);
    }
    let mut ctx = Ctx {
        params,
        client: None,
        redirect_checked: false,
    };
    let mut session = match app.load_session(&req).await {
        Ok(session) => session,
        Err(error) => return app.render_error(&error.into()).await.into_response(),
    };
    let previous = (!session.new).then(|| session.id.clone());
    let mut extra_cookies = Vec::new();
    let result = match duplicate {
        Some(key) => Err(OidcError::invalid_request(format!(
            "'{key}' parameter must not be provided twice"
        ))),
        None => match validate(&app, &mut ctx).await {
            Ok(()) => proceed(&app, &req, &mut ctx, &mut session, None, &mut extra_cookies).await,
            Err(error) => Err(error),
        },
    };
    finish(&app, &mut ctx, &session, previous.as_deref(), result, extra_cookies).await
}

/// GET /auth/:uid: back from an interaction.
pub async fn resume(State(app): State<App>, Path(uid): Path<String>, req: Req) -> Response {
    if !app.limits.check(Limit::Authorization, &req.path, req.ip) {
        return crate::http::ApiError::rate_limited().into_response();
    }
    let mut ctx = Ctx {
        params: BTreeMap::new(),
        client: None,
        redirect_checked: false,
    };
    let mut session = match app.load_session(&req).await {
        Ok(session) => session,
        Err(error) => return app.render_error(&error.into()).await.into_response(),
    };
    let previous = (!session.new).then(|| session.id.clone());
    let mut cookies = Vec::new();
    let result = resume_inner(&app, &req, &uid, &mut ctx, &mut session, &mut cookies).await;
    finish(&app, &mut ctx, &session, previous.as_deref(), result, cookies).await
}

async fn resume_inner(
    app: &App,
    req: &Req,
    uid: &str,
    ctx: &mut Ctx,
    session: &mut Session,
    cookies: &mut Vec<String>,
) -> OidcResult<Out> {
    let names = app.cookie_names();
    let Some(cookie) = req.cookie(names.resume).filter(|c| *c == uid) else {
        return Err(OidcError::session_not_found("authorization request has expired"));
    };
    let Some(found) = app.store.find::<Interaction>(INTERACTION, cookie).await? else {
        return Err(OidcError::session_not_found("interaction session not found"));
    };
    let interaction = found.value;
    if interaction.session_uid.as_ref().is_some_and(|u| *u != session.uid) {
        return Err(OidcError::session_not_found(
            "interaction session and authentication session mismatch",
        ));
    }
    let result = interaction.result.clone().unwrap_or_default();
    // Someone else signed in on this browser: end the old session before starting theirs.
    if let (Some(login), Some(current)) = (&result.login, session.account_id.clone())
        && login.account_id != current
    {
        super::logout::end_session(app, session, true).await?;
        *session = Session::fresh(app.session_ttl());
        session.touched = true;
    }
    app.store.destroy(INTERACTION, &interaction.uid).await?;
    cookies.push(clear_cookie(
        names.resume,
        &app.short_cookie_options(&format!("/auth/{uid}"), None),
    ));
    ctx.params = interaction.params.clone();
    ctx.redirect_checked = true;
    ctx.client = app.clients.load(interaction.client_id()).await?;
    if ctx.client.is_none() {
        return Err(OidcError::invalid_client("client is invalid"));
    }
    if let Some(error) = &result.error {
        return Err(OidcError::new(
            error,
            result.error_description.clone().unwrap_or_default(),
        ));
    }
    if let Some(login) = &result.login {
        session.account_id = Some(login.account_id.clone());
        session.login_ts = Some(login.ts);
        session.amr = login.amr.clone();
        session.exp = now() + app.session_ttl();
        session.touched = true;
        if !session.new {
            session.reset_identifier();
        }
    }
    proceed(app, req, ctx, session, Some(result), cookies).await
}

/// Saves the session, then turns an error into a redirect to the client or a rendered page.
async fn finish(
    app: &App,
    ctx: &mut Ctx,
    session: &Session,
    previous: Option<&str>,
    result: OidcResult<Out>,
    extra_cookies: Vec<String>,
) -> Response {
    let out = match result {
        Ok(out) => out,
        Err(error) => error_response(app, ctx, error).await,
    };
    let session_cookies = match app.save_session(session, previous).await {
        Ok(cookies) => cookies,
        Err(error) => return app.render_error(&error.into()).await.into_response(),
    };
    out.no_store()
        .cookies(extra_cookies)
        .cookies(session_cookies)
        .into_response()
}

/// oidc-provider's authorization error handler: redirect only to a registered redirect_uri of a
/// known client; render everything else.
async fn error_response(app: &App, ctx: &mut Ctx, mut error: OidcError) -> Out {
    if error.status == StatusCode::INTERNAL_SERVER_ERROR {
        return app.render_error(&error).await;
    }
    if ctx.client.is_none()
        && let Some(id) = ctx.get("client_id")
    {
        ctx.client = app.clients.load(id).await.ok().flatten();
    }
    if let Some(client) = &ctx.client
        && !ctx.redirect_checked
        && error.error != "invalid_redirect_uri"
        && let Some(uri) = ctx.get("redirect_uri")
        && !client.redirect_uris.iter().any(|r| r == uri)
    {
        error = OidcError::invalid_redirect_uri();
    }
    let redirect_uri = ctx.get("redirect_uri").map(str::to_string);
    let (Some(_), Some(uri)) = (&ctx.client, redirect_uri) else {
        return app.render_error(&error).await;
    };
    if !error.allow_redirect || ctx.get("client_id").is_none() {
        return app.render_error(&error).await;
    }
    let mode = ctx
        .get("response_mode")
        .filter(|m| RESPONSE_MODES.contains(m))
        .unwrap_or("query")
        .to_string();
    let mut params = vec![("error", error.error.clone())];
    if !error.description.is_empty() {
        params.push(("error_description", error.description.clone()));
    }
    if let Some(state) = ctx.get("state") {
        params.push(("state", state.to_string()));
    }
    params.push(("iss", app.issuer.clone()));
    respond(&mode, &uri, &params)
}

/// Request validation, in oidc-provider's order. Normalizes params in place (scope, prompt, max_age).
async fn validate(app: &App, ctx: &mut Ctx) -> OidcResult<()> {
    if ctx.get("request").is_some() {
        return Err(OidcError::new(
            "request_not_supported",
            "request parameter provided but not supported",
        ));
    }
    if ctx.get("request_uri").is_some() {
        return Err(OidcError::new(
            "request_uri_not_supported",
            "request_uri parameter provided but not supported",
        ));
    }
    let client_id = ctx.get("client_id").ok_or_else(|| missing("client_id"))?.to_string();
    ctx.client = app.clients.load(&client_id).await?;
    if ctx.client.is_none() {
        return Err(OidcError::invalid_client("client is invalid"));
    }
    if let Some(mode) = ctx.get("response_mode")
        && !RESPONSE_MODES.contains(&mode)
    {
        ctx.params.remove("response_mode");
        return Err(OidcError::new(
            "unsupported_response_mode",
            "unsupported response_mode requested",
        ));
    }
    let response_type = ctx.get("response_type").ok_or_else(|| missing("response_type"))?;
    if ctx.get("registration").is_some() {
        return Err(OidcError::new(
            "registration_not_supported",
            "registration parameter provided but not supported",
        ));
    }
    let mut types: Vec<&str> = response_type.split(' ').filter(|s| !s.is_empty()).collect();
    types.sort();
    types.dedup();
    let response_type = types.join(" ");
    if response_type != "code" {
        return Err(OidcError::new(
            "unsupported_response_type",
            "unsupported response_type requested",
        ));
    }
    ctx.params.insert("response_type".into(), response_type);
    if ctx.get("redirect_uri").is_none() {
        return Err(missing("redirect_uri"));
    }

    let prompts = ctx.prompts();
    if ctx.get("prompt").is_some() {
        if prompts.iter().any(|p| !PROMPTS.contains(&p.as_str())) {
            return Err(OidcError::invalid_request("unsupported prompt value requested"));
        }
        if prompts.contains("none") && prompts.len() != 1 {
            return Err(OidcError::invalid_request("prompt none must only be used alone"));
        }
    }

    // Scope.
    if let Some(scope) = ctx.get("scope")
        && !SCOPE_CHARS.is_match(scope)
    {
        return Err(OidcError::invalid_scope("scope contains invalid characters"));
    }
    let mut scopes: Vec<String> = Vec::new();
    for scope in ctx.scopes() {
        if !scopes.iter().any(|s| s == scope) {
            scopes.push(scope.to_string());
        }
    }
    // offline_access only with prompt=consent (OIDC Core §11) and for clients that may refresh.
    if scopes.iter().any(|s| s == "offline_access") && (!prompts.contains("consent") || !ctx.client().refresh_allowed())
    {
        scopes.retain(|s| s != "offline_access");
    }
    if scopes.is_empty() {
        ctx.params.remove("scope");
    } else {
        ctx.params.insert("scope".into(), scopes.join(" "));
    }
    for scope in &scopes {
        if SUPPORTED_SCOPES.contains(&scope.as_str()) && !ctx.client().scopes.contains(scope) {
            return Err(OidcError::invalid_scope("requested scope is not allowed"));
        }
    }
    if !scopes.iter().any(|s| s == "openid") {
        for param in [
            "acr_values",
            "claims",
            "claims_locales",
            "id_token_hint",
            "max_age",
            "nonce",
        ] {
            if ctx.get(param).is_some() {
                return Err(OidcError::invalid_request(format!(
                    "openid scope must be requested when using the {param} parameter"
                )));
            }
        }
    }

    // Redirect URI: exact match only.
    let redirect_uri = ctx.get("redirect_uri").unwrap_or_default();
    if !ctx.client().redirect_uris.iter().any(|r| r == redirect_uri) {
        return Err(OidcError::invalid_redirect_uri());
    }
    ctx.redirect_checked = true;

    // PKCE.
    let challenge = ctx.get("code_challenge");
    let method = ctx.get("code_challenge_method");
    if method.is_none() && challenge.is_some() {
        return Err(OidcError::invalid_request("code_challenge_method must be provided"));
    }
    if let Some(method) = method {
        if method != "S256" {
            return Err(OidcError::invalid_request(
                "not supported value of code_challenge_method",
            ));
        }
        if challenge.is_none() {
            return Err(OidcError::invalid_request(
                "code_challenge must be provided with code_challenge_method",
            ));
        }
    }
    if challenge.is_none() && ctx.client().pkce_required() {
        return Err(OidcError::invalid_request(
            "Authorization Server policy requires PKCE to be used for this request",
        ));
    }
    if let Some(challenge) = challenge
        && !PKCE_FORMAT.is_match(challenge)
    {
        return Err(OidcError::invalid_request(
            "code_challenge must be a string with a minimum length of 43 characters",
        ));
    }

    // Claims parameter.
    if let Some(raw) = ctx.get("claims") {
        let claims: Value = serde_json::from_str(raw)
            .map_err(|_| OidcError::invalid_request("could not parse the claims parameter JSON"))?;
        let Some(object) = claims.as_object() else {
            return Err(OidcError::invalid_request("claims parameter should be a JSON object"));
        };
        if !object.contains_key("userinfo") && !object.contains_key("id_token") {
            return Err(OidcError::invalid_request(
                "claims parameter should have userinfo or id_token properties",
            ));
        }
        for container in ["userinfo", "id_token"] {
            if let Some(section) = object.get(container) {
                let Some(section) = section.as_object() else {
                    return Err(OidcError::invalid_request(format!(
                        "claims.{container} should be an object"
                    )));
                };
                if section.values().any(|v| !v.is_null() && !v.is_object()) {
                    return Err(OidcError::invalid_request(format!(
                        "claims.{container} members must be null or objects"
                    )));
                }
            }
        }
    }

    // max_age: 0 means "sign in again".
    if let Some(raw) = ctx.get("max_age") {
        let Ok(max_age) = raw.parse::<i64>() else {
            return Err(OidcError::invalid_request("invalid max_age parameter value"));
        };
        if max_age < 0 {
            return Err(OidcError::invalid_request("invalid max_age parameter value"));
        }
        if max_age == 0 {
            ctx.params.remove("max_age");
            if !prompts.contains("login") {
                let mut joined: Vec<String> = prompts.iter().cloned().collect();
                joined.push("login".into());
                ctx.params.insert("prompt".into(), joined.join(" "));
            }
        }
    }

    if let Some(hint) = ctx.get("id_token_hint") {
        verify_id_token_hint(app, hint, &ctx.client().client_id)
            .await
            .map_err(|_| OidcError::invalid_request("could not validate id_token_hint"))?;
    }
    Ok(())
}

/// Our own ID token, for this client. Expired hints are fine: the point is who, not when.
pub async fn verify_id_token_hint(app: &App, hint: &str, client_id: &str) -> Result<Map<String, Value>> {
    let (_, payload) = app.keys.snapshot().await?.verify(hint)?;
    anyhow::ensure!(
        payload.get("iss").and_then(Value::as_str) == Some(app.issuer.as_str()),
        "issuer"
    );
    let aud_ok = match payload.get("aud") {
        Some(Value::String(aud)) => aud == client_id,
        Some(Value::Array(auds)) => auds.iter().any(|a| a == client_id),
        _ => false,
    };
    anyhow::ensure!(aud_ok, "audience");
    Ok(payload)
}

struct Check {
    prompt: &'static str,
    reasons: Vec<&'static str>,
    details: Map<String, Value>,
    error: &'static str,
    description: &'static str,
}

/// Session, grant, interaction policy, and the code.
async fn proceed(
    app: &App,
    req: &Req,
    ctx: &mut Ctx,
    session: &mut Session,
    result: Option<InteractionResult>,
    cookies: &mut Vec<String>,
) -> OidcResult<Out> {
    let client = ctx.client().clone();
    let prompts = ctx.prompts();
    let requested = ctx.claims();
    let result = result.unwrap_or_default();
    let db = app.pool.get().await?;

    // An account that was disabled (or deleted) no longer counts as signed in.
    let account: Option<Account> = match &session.account_id {
        Some(id) => accounts::find(&db, id).await?,
        None => None,
    };

    // The grant: first-party clients skip consent, so theirs is created or extended right here.
    let mut grant: Option<(Grant, bool)> = None;
    if let Some(account) = &account {
        let existing_id = result
            .consent
            .as_ref()
            .and_then(|c| c.grant_id.clone())
            .or_else(|| session.grant_id_for(&client.client_id).map(str::to_string));
        let existing = match existing_id {
            Some(id) => app
                .store
                .find::<Grant>(GRANT, &id)
                .await?
                .map(|f| f.value)
                .filter(|g| g.account_id == account.id.to_string() && g.client_id == client.client_id),
            None => None,
        };
        let mut saved = existing.is_some();
        let mut g =
            existing.unwrap_or_else(|| Grant::new(&account.id.to_string(), &client.client_id, app.session_ttl()));
        if client.first_party {
            g.add_scopes(ctx.oidc_scopes());
            let names = requested.names();
            g.add_claims(names.iter().map(String::as_str));
            g.exp = now() + app.session_ttl();
            save_grant(app, &g).await?;
            saved = true;
        }
        if saved {
            session.authorization(&client.client_id).grant_id = Some(g.jti.clone());
        }
        grant = Some((g, saved));
    }

    let pending = |name: &str| {
        prompts.contains(name)
            && match name {
                "login" => result.login.is_none(),
                "consent" => result.consent.is_none(),
                _ => true,
            }
    };

    // Interaction policy: login → access → consent; the first prompt with reasons wins.
    let mut check: Option<Check> = None;
    {
        let mut reasons = Vec::new();
        if pending("login") {
            reasons.push("login_prompt");
        }
        if account.is_none() {
            reasons.push("no_session");
        }
        if let Some(max_age) = ctx.get("max_age").and_then(|m| m.parse::<i64>().ok())
            && (account.is_none() || (session.past(max_age) && result.login.is_none()))
        {
            reasons.push("max_age");
        }
        if let Some(hint) = ctx.get("id_token_hint") {
            let sub = verify_id_token_hint(app, hint, &client.client_id)
                .await
                .ok()
                .and_then(|p| p.get("sub").and_then(Value::as_str).map(str::to_string));
            if account.as_ref().is_none_or(|a| Some(a.id.to_string()) != sub) {
                reasons.push("id_token_hint");
            }
        }
        if let Some(value) = requested.id_token.get("sub").and_then(|s| s.get("value"))
            && account.as_ref().is_none_or(|a| value != &json!(a.id.to_string()))
        {
            reasons.push("claims_id_token_sub_value");
        }
        // A level the request asks for and this sign-in doesn't reach (R11): sign in again.
        if account.is_some() && !acr::satisfied(session.amr.as_deref(), &ctx.params) {
            reasons.push("acr_values");
        }
        if !reasons.is_empty() {
            let mut details = Map::new();
            for key in ["max_age", "login_hint", "id_token_hint"] {
                if let Some(value) = ctx.get(key) {
                    details.insert(key.into(), json!(value));
                }
            }
            let description = match reasons[0] {
                "login_prompt" => "login prompt was not resolved",
                "no_session" => "End-User authentication is required",
                "max_age" => "End-User authentication could not be obtained",
                "id_token_hint" => "id_token_hint and authenticated subject do not match",
                "acr_values" => "requested ACR could not be obtained",
                _ => "requested subject could not be obtained",
            };
            check = Some(Check {
                prompt: "login",
                reasons,
                details,
                error: "login_required",
                description,
            });
        }
    }
    if check.is_none()
        && let (Some(group), Some(account)) = (client.required_group_id, &account)
        && !accounts::is_member(&db, account.id, group).await?
    {
        // Access refused by the app's required group: the card names the group (R7).
        let mut details = Map::new();
        details.insert("requiredGroup".into(), json!(group));
        check = Some(Check {
            prompt: "access",
            reasons: vec!["group_required"],
            details,
            error: "interaction_required",
            description: "End-User is not a member of the group this client requires",
        });
    }
    if check.is_none()
        && let Some((g, _)) = &grant
    {
        let mut reasons = Vec::new();
        let mut details = Map::new();
        if pending("consent") {
            reasons.push("consent_prompt");
        }
        let missing_scopes: Vec<&str> = ctx
            .oidc_scopes()
            .into_iter()
            .filter(|s| !g.scopes.contains(*s))
            .collect();
        if !missing_scopes.is_empty() {
            reasons.push("op_scopes_missing");
            details.insert("missingOIDCScope".into(), json!(missing_scopes));
        }
        let missing_claims: Vec<String> = requested
            .names()
            .into_iter()
            .filter(|c| {
                !g.claims.contains(c) && !["sub", "sid", "auth_time", "acr", "amr", "iss"].contains(&c.as_str())
            })
            .collect();
        if !missing_claims.is_empty() {
            reasons.push("op_claims_missing");
            details.insert("missingOIDCClaims".into(), json!(missing_claims));
        }
        if !reasons.is_empty() {
            let description = match reasons[0] {
                "consent_prompt" => "consent prompt was not resolved",
                "op_scopes_missing" => "requested scopes not granted",
                _ => "requested claims not granted",
            };
            check = Some(Check {
                prompt: "consent",
                reasons,
                details,
                error: "consent_required",
                description,
            });
        }
    }
    drop(db);

    if let Some(check) = check {
        if prompts.contains("none") {
            return Err(OidcError::new(check.error, check.description).status(StatusCode::SEE_OTHER));
        }
        let uid = random_token(16);
        let interaction = Interaction {
            uid: uid.clone(),
            params: ctx.params.clone(),
            prompt: Prompt {
                name: check.prompt.into(),
                reasons: check.reasons.iter().map(|r| r.to_string()).collect(),
                details: check.details,
            },
            session_uid: account.as_ref().map(|_| session.uid.clone()),
            account_id: account.as_ref().map(|a| a.id.to_string()),
            grant_id: grant.as_ref().filter(|(_, saved)| *saved).map(|(g, _)| g.jti.clone()),
            last_submission: (result.login.is_some() || result.consent.is_some()).then_some(result),
            result: None,
            exp: now() + INTERACTION_TTL,
        };
        app.store
            .save(
                INTERACTION,
                &uid,
                &interaction,
                Columns {
                    uid: Some(&uid),
                    ..Default::default()
                },
                interaction.exp,
            )
            .await?;
        let names = app.cookie_names();
        let destination = format!("/interaction/{uid}");
        cookies.push(set_cookie(
            names.interaction,
            &uid,
            &app.short_cookie_options(&destination, Some(INTERACTION_TTL)),
        ));
        cookies.push(set_cookie(
            names.resume,
            &uid,
            &app.short_cookie_options(&format!("/auth/{uid}"), Some(INTERACTION_TTL)),
        ));
        let _ = req;
        return Ok(Out::see_other(&destination));
    }

    let Some(account) = account else {
        return Err(OidcError::access_denied(
            "authorization request resolved without requesting interactions but no account id was resolved",
        ));
    };
    let Some((grant, _)) = grant else {
        return Err(OidcError::access_denied("no grant"));
    };
    let requested_scopes = ctx.scopes();
    let scope: Vec<&str> = grant.filter_scopes(&requested_scopes);
    if scope.is_empty() {
        return Err(OidcError::access_denied(
            "authorization request resolved without requesting interactions but no scope was granted",
        ));
    }
    let scope = scope.join(" ");

    // The code. Not offline: it (and everything it yields) lives and dies with this session.
    let offline = scope.split(' ').any(|s| s == "offline_access");
    let authorization = session.authorization(&client.client_id);
    authorization.grant_id = Some(grant.jti.clone());
    if offline {
        authorization.persists_logout = true;
    }
    let sid = authorization.sid.clone();
    let include_sid = client.backchannel_logout_uri.is_some() || requested.id_token.contains_key("sid");
    let value = random_token(32);
    let code = Code {
        client_id: client.client_id.clone(),
        account_id: account.id.to_string(),
        grant_id: grant.jti.clone(),
        scope,
        claims: ctx.get("claims").and_then(|c| serde_json::from_str(c).ok()),
        nonce: ctx.get("nonce").map(str::to_string),
        redirect_uri: ctx.get("redirect_uri").unwrap_or_default().to_string(),
        code_challenge: ctx.get("code_challenge").map(str::to_string),
        auth_time: session.login_ts.unwrap_or_else(now),
        amr: session.amr.clone(),
        sid: include_sid.then_some(sid),
        session_uid: session.uid.clone(),
        expires_with_session: !offline,
    };
    let account_id = account.id.to_string();
    app.store
        .save(
            CODE,
            &token_id(&value),
            &code,
            Columns {
                grant_id: Some(&grant.jti),
                account_id: Some(&account_id),
                ..Default::default()
            },
            now() + CODE_TTL,
        )
        .await?;
    let mut params = vec![("code", value)];
    if let Some(state) = ctx.get("state") {
        params.push(("state", state.to_string()));
    }
    params.push(("iss", app.issuer.clone()));
    let mode = ctx.get("response_mode").unwrap_or("query").to_string();
    Ok(respond(&mode, &code.redirect_uri, &params))
}

pub async fn save_grant(app: &App, grant: &Grant) -> Result<()> {
    app.store
        .save(
            GRANT,
            &grant.jti,
            grant,
            Columns {
                grant_id: Some(&grant.jti),
                account_id: Some(&grant.account_id),
                ..Default::default()
            },
            grant.exp,
        )
        .await
}

pub fn _unused(_: &store::Store) {}
