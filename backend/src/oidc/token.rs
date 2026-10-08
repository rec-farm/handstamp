//! The token endpoint (authorization_code, refresh_token), userinfo, introspection and revocation.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use axum::{
    extract::State,
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::{
    ClientAuth, IdTokenInput, OidcError, OidcResult, RequestedClaims, authenticate_client, client_error_response,
    id_token, release_claims,
    models::{AccessToken, Code, Grant, RefreshToken, Session},
    single_params,
    store::{ACCESS_TOKEN, CODE, Columns, GRANT, REFRESH_TOKEN, SESSION, now, token_id},
};
use crate::{
    accounts::{self, Account},
    app::App,
    clients::Client,
    crypto::{b64url, constant_time_eq, random_token, sha256},
    http::{Limit, Out, Req},
};

/// Is a session-bound token still riding on its session? (oidc-provider's checkSessionBinding)
async fn session_alive(app: &App, session_uid: &str, account_id: &str, client_id: &str, grant_id: &str) -> Result<bool> {
    let Some((_, session)) = app.store.find_by_uid::<Session>(SESSION, session_uid).await? else { return Ok(false) };
    Ok(session.account_id.as_deref() == Some(account_id) && session.grant_id_for(client_id) == Some(grant_id))
}

async fn find_grant(app: &App, grant_id: &str, client_id: &str) -> OidcResult<Grant> {
    let grant = app.store.find::<Grant>(GRANT, grant_id).await?.map(|f| f.value);
    match grant {
        None => Err(OidcError::invalid_grant("grant not found")),
        Some(g) if g.exp <= now() => Err(OidcError::invalid_grant("grant is expired")),
        Some(g) if g.client_id != client_id => Err(OidcError::invalid_grant("client mismatch")),
        Some(g) => Ok(g),
    }
}

struct Issue<'a> {
    client: &'a Client,
    account: &'a Account,
    grant: &'a Grant,
    scope: String,
    claims: Option<Value>,
    nonce: Option<String>,
    auth_time: i64,
    amr: Option<Vec<String>>,
    sid: Option<String>,
    session_uid: String,
    expires_with_session: bool,
    refresh: Option<String>,
}

/// Access token, ID token, and (for clients allowed the refresh_token grant) a refresh token.
async fn issue(app: &App, issue: Issue<'_>) -> OidcResult<Value> {
    let iat = now();
    let ttl = (app.config.access_token_minutes * 60) as i64;
    let access_value = random_token(32);
    let account_id = issue.account.id.to_string();
    let at = AccessToken {
        client_id: issue.client.client_id.clone(),
        account_id: account_id.clone(),
        grant_id: issue.grant.jti.clone(),
        scope: issue.scope.clone(),
        claims: issue.claims.clone(),
        session_uid: issue.session_uid.clone(),
        expires_with_session: issue.expires_with_session,
        sid: issue.sid.clone(),
        iat,
        exp: iat + ttl,
    };
    let columns = || Columns { grant_id: Some(&issue.grant.jti), account_id: Some(&account_id), ..Default::default() };
    app.store.save(ACCESS_TOKEN, &token_id(&access_value), &at, columns(), at.exp).await?;

    let refresh_value = match issue.refresh {
        Some(value) => Some(value),
        None if issue.client.refresh_allowed() => {
            let value = random_token(32);
            let rt = RefreshToken {
                client_id: issue.client.client_id.clone(),
                account_id: account_id.clone(),
                grant_id: issue.grant.jti.clone(),
                scope: issue.scope.clone(),
                claims: issue.claims.clone(),
                nonce: issue.nonce.clone(),
                auth_time: issue.auth_time,
                amr: issue.amr.clone(),
                sid: issue.sid.clone(),
                session_uid: issue.session_uid.clone(),
                expires_with_session: issue.expires_with_session,
                iat,
                exp: iat + (app.config.refresh_token_days * 24 * 3600) as i64,
                rotations: 0,
            };
            app.store.save(REFRESH_TOKEN, &token_id(&value), &rt, columns(), rt.exp).await?;
            Some(value)
        }
        None => None,
    };

    let mut body = json!({
        "access_token": access_value,
        "expires_in": ttl,
        "scope": issue.scope,
        "token_type": "Bearer",
    });
    if issue.scope.split(' ').any(|s| s == "openid") {
        let requested = RequestedClaims::from_value(issue.claims.as_ref());
        let token = id_token(
            app,
            IdTokenInput {
                client: issue.client,
                account: issue.account,
                scope: &issue.scope,
                requested: &requested,
                grant_claims: &issue.grant.claims,
                nonce: issue.nonce.as_deref(),
                auth_time: issue.auth_time,
                amr: issue.amr.as_deref(),
                sid: issue.sid.as_deref(),
            },
        )
        .await?;
        body["id_token"] = json!(token);
    }
    if let Some(refresh) = refresh_value {
        body["refresh_token"] = json!(refresh);
    }
    Ok(body)
}

fn token_response(body: &Value) -> Out {
    Out::json(StatusCode::OK, body).no_store().header(header::PRAGMA, "no-cache")
}

const TOKEN_PARAMS: [&str; 9] =
    ["grant_type", "code", "code_verifier", "redirect_uri", "refresh_token", "scope", "client_id", "client_secret", "client_assertion"];

/// POST /token.
pub async fn token(State(app): State<App>, req: Req) -> Response {
    if !app.limits.check(Limit::Token, &req.path, req.ip) {
        return crate::http::ApiError::rate_limited().into_response();
    }
    let result = async {
        if req.method != Method::POST {
            return Err(OidcError::invalid_request("only POST is supported"));
        }
        if !req.is_form() {
            return Err(OidcError::invalid_request("only application/x-www-form-urlencoded content-type bodies are supported"));
        }
        let form = single_params(req.form_pairs(), Some(&TOKEN_PARAMS))?;
        let ClientAuth { client } = authenticate_client(&app, &req, &form).await?;
        let grant_type = form.get("grant_type").ok_or_else(|| super::OidcError::invalid_request("missing required parameter 'grant_type'"))?;
        match grant_type.as_str() {
            "authorization_code" => authorization_code(&app, &client, &form).await,
            "refresh_token" => {
                if !client.refresh_allowed() {
                    return Err(OidcError::new("unauthorized_client", "requested grant type is not allowed for this client"));
                }
                refresh_token(&app, &client, &form).await
            }
            _ => Err(OidcError::new("unsupported_grant_type", "unsupported grant_type requested")),
        }
    }
    .await;
    match result {
        Ok(body) => token_response(&body).into_response(),
        Err(error) => client_error_response(&app, &error, &req).into_response(),
    }
}

fn check_pkce(verifier: Option<&String>, challenge: Option<&String>) -> OidcResult<()> {
    if verifier.is_none() && challenge.is_none() {
        return Ok(());
    }
    let Some(verifier) = verifier else { return Err(OidcError::invalid_grant("grant request is invalid")) };
    if !regex::Regex::new(r"^[A-Za-z0-9._~-]{43,128}$").unwrap().is_match(verifier) {
        return Err(OidcError::invalid_grant("grant request is invalid"));
    }
    let Some(challenge) = challenge else { return Err(OidcError::invalid_grant("grant request is invalid")) };
    if !constant_time_eq(b64url(&sha256(verifier.as_bytes())).as_bytes(), challenge.as_bytes()) {
        return Err(OidcError::invalid_grant("grant request is invalid"));
    }
    Ok(())
}

pub struct ExchangedCode {
    pub body: Value,
    pub account: Account,
    pub sid: Option<String>,
    pub auth_time: i64,
    pub amr: Option<Vec<String>>,
}

/// The code exchange itself, also used in-process by the console's own sign-in.
pub async fn exchange_code(app: &App, client: &Client, form: &BTreeMap<String, String>) -> OidcResult<ExchangedCode> {
    let code_value = form.get("code").ok_or_else(|| OidcError::invalid_request("missing required parameter 'code'"))?;
    let redirect_uri =
        form.get("redirect_uri").ok_or_else(|| OidcError::invalid_request("missing required parameter 'redirect_uri'"))?;
    let id = token_id(code_value);
    // Expired codes are still found, to tell them apart from unknown ones.
    let found = {
        let db = app.pool.get().await?;
        db.query_opt(
            "SELECT payload, consumed_at IS NOT NULL, expires_at < now() FROM oidc_payloads WHERE kind = $1 AND id = $2",
            &[&CODE, &id],
        )
        .await?
    };
    let Some(row) = found else { return Err(OidcError::invalid_grant("authorization code not found")) };
    let Ok(code) = serde_json::from_value::<Code>(row.get(0)) else {
        return Err(OidcError::invalid_grant("authorization code not found"));
    };
    let (consumed, expired): (bool, bool) = (row.get(1), row.get(2));
    if code.client_id != client.client_id {
        return Err(OidcError::invalid_grant("client mismatch"));
    }
    if expired {
        return Err(OidcError::invalid_grant("authorization code is expired"));
    }
    let grant = find_grant(app, &code.grant_id, &client.client_id).await?;
    check_pkce(form.get("code_verifier"), code.code_challenge.as_ref())?;
    if &code.redirect_uri != redirect_uri {
        return Err(OidcError::invalid_grant("authorization code redirect_uri mismatch"));
    }
    // A code used twice: revoke everything it ever produced.
    if consumed || !app.store.consume(CODE, &id).await? {
        app.store.revoke_grant(&code.grant_id).await?;
        return Err(OidcError::invalid_grant("authorization code already consumed"));
    }
    if code.expires_with_session
        && !session_alive(app, &code.session_uid, &code.account_id, &client.client_id, &code.grant_id).await?
    {
        return Err(OidcError::invalid_grant("authorization code is invalid (session ended)"));
    }
    let db = app.pool.get().await?;
    let Some(account) = accounts::find(&db, &code.account_id).await? else {
        return Err(OidcError::invalid_grant("authorization code invalid (referenced account not found)"));
    };
    drop(db);
    if grant.account_id != code.account_id {
        return Err(OidcError::invalid_grant("accountId mismatch"));
    }
    let body = issue(
        app,
        Issue {
            client,
            account: &account,
            grant: &grant,
            scope: code.scope.clone(),
            claims: code.claims.clone(),
            nonce: code.nonce.clone(),
            auth_time: code.auth_time,
            amr: code.amr.clone(),
            sid: code.sid.clone(),
            session_uid: code.session_uid.clone(),
            expires_with_session: code.expires_with_session,
            refresh: None,
        },
    )
    .await?;
    Ok(ExchangedCode { body, account, sid: code.sid, auth_time: code.auth_time, amr: code.amr })
}

async fn authorization_code(app: &App, client: &Client, form: &BTreeMap<String, String>) -> OidcResult<Value> {
    Ok(exchange_code(app, client, form).await?.body)
}

async fn refresh_token(app: &App, client: &Client, form: &BTreeMap<String, String>) -> OidcResult<Value> {
    let value = form.get("refresh_token").ok_or_else(|| OidcError::invalid_request("missing required parameter 'refresh_token'"))?;
    let id = token_id(value);
    let row = {
        let db = app.pool.get().await?;
        db.query_opt(
            "SELECT payload, consumed_at IS NOT NULL, expires_at < now() FROM oidc_payloads WHERE kind = $1 AND id = $2",
            &[&REFRESH_TOKEN, &id],
        )
        .await?
    };
    let Some(row) = row else { return Err(OidcError::invalid_grant("refresh token not found")) };
    let Ok(rt) = serde_json::from_value::<RefreshToken>(row.get(0)) else {
        return Err(OidcError::invalid_grant("refresh token not found"));
    };
    let (consumed, expired): (bool, bool) = (row.get(1), row.get(2));
    if rt.client_id != client.client_id {
        return Err(OidcError::invalid_grant("client mismatch"));
    }
    if expired {
        return Err(OidcError::invalid_grant("refresh token is expired"));
    }
    if rt.expires_with_session && !session_alive(app, &rt.session_uid, &rt.account_id, &client.client_id, &rt.grant_id).await? {
        return Err(OidcError::invalid_grant("refresh token is invalid (session ended)"));
    }
    let grant = find_grant(app, &rt.grant_id, &client.client_id).await?;
    let requested: Option<BTreeSet<&str>> = form.get("scope").map(|s| s.split(' ').filter(|s| !s.is_empty()).collect());
    if let Some(requested) = &requested {
        let held: BTreeSet<&str> = rt.scope.split(' ').collect();
        let missing: Vec<&str> = requested.iter().copied().filter(|s| !held.contains(s)).collect();
        if !missing.is_empty() {
            return Err(OidcError::invalid_scope(format!(
                "refresh token missing requested {}",
                if missing.len() == 1 { "scope" } else { "scopes" }
            )));
        }
    }
    let db = app.pool.get().await?;
    let Some(account) = accounts::find(&db, &rt.account_id).await? else {
        return Err(OidcError::invalid_grant("refresh token invalid (referenced account not found)"));
    };
    drop(db);
    // Rotate on every use. Reusing a consumed refresh token revokes the whole grant.
    if consumed || !app.store.consume(REFRESH_TOKEN, &id).await? {
        app.store.revoke_grant(&rt.grant_id).await?;
        return Err(OidcError::invalid_grant("refresh token already used"));
    }
    let next_value = random_token(32);
    let next = RefreshToken { rotations: rt.rotations + 1, iat: now(), ..rt.clone() };
    let account_id = account.id.to_string();
    app.store
        .save(
            REFRESH_TOKEN,
            &token_id(&next_value),
            &next,
            Columns { grant_id: Some(&rt.grant_id), account_id: Some(&account_id), ..Default::default() },
            now() + (app.config.refresh_token_days * 24 * 3600) as i64,
        )
        .await?;
    let scope = match &requested {
        Some(requested) => rt.scope.split(' ').filter(|s| requested.contains(s)).collect::<Vec<_>>().join(" "),
        None => rt.scope.clone(),
    };
    let scope: Vec<&str> = scope.split(' ').filter(|s| grant.scopes.contains(*s)).collect();
    issue(
        app,
        Issue {
            client,
            account: &account,
            grant: &grant,
            scope: scope.join(" "),
            claims: rt.claims.clone(),
            nonce: rt.nonce.clone(),
            auth_time: rt.auth_time,
            amr: rt.amr.clone(),
            sid: rt.sid.clone(),
            session_uid: rt.session_uid.clone(),
            expires_with_session: rt.expires_with_session,
            refresh: Some(next_value),
        },
    )
    .await
}

/// A live access token, still bound to its session where it should be.
async fn find_access_token(app: &App, value: &str) -> Result<Option<AccessToken>> {
    let Some(found) = app.store.find::<AccessToken>(ACCESS_TOKEN, &token_id(value)).await? else { return Ok(None) };
    let at = found.value;
    if at.exp <= now() {
        return Ok(None);
    }
    if at.expires_with_session && !session_alive(app, &at.session_uid, &at.account_id, &at.client_id, &at.grant_id).await? {
        return Ok(None);
    }
    Ok(Some(at))
}

fn bearer_error(error: &str, description: &str) -> Out {
    Out::json(StatusCode::UNAUTHORIZED, &json!({ "error": error, "error_description": description }))
        .no_store()
        .header(header::WWW_AUTHENTICATE, &format!("Bearer realm=\"handstamp\", error=\"{error}\", error_description=\"{description}\""))
}

/// GET or POST /me.
pub async fn userinfo(State(app): State<App>, req: Req) -> Response {
    let result: Result<Out> = async {
        let from_header = req.header("authorization").and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")));
        let from_body = (req.method == Method::POST)
            .then(|| req.form_pairs().into_iter().find(|(k, _)| k == "access_token").map(|(_, v)| v))
            .flatten();
        let token = match (from_header, &from_body) {
            (Some(_), Some(_)) => return Ok(OidcError::invalid_request("access token must only be provided using one mechanism").json()),
            (Some(t), None) => t.to_string(),
            (None, Some(t)) => t.clone(),
            (None, None) => return Ok(bearer_error("invalid_token", "no access token provided")),
        };
        let Some(at) = find_access_token(&app, token.trim()).await? else {
            return Ok(bearer_error("invalid_token", "invalid token provided"));
        };
        let granted: BTreeSet<String> = at.scope.split(' ').filter(|s| !s.is_empty()).map(str::to_string).collect();
        if !granted.contains("openid") {
            return Ok(Out::json(StatusCode::FORBIDDEN, &json!({ "error": "insufficient_scope", "error_description": "access token missing 'openid' scope" })));
        }
        let db = app.pool.get().await?;
        let Some(account) = accounts::find(&db, &at.account_id).await? else {
            return Ok(bearer_error("invalid_token", "invalid token provided"));
        };
        drop(db);
        let grant = app.store.find::<Grant>(GRANT, &at.grant_id).await?.map(|f| f.value);
        let Some(grant) = grant else { return Ok(bearer_error("invalid_token", "invalid token provided")) };
        let requested = RequestedClaims::from_value(at.claims.as_ref());
        let scopes: Vec<&str> = granted.iter().map(String::as_str).collect();
        let claims = release_claims(&app, &account, &scopes, &granted, &requested.userinfo, &grant.claims).await?;
        Ok(Out::json(StatusCode::OK, &Value::Object(claims)).no_store())
    }
    .await;
    match result {
        Ok(out) => out.into_response(),
        Err(error) => OidcError::from(error).json().into_response(),
    }
}

/// POST /token/introspection: a client may introspect its own tokens.
pub async fn introspection(State(app): State<App>, req: Req) -> Response {
    let result = async {
        let form = single_params(req.form_pairs(), Some(&["token", "token_type_hint", "client_id", "client_secret"]))?;
        let ClientAuth { client } = authenticate_client(&app, &req, &form).await?;
        let token = form.get("token").ok_or_else(|| OidcError::invalid_request("missing required parameter 'token'"))?;
        let inactive = json!({ "active": false });
        if let Some(at) = find_access_token(&app, token).await?
            && at.client_id == client.client_id
        {
            return Ok(json!({
                "active": true,
                "client_id": at.client_id,
                "exp": at.exp,
                "iat": at.iat,
                "iss": app.issuer,
                "scope": at.scope,
                "sub": at.account_id,
                "token_type": "Bearer",
            }));
        }
        if let Some(found) = app.store.find::<RefreshToken>(REFRESH_TOKEN, &token_id(token)).await?
            && !found.consumed
            && found.value.client_id == client.client_id
            && found.value.exp > now()
        {
            let rt = found.value;
            return Ok(json!({
                "active": true,
                "client_id": rt.client_id,
                "exp": rt.exp,
                "iat": rt.iat,
                "iss": app.issuer,
                "scope": rt.scope,
                "sub": rt.account_id,
                "token_type": "refresh_token",
            }));
        }
        Ok::<_, OidcError>(inactive)
    }
    .await;
    match result {
        Ok(body) => Out::json(StatusCode::OK, &body).no_store().into_response(),
        Err(error) => client_error_response(&app, &error, &req).into_response(),
    }
}

/// POST /token/revocation. Revoking a refresh token revokes its grant; always 200.
pub async fn revocation(State(app): State<App>, req: Req) -> Response {
    let result = async {
        let form = single_params(req.form_pairs(), Some(&["token", "token_type_hint", "client_id", "client_secret"]))?;
        let ClientAuth { client } = authenticate_client(&app, &req, &form).await?;
        let token = form.get("token").ok_or_else(|| OidcError::invalid_request("missing required parameter 'token'"))?;
        let id = token_id(token);
        if let Some(found) = app.store.find::<AccessToken>(ACCESS_TOKEN, &id).await?
            && found.value.client_id == client.client_id
        {
            app.store.destroy(ACCESS_TOKEN, &id).await?;
        } else if let Some(found) = app.store.find::<RefreshToken>(REFRESH_TOKEN, &id).await?
            && found.value.client_id == client.client_id
        {
            app.store.revoke_grant(&found.value.grant_id).await?;
        }
        Ok::<_, OidcError>(())
    }
    .await;
    match result {
        Ok(()) => Out::new(StatusCode::OK).into_response(),
        Err(error) => client_error_response(&app, &error, &req).into_response(),
    }
}
