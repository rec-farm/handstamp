//! The OpenID Connect provider: authorization code flow with PKCE, refresh token rotation,
//! userinfo, introspection, revocation, RP-initiated and back-channel logout. Behaviour follows
//! oidc-provider 9 as Handstamp configured it, so the OpenID conformance results carry over.

pub mod authorize;
pub mod discovery;
pub mod logout;
pub mod models;
pub mod store;
pub mod token;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};

use crate::{
    accounts::{self, Account},
    app::App,
    clients::Client,
    crypto::constant_time_eq,
    http::{CookieOptions, Out, Req, SameSite, clear_cookie, set_cookie},
    web,
};
use models::Session;
use store::{Columns, SESSION, now};

/// An OAuth/OIDC error with what oidc-provider would have answered.
#[derive(Debug, Clone)]
pub struct OidcError {
    pub error: String,
    pub description: String,
    pub status: StatusCode,
    /// False for errors that must never travel to a redirect_uri (a bad redirect_uri itself).
    pub allow_redirect: bool,
}

impl OidcError {
    pub fn new(error: &str, description: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            description: description.into(),
            status: StatusCode::BAD_REQUEST,
            allow_redirect: true,
        }
    }
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new("invalid_request", description)
    }
    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new("invalid_client", description)
    }
    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new("invalid_grant", description)
    }
    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new("invalid_scope", description)
    }
    pub fn access_denied(description: impl Into<String>) -> Self {
        Self::new("access_denied", description)
    }
    pub fn invalid_redirect_uri() -> Self {
        Self {
            allow_redirect: false,
            ..Self::new(
                "invalid_redirect_uri",
                "redirect_uri did not match any of the client's registered redirect_uris",
            )
        }
    }
    pub fn session_not_found(description: impl Into<String>) -> Self {
        Self::new("invalid_request", description)
    }
    pub fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            ..Self::new("server_error", "oops! something went wrong")
        }
    }
    pub fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// The token-endpoint style JSON body.
    pub fn json(&self) -> Out {
        Out::json(
            self.status,
            &json!({ "error": self.error, "error_description": self.description }),
        )
        .no_store()
        .header(axum::http::header::PRAGMA, "no-cache")
    }
}

impl From<anyhow::Error> for OidcError {
    fn from(error: anyhow::Error) -> Self {
        tracing::error!(error = %format!("{error:#}"), "provider error");
        Self::server_error()
    }
}

impl From<deadpool_postgres::PoolError> for OidcError {
    fn from(error: deadpool_postgres::PoolError) -> Self {
        anyhow::Error::from(error).into()
    }
}

impl From<tokio_postgres::Error> for OidcError {
    fn from(error: tokio_postgres::Error) -> Self {
        anyhow::Error::from(error).into()
    }
}

pub type OidcResult<T> = Result<T, OidcError>;

/// `__Host-` needs Secure + Path=/. The interaction and resume cookies are path-scoped to
/// /interaction/:uid and /auth/:uid, so those get `__Secure-`. Over plain http (local dev only)
/// browsers reject both prefixes, so they are dropped.
pub struct CookieNames {
    pub session: &'static str,
    pub interaction: &'static str,
    pub resume: &'static str,
}

pub fn cookie_names(https: bool) -> CookieNames {
    if https {
        CookieNames {
            session: "__Host-hs_session",
            interaction: "__Secure-hs_interaction",
            resume: "__Secure-hs_resume",
        }
    } else {
        CookieNames {
            session: "hs_session",
            interaction: "hs_interaction",
            resume: "hs_resume",
        }
    }
}

impl App {
    pub fn cookie_names(&self) -> CookieNames {
        cookie_names(self.config.https())
    }

    /// The SSO session cookie. OIDC Core requires POST at the authorization endpoint, which only
    /// works cross-site with SameSite=None (needs Secure), so https issuers use None (R16).
    pub fn session_cookie_options(&self, max_age: Option<i64>) -> CookieOptions {
        let https = self.config.https();
        CookieOptions {
            path: "/".into(),
            max_age,
            same_site: if https { SameSite::None } else { SameSite::Lax },
            secure: https,
        }
    }

    pub fn short_cookie_options(&self, path: &str, max_age: Option<i64>) -> CookieOptions {
        CookieOptions::lax(path, self.config.https(), max_age)
    }

    pub fn session_ttl(&self) -> i64 {
        (self.config.session_max_days * 24 * 3600) as i64
    }

    /// The current SSO session, or a fresh unsaved one.
    pub async fn load_session(&self, req: &Req) -> Result<Session> {
        if let Some(id) = req.cookie(self.cookie_names().session)
            && let Some(found) = self.store.find::<Session>(SESSION, &store::token_id(id)).await?
        {
            let mut session = found.value;
            session.id = id.to_string();
            session.new = false;
            return Ok(session);
        }
        Ok(Session::fresh(self.session_ttl()))
    }

    /// Persists a session that exists or changed, and returns the cookie for it.
    pub async fn save_session(&self, session: &Session, previous_id: Option<&str>) -> Result<Vec<String>> {
        if session.new && !session.touched {
            return Ok(Vec::new());
        }
        if let Some(previous) = previous_id
            && previous != session.id
        {
            self.store.destroy(SESSION, &store::token_id(previous)).await?;
        }
        self.store
            .save(
                SESSION,
                &store::token_id(&session.id),
                session,
                Columns {
                    uid: Some(&session.uid),
                    account_id: session.account_id.as_deref(),
                    ..Default::default()
                },
                session.exp,
            )
            .await?;
        let max_age = (session.exp - now()).max(0);
        Ok(vec![set_cookie(
            self.cookie_names().session,
            &session.id,
            &self.session_cookie_options(Some(max_age)),
        )])
    }

    pub fn clear_session_cookie(&self) -> String {
        clear_cookie(self.cookie_names().session, &self.session_cookie_options(None))
    }

    /// oidc-provider's renderError: a fixed message per code, nothing from the request (S20).
    pub async fn render_error(&self, error: &OidcError) -> Out {
        let code = if regex_error_code(&error.error) {
            error.error.as_str()
        } else {
            "server_error"
        };
        let html = if self.config.conformance_mode {
            format!(
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error</title></head><body><h1>Handstamp could not complete this request</h1><p>error: {code}</p></body></html>"
            )
        } else {
            self.shell.render("/error", &[("view", "error"), ("code", code)]).await
        };
        Out::html(error.status, html).no_store()
    }
}

fn regex_error_code(code: &str) -> bool {
    !code.is_empty() && code.len() <= 64 && code.chars().all(|c| c.is_ascii_lowercase() || c == '_')
}

/// Delivers authorization response parameters through the requested response mode.
pub fn respond(mode: &str, redirect_uri: &str, params: &[(&str, String)]) -> Out {
    match mode {
        "form_post" => form_post(redirect_uri, params),
        "fragment" => {
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(params)
                .finish();
            Out::see_other(&format!("{redirect_uri}#{encoded}"))
        }
        _ => {
            let mut url = match url::Url::parse(redirect_uri) {
                Ok(url) => url,
                Err(_) => return Out::see_other(redirect_uri),
            };
            url.query_pairs_mut().extend_pairs(params);
            Out::see_other(url.as_str())
        }
    }
}

const AUTOSUBMIT: &str = "document.forms[0].submit()";

/// An auto-submitting form. Its one inline script is allowed by hash, not by 'unsafe-inline'.
pub fn form_post(action: &str, params: &[(&str, String)]) -> Out {
    let escape = |v: &str| {
        v.replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let inputs: String = params
        .iter()
        .map(|(k, v)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\"/>",
                escape(k),
                escape(v)
            )
        })
        .collect();
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Submitting…</title></head><body><form method=\"post\" action=\"{}\">{inputs}<noscript><button type=\"submit\">Continue</button></noscript></form><script>{AUTOSUBMIT}</script></body></html>",
        escape(action)
    );
    Out::html(StatusCode::OK, html).no_store().header(
        axum::http::header::CONTENT_SECURITY_POLICY,
        &web::html_csp(&[web::script_hash(AUTOSUBMIT)]),
    )
}

/// The claims parameter, parsed once.
#[derive(Clone, Debug, Default)]
pub struct RequestedClaims {
    pub id_token: Map<String, Value>,
    pub userinfo: Map<String, Value>,
}

impl RequestedClaims {
    pub fn from_value(value: Option<&Value>) -> Self {
        let section = |name: &str| {
            value
                .and_then(|v| v.get(name))
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default()
        };
        Self {
            id_token: section("id_token"),
            userinfo: section("userinfo"),
        }
    }

    /// Every claim named in either section (what consent asks about).
    pub fn names(&self) -> BTreeSet<String> {
        self.id_token.keys().chain(self.userinfo.keys()).cloned().collect()
    }
}

/// Claims that a grant can never take away.
const NON_REJECTABLE: [&str; 6] = ["sub", "sid", "auth_time", "acr", "amr", "iss"];

/// The claims released for a use: everything the granted scopes cover, plus individually
/// requested claims the grant allows.
pub async fn release_claims(
    app: &App,
    account: &Account,
    scope_mask: &[&str],
    granted_scopes: &BTreeSet<String>,
    requested: &Map<String, Value>,
    grant_claims: &BTreeSet<String>,
) -> Result<Map<String, Value>> {
    let db = app.pool.get().await?;
    let available = account.available(&db, granted_scopes).await?;
    let mut mask: BTreeSet<&str> = scope_mask
        .iter()
        .flat_map(|s| accounts::scope_claims(s).iter().copied())
        .collect();
    for claim in requested.keys() {
        if NON_REJECTABLE.contains(&claim.as_str()) || grant_claims.contains(claim) {
            mask.insert(claim);
        }
    }
    let mut out = Map::new();
    for claim in mask {
        if !accounts::CLAIMS_SUPPORTED.contains(&claim) {
            continue;
        }
        if let Some(value) = available.get(claim) {
            out.insert(claim.to_string(), value.clone());
        }
    }
    out.insert("sub".into(), json!(account.id.to_string()));
    Ok(out)
}

pub struct IdTokenInput<'a> {
    pub client: &'a Client,
    pub account: &'a Account,
    pub scope: &'a str,
    pub requested: &'a RequestedClaims,
    pub grant_claims: &'a BTreeSet<String>,
    pub nonce: Option<&'a str>,
    pub auth_time: i64,
    pub amr: Option<&'a [String]>,
    pub sid: Option<&'a str>,
}

/// An RS256 ID token. With conformIdTokenClaims, scope-based profile and email claims go to
/// userinfo; the ID token gets the openid-scope claims (sub, groups, amr) plus individually
/// requested ones (D6).
pub async fn id_token(app: &App, input: IdTokenInput<'_>) -> Result<String> {
    let granted: BTreeSet<String> = input
        .scope
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let mut claims = release_claims(
        app,
        input.account,
        &["openid"],
        &granted,
        &input.requested.id_token,
        input.grant_claims,
    )
    .await?;
    let iat = now();
    if let Some(amr) = input.amr.filter(|a| !a.is_empty()) {
        claims.insert("amr".into(), json!(amr));
    }
    claims.insert("auth_time".into(), json!(input.auth_time));
    if let Some(nonce) = input.nonce {
        claims.insert("nonce".into(), json!(nonce));
    }
    if let Some(sid) = input.sid {
        claims.insert("sid".into(), json!(sid));
    }
    claims.insert("iat".into(), json!(iat));
    claims.insert("exp".into(), json!(iat + (app.config.id_token_minutes * 60) as i64));
    claims.insert("aud".into(), json!(input.client.client_id));
    claims.insert("iss".into(), json!(app.issuer));
    let signer = app.keys.signer().await?;
    signer.sign(
        &json!({ "alg": crate::keys::ALG, "kid": signer.kid }),
        &Value::Object(claims),
    )
}

/// Client authentication at the token, introspection and revocation endpoints. A client may only
/// use the method it registered.
pub struct ClientAuth {
    pub client: Client,
}

pub async fn authenticate_client(app: &App, req: &Req, form: &BTreeMap<String, String>) -> OidcResult<ClientAuth> {
    let basic = req
        .header("authorization")
        .and_then(|h| h.strip_prefix("Basic ").or_else(|| h.strip_prefix("basic ")));
    let unauthorized = |description: &str| OidcError::invalid_client(description).status(StatusCode::UNAUTHORIZED);
    let (client_id, secret, method) = if let Some(encoded) = basic {
        let decoded = STANDARD
            .decode(encoded.trim())
            .ok()
            .and_then(|b| String::from_utf8(b).ok());
        let Some((id, secret)) = decoded.as_deref().and_then(|d| d.split_once(':')) else {
            return Err(unauthorized("invalid authorization header value format"));
        };
        let decode = |v: &str| {
            url::form_urlencoded::parse(format!("v={}", v.replace('+', "%2B")).as_bytes())
                .next()
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default()
        };
        if form.contains_key("client_secret") {
            return Err(OidcError::invalid_request(
                "client authentication must only be provided using one mechanism",
            ));
        }
        (decode(id), Some(decode(secret)), "client_secret_basic")
    } else if let Some(secret) = form.get("client_secret") {
        let id = form.get("client_id").cloned().unwrap_or_default();
        (id, Some(secret.clone()), "client_secret_post")
    } else {
        (form.get("client_id").cloned().unwrap_or_default(), None, "none")
    };
    if client_id.is_empty() {
        return Err(OidcError::invalid_request(
            "no client authentication mechanism provided",
        ));
    }
    if form.get("client_id").is_some_and(|id| id != &client_id) {
        return Err(OidcError::invalid_request(
            "mismatch in body and authorization client ids",
        ));
    }
    let Some(client) = app.clients.load(&client_id).await? else {
        return Err(unauthorized("client authentication failed"));
    };
    if client.auth_method != method {
        return Err(unauthorized("client authentication failed"));
    }
    if method != "none" {
        let expected = client.secret.clone().unwrap_or_default();
        if !constant_time_eq(expected.as_bytes(), secret.unwrap_or_default().as_bytes()) {
            return Err(unauthorized("client authentication failed"));
        }
    }
    Ok(ClientAuth { client })
}

/// invalid_client at a token-style endpoint, with the Basic challenge clients expect.
pub fn client_error_response(app: &App, error: &OidcError) -> Out {
    let mut out = error.json();
    if error.error == "invalid_client" {
        out.status = StatusCode::UNAUTHORIZED;
        let realm = app.config.issuer_host();
        out = out.header(
            axum::http::header::WWW_AUTHENTICATE,
            &format!(
                "Basic realm=\"{realm}\", error=\"invalid_client\", error_description=\"{}\"",
                error.description
            ),
        );
    }
    out
}

/// A form body as a map. Repeated parameters are an error everywhere (rejectDupes).
pub fn single_params(pairs: Vec<(String, String)>, allowed: Option<&[&str]>) -> OidcResult<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (key, value) in pairs {
        if allowed.is_some_and(|a| !a.contains(&key.as_str())) {
            continue;
        }
        if out.contains_key(&key) {
            return Err(OidcError::invalid_request(format!(
                "'{key}' parameter must not be provided twice"
            )));
        }
        if !value.is_empty() {
            out.insert(key, value);
        }
    }
    Ok(out)
}
