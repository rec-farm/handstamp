//! The application: shared state and the router. One process, one port: the protocol, the JSON
//! APIs and the SPA (docs/PLAN.md §1.2).

use std::{ops::Deref, sync::Arc, time::Instant};

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use deadpool_postgres::Pool;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};
use uuid::Uuid;

use crate::{
    clients::Clients,
    config::Config,
    crypto::{self, Purpose},
    enrollment::{Enrollments, Setup},
    http::{CookieOptions, Out, RateLimiter, Req, clear_cookie, set_cookie},
    identities::Identities,
    keys::Keys,
    oidc::{self, store::Store},
    passkeys::Passkeys,
    upstream::providers::Providers,
    web::Shell,
    webauthn::RelyingParty,
};

pub struct Inner {
    pub config: Config,
    /// The issuer as published: the origin, no trailing slash.
    pub issuer: String,
    pub pool: Pool,
    pub store: Store,
    pub keys: Keys,
    pub clients: Clients,
    pub passkeys: Passkeys,
    pub setup: Setup,
    pub enrollments: Enrollments,
    pub identities: Identities,
    pub providers: Providers,
    pub shell: Shell,
    pub limits: Arc<RateLimiter>,
    pub rp: RelyingParty,
    pub csrf_key: [u8; 32],
    pub state_key: [u8; 32],
    pub test_user: Option<Uuid>,
}

#[derive(Clone)]
pub struct App(pub Arc<Inner>);

impl Deref for App {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl App {
    pub fn new(config: Config, pool: Pool, shell: Shell, test_user: Option<Uuid>) -> Self {
        let root = config.secret_key.clone();
        let issuer = config.issuer_origin();
        let rp = RelyingParty {
            id: config.issuer_host(),
            name: config.instance_name.clone(),
            origin: issuer.clone(),
        };
        App(Arc::new(Inner {
            store: Store::new(pool.clone()),
            keys: Keys::new(pool.clone(), &root),
            clients: Clients::new(pool.clone(), &root),
            passkeys: Passkeys::new(pool.clone()),
            setup: Setup::new(pool.clone()),
            enrollments: Enrollments::new(pool.clone(), issuer.clone()),
            identities: Identities::new(pool.clone()),
            providers: Providers::new(pool.clone(), &root),
            limits: RateLimiter::new(config.rate_limit_scale),
            csrf_key: crypto::derive_key(&root, Purpose::Csrf),
            state_key: crypto::derive_key(&root, Purpose::StateCookies),
            rp,
            issuer,
            shell,
            test_user,
            pool,
            config,
        }))
    }

    /// `__Host-` prefixed on https, where browsers honor it.
    pub fn host_cookie_name(&self, base: &str) -> String {
        if self.config.https() {
            format!("__Host-{base}")
        } else {
            base.to_string()
        }
    }

    /// A short-lived, encrypted, HttpOnly cookie holding server state between redirects (upstream
    /// sign-in state, a pending enrollment, the console session). Sealed and bound to its name.
    pub fn write_sealed<T: Serialize>(&self, base: &str, value: &T, max_age: i64) -> String {
        let name = self.host_cookie_name(base);
        let mut payload = serde_json::to_value(value).unwrap_or_else(|_| json!({}));
        payload["exp"] = json!(oidc::store::now() + max_age);
        let sealed = crypto::seal(&self.state_key, payload.to_string().as_bytes(), &name);
        set_cookie(
            &name,
            &crypto::b64url(&sealed),
            &CookieOptions::lax("/", self.config.https(), Some(max_age)),
        )
    }

    pub fn read_sealed<T: DeserializeOwned>(&self, req: &Req, base: &str) -> Option<T> {
        let name = self.host_cookie_name(base);
        let raw = crypto::b64url_decode(req.cookie(&name)?)?;
        let opened = crypto::open(&self.state_key, &raw, &name).ok()?;
        let value: serde_json::Value = serde_json::from_slice(&opened).ok()?;
        if value["exp"].as_i64()? <= oidc::store::now() {
            return None;
        }
        serde_json::from_value(value).ok()
    }

    pub fn clear_sealed(&self, base: &str) -> String {
        clear_cookie(
            &self.host_cookie_name(base),
            &CookieOptions::lax("/", self.config.https(), None),
        )
    }
}

/// SPA routes that return index.html. Everything else under these prefixes is a 404.
const UI_PATHS: [&str; 10] = [
    "/",
    "/interaction/{uid}",
    "/setup",
    "/account",
    "/error",
    "/logout",
    "/signed-out",
    "/enroll",
    "/admin",
    "/admin/{*rest}",
];

async fn spa(State(app): State<App>, req: Req) -> Response {
    let html = app.shell.render(&req.path_and_query(), &[]).await;
    Out::html(StatusCode::OK, html).no_store().into_response()
}

async fn healthz() -> Response {
    Out::json(StatusCode::OK, &json!({ "ok": true })).into_response()
}

async fn readyz(State(app): State<App>) -> Response {
    let ok = match app.pool.get().await {
        Ok(client) => client.simple_query("select 1").await.is_ok(),
        Err(_) => false,
    };
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    Out::json(status, &json!({ "ok": ok })).into_response()
}

async fn not_found() -> Response {
    Out::json(StatusCode::NOT_FOUND, &json!({ "error": "not_found" })).into_response()
}

/// Applied to every response, including the protocol's (S15). The CSP goes on everything too;
/// a response that brings its own (form_post) keeps it.
async fn security_headers(State(app): State<App>, req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    let mut set = |name: &'static str, value: &'static str| {
        headers.insert(HeaderName::from_static(name), HeaderValue::from_static(value));
    };
    set("x-content-type-options", "nosniff");
    set("referrer-policy", "no-referrer");
    set("x-frame-options", "DENY");
    set("cross-origin-opener-policy", "same-origin");
    if app.config.https() {
        set("strict-transport-security", "max-age=31536000");
    }
    if let Some(csp) = app.shell.csp()
        && !headers.contains_key(header::CONTENT_SECURITY_POLICY)
        && let Ok(value) = HeaderValue::from_str(csp)
    {
        headers.insert(header::CONTENT_SECURITY_POLICY, value);
    }
    response
}

/// Query strings carry authorization codes, state and id_token_hint, so URLs are logged by path
/// only. Headers and bodies are never logged (S9).
pub fn log_url(uri: &axum::http::Uri) -> String {
    match uri.query() {
        Some(_) => format!("{}?[redacted]", uri.path()),
        None => uri.path().to_string(),
    }
}

async fn access_log(req: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let redacted = log_url(req.uri());
    let response = next.run(req).await;
    let status = response.status().as_u16();
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    if status >= 500 {
        tracing::error!(method = %method, url = %redacted, status, ms, "request completed");
    } else {
        tracing::info!(method = %method, url = %redacted, status, ms, "request completed");
    }
    response
}

pub fn router(app: App) -> Router {
    let mut router = Router::new()
        .route("/.well-known/openid-configuration", get(oidc::discovery::discovery))
        .route("/jwks", get(oidc::discovery::jwks))
        .route(
            "/auth",
            get(oidc::authorize::authorization).post(oidc::authorize::authorization),
        )
        .route(
            "/auth/{uid}",
            get(oidc::authorize::resume).post(oidc::authorize::resume),
        )
        .route("/token", post(oidc::token::token).get(oidc::token::token))
        .route("/me", get(oidc::token::userinfo).post(oidc::token::userinfo))
        .route("/token/introspection", post(oidc::token::introspection))
        .route("/token/revocation", post(oidc::token::revocation))
        .route("/session/end", get(oidc::logout::end).post(oidc::logout::end))
        .route("/session/end/confirm", post(oidc::logout::confirm))
        .route("/session/end/success", get(oidc::logout::success))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(crate::interaction::routes(&app))
        .merge(crate::upstream::routes::routes())
        .merge(crate::console::routes())
        .merge(crate::admin::routes());
    for path in UI_PATHS {
        // In conformance mode the interaction page is the plain form from interaction.rs.
        if app.config.conformance_mode && path == "/interaction/{uid}" {
            continue;
        }
        router = router.route(path, get(spa));
    }
    if let crate::web::Shell::Static { .. } = app.shell {
        let assets = Router::new()
            .fallback_service(ServeDir::new(app.config.web_dist.join("assets")))
            .layer(SetResponseHeaderLayer::overriding(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ));
        router = router.nest_service("/assets", assets);
    }
    router
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(app.clone(), security_headers))
        .layer(middleware::from_fn(access_log))
        .with_state(app)
}

#[cfg(test)]
mod tests {
    #[test]
    fn logs_urls_without_query_strings() {
        let uri: axum::http::Uri = "/console/callback?code=secret-code&state=s".parse().unwrap();
        assert_eq!(super::log_url(&uri), "/console/callback?[redacted]");
        assert_eq!(super::log_url(&"/readyz".parse().unwrap()), "/readyz");
    }
}
