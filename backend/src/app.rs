use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

use crate::{
    keys::Keys,
    web::{self, Shell},
};

pub struct AppState {
    pub issuer: String,
    pub https: bool,
    pub trust_proxy: bool,
    pub pool: Pool,
    pub keys: Keys,
    pub shell: Shell,
}

type Shared = State<Arc<AppState>>;

// SPA routes that return index.html (apps/server/src/app.ts UI_PATHS).
const UI_PATHS: &[&str] = &[
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

// Owned by oidc-provider or the Node API today. Each one moves here only with its tests and a
// green conformance run (docs/RUST-PORT.md).
const NOT_PORTED: &[&str] = &[
    "/auth",
    "/auth/{*rest}",
    "/token",
    "/token/{*rest}",
    "/me",
    "/session/end",
    "/session/end/{*rest}",
    "/interaction/{uid}/{*rest}",
    "/api/{*rest}",
    "/console/{*rest}",
];

pub fn router(state: Arc<AppState>, web_dist: Option<PathBuf>) -> Router {
    let mut app = Router::new()
        .route("/healthz", get(|| async { Json(json!({ "ok": true })) }))
        .route("/readyz", get(readyz))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks));
    for path in UI_PATHS {
        app = app.route(path, get(spa));
    }
    for path in NOT_PORTED {
        app = app.route(path, any(not_ported));
    }
    if let Some(dist) = web_dist {
        let assets = Router::new()
            .fallback_service(ServeDir::new(dist.join("assets")))
            .layer(SetResponseHeaderLayer::overriding(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ));
        app = app.nest_service("/assets", assets);
    }
    app.fallback(|| async { (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))) })
        .layer(middleware::from_fn_with_state(state.clone(), base_headers))
        .with_state(state)
}

// Applied to every response (S15).
async fn base_headers(State(state): Shared, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    for (name, value) in web::base_headers(state.https) {
        res.headers_mut()
            .insert(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
    res
}

async fn readyz(State(state): Shared) -> Response {
    let ok = match state.pool.get().await {
        Ok(client) => client.simple_query("select 1").await.is_ok(),
        Err(_) => false,
    };
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(json!({ "ok": ok }))).into_response()
}

async fn spa(State(state): Shared) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_SECURITY_POLICY, state.shell.csp.as_str()),
        ],
        state.shell.html.clone(),
    )
        .into_response()
}

async fn not_ported() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({ "error": "not_implemented", "error_description": "Not ported to the Rust server yet" })),
    )
        .into_response()
}

// Like oidc-provider (Koa), endpoint URLs follow the request: the Host header over plain http,
// or X-Forwarded-Proto/Host when a proxy is trusted. The issuer is always the configured one.
pub fn request_origin(headers: &HeaderMap, trust_proxy: bool) -> String {
    let first = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_string())
    };
    let forwarded = |name: &str| {
        if trust_proxy {
            first(name).filter(|v| !v.is_empty())
        } else {
            None
        }
    };
    let proto = forwarded("x-forwarded-proto").unwrap_or_else(|| "http".into());
    let host = forwarded("x-forwarded-host")
        .or_else(|| first("host"))
        .unwrap_or_default();
    format!("{proto}://{host}")
}

// Same metadata as the Node server publishes today, so relying parties see one contract.
pub fn discovery_document(issuer: &str, origin: &str) -> Value {
    let at = |path: &str| format!("{origin}{path}");
    json!({
        "issuer": issuer,
        "authorization_endpoint": at("/auth"),
        "token_endpoint": at("/token"),
        "userinfo_endpoint": at("/me"),
        "end_session_endpoint": at("/session/end"),
        "introspection_endpoint": at("/token/introspection"),
        "revocation_endpoint": at("/token/revocation"),
        "jwks_uri": at("/jwks"),
        "scopes_supported": ["openid", "offline_access", "profile", "email", "groups"],
        "claims_supported": ["sub", "groups", "amr", "name", "preferred_username", "updated_at", "email", "email_verified", "sid", "auth_time", "iss"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["form_post", "fragment", "query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claim_types_supported": ["normal"],
        "claims_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "authorization_response_iss_parameter_supported": true,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
    })
}

async fn discovery(State(state): Shared, headers: HeaderMap) -> Json<Value> {
    Json(discovery_document(
        &state.issuer,
        &request_origin(&headers, state.trust_proxy),
    ))
}

async fn jwks(State(state): Shared) -> Response {
    match state.keys.public_jwks().await {
        Ok(keys) => (
            [(header::CONTENT_TYPE, "application/jwk-set+json; charset=utf-8")],
            Json(keys),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "jwks failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "server_error" })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(k, v)| (HeaderName::from_static(k), HeaderValue::from_static(v)))
            .collect()
    }

    #[test]
    fn endpoints_follow_the_request_like_koa() {
        let h = headers(&[
            ("host", "127.0.0.1:3000"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "id.example.com"),
        ]);
        assert_eq!(request_origin(&h, false), "http://127.0.0.1:3000");
        assert_eq!(request_origin(&h, true), "https://id.example.com");
        let doc = discovery_document("https://id.example.com", "https://id.example.com");
        assert_eq!(doc["issuer"], "https://id.example.com");
        assert_eq!(doc["token_endpoint"], "https://id.example.com/token");
    }
}
