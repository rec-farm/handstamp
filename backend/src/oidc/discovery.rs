//! Discovery and JWKS: the same metadata oidc-provider published, so relying parties see one contract.

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::{accounts::CLAIMS_SUPPORTED, app::App, http::Out};

/// Every endpoint lives under the configured issuer. URLs are never built from the Host header,
/// so a forged Host can't put someone else's endpoints in the document.
pub fn document(issuer: &str) -> Value {
    let at = |path: &str| format!("{issuer}{path}");
    json!({
        "acr_values_supported": super::acr::SUPPORTED,
        "authorization_endpoint": at("/auth"),
        "claims_parameter_supported": true,
        "claims_supported": CLAIMS_SUPPORTED,
        "code_challenge_methods_supported": ["S256"],
        "end_session_endpoint": at("/session/end"),
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "issuer": issuer,
        "jwks_uri": at("/jwks"),
        "authorization_response_iss_parameter_supported": true,
        "response_modes_supported": ["form_post", "fragment", "query"],
        "response_types_supported": ["code"],
        "scopes_supported": ["openid", "offline_access", "profile", "email", "groups"],
        "subject_types_supported": ["public"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "token_endpoint": at("/token"),
        "id_token_signing_alg_values_supported": ["RS256"],
        "request_uri_parameter_supported": false,
        "userinfo_endpoint": at("/me"),
        "introspection_endpoint": at("/token/introspection"),
        "revocation_endpoint": at("/token/revocation"),
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "claim_types_supported": ["normal"],
    })
}

pub async fn discovery(State(app): State<App>) -> Response {
    Out::json(StatusCode::OK, &document(&app.issuer))
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .into_response()
}

pub async fn jwks(State(app): State<App>) -> Response {
    match app.keys.snapshot().await {
        Ok(snapshot) => Out::json(StatusCode::OK, &snapshot.jwks)
            .header(header::CONTENT_TYPE, "application/jwk-set+json; charset=utf-8")
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .into_response(),
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "jwks failed");
            Out::json(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": "server_error" })).into_response()
        }
    }
}
